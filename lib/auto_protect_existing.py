#!/usr/bin/env python3
"""
AutoCaddyProtector - Автоматический защитник уже запущенного Caddy
Подключается к существующему Docker-контейнеру Caddy без остановки
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import docker
import psutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
import re


class AutoCaddyProtector:
    """
    Автоматически защищает уже запущенный Caddy в Docker
    Подключается к логам и защищает без остановки контейнера
    """
    def __init__(self):
        self.docker_client = docker.from_env()
        self.caddy_container = None
        self.log_stream = None
        self.blocked_ips = set()
        self.traffic_analyzer = TrafficAnalyzer()
        self.monitoring = False
        self.monitor_thread = None
        
        # Настройка логирования
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AutoCaddyProtector - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/astracat_guard_auto.log'),
                logging.StreamHandler()
            ]
        )

    def find_caddy_container(self):
        """Автоматически найти запущенный контейнер Caddy"""
        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                # Проверяем имя или образ контейнера
                if ('caddy' in container.name.lower() or 
                    'caddy' in container.image.tags[0].lower() if container.image.tags else False):
                    self.caddy_container = container
                    logging.info(f"Найден Caddy контейнер: {container.name} (ID: {container.id[:12]})")
                    return True
            
            # Если не найден по имени, ищем по портам
            for container in containers:
                ports = container.ports
                # Ищем контейнер, который использует стандартные порты Caddy
                for port in ports.values() if ports else []:
                    if port and isinstance(port, list):
                        for mapping in port:
                            if mapping.get('HostPort') in ['80', '443', '2019']:
                                self.caddy_container = container
                                logging.info(f"Найден возможный Caddy контейнер по портам: {container.name}")
                                return True
            
            logging.warning("Не найден контейнер с Caddy, попробуйте указать имя вручную")
            return False
            
        except Exception as e:
            logging.error(f"Ошибка поиска контейнера Caddy: {e}")
            return False

    def attach_to_caddy_logs(self):
        """Подключиться к логам запущенного контейнера Caddy"""
        if not self.caddy_container:
            return False
            
        try:
            # Используем прямое чтение логов через Docker API
            self.log_stream = self.caddy_container.logs(stream=True, follow=True)
            logging.info(f"Подключено к логам контейнера {self.caddy_container.name}")
            return True
        except Exception as e:
            logging.error(f"Ошибка подключения к логам: {e}")
            return False

    def setup_log_file_monitoring(self):
        """Альтернативный метод - мониторинг файлов логов"""
        # Пытаемся найти файлы логов из работающего контейнера
        try:
            # Попробуем выполнить команду в контейнере для поиска логов
            result = self.caddy_container.exec_run('find / -name "access.log" -o -name "*.log" 2>/dev/null | grep -i caddy', 
                                                  stdout=True, stderr=True)
            if result.exit_code == 0:
                log_paths = result.output.decode().strip().split('\n')
                if log_paths and log_paths[0]:
                    logging.info(f"Найдены логи в контейнере: {log_paths[0]}")
                    # Попытаемся скопировать лог в хостовую систему
                    try:
                        with open('/tmp/caddy_access.log', 'w') as f:
                            f.write('')  # Создаем файл
                    except:
                        pass
                    return True
        except Exception as e:
            logging.warning(f"Не удалось получить пути к логам напрямую: {e}")
        
        return False

    def parse_caddy_log(self, log_line):
        """Парсинг строки лога Caddy (обычно в JSON формате)"""
        try:
            # Caddy по умолчанию использует JSON логи
            log_entry = json.loads(log_line)
            return {
                'ip': log_entry.get('request', {}).get('remote_ip', 'unknown'),
                'method': log_entry.get('request', {}).get('method', 'GET'),
                'uri': log_entry.get('request', {}).get('uri', ''),
                'status': log_entry.get('status', 200),
                'size': log_entry.get('bytes_written', 0),
                'user_agent': log_entry.get('request', {}).get('headers', {}).get('User-Agent', [''])[0],
                'timestamp': log_entry.get('ts', time.time()),
            }
        except json.JSONDecodeError:
            # Альтернативный парсинг для текстового формата
            return self.parse_text_log(log_line)
        except Exception:
            return None

    def parse_text_log(self, log_line):
        """Парсинг текстового формата лога (если используется)"""
        # Пример формата: "IP - - [timestamp] "METHOD URI PROTO" STATUS SIZE"
        pattern = r'^(\S+) .*? "(\w+) ([^"]+)" (\d+) (\d+)'
        match = re.match(pattern, log_line)
        if match:
            return {
                'ip': match.group(1),
                'method': match.group(2),
                'uri': match.group(3),
                'status': int(match.group(4)),
                'size': int(match.group(5)),
                'timestamp': time.time(),
                'user_agent': '',
            }
        return None

    def block_ip_globally(self, ip):
        """Блокировка IP через iptables на хосте"""
        if ip in self.blocked_ips:
            return
            
        try:
            # Пробуем заблокировать через iptables
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logging.warning(f"IP {ip} заблокирован через iptables")
            else:
                logging.error(f"Не удалось заблокировать IP {ip}: {result.stderr}")
        except subprocess.TimeoutExpired:
            logging.error(f"Таймаут при блокировке IP {ip}")
        except Exception as e:
            logging.error(f"Ошибка блокировки IP {ip}: {e}")

    def analyze_and_protect(self):
        """Основной цикл анализа логов и защиты"""
        logging.info("Начало мониторинга и защиты существующего Caddy...")
        
        if not self.attach_to_caddy_logs():
            logging.info("Пробуем альтернативный метод мониторинга...")
            if not self.setup_log_file_monitoring():
                logging.error("Не удалось подключиться к логам Caddy")
                return
        
        try:
            for log_line in self.log_stream:
                log_line = log_line.decode('utf-8').strip()
                if not log_line:
                    continue
                
                # Парсим строку лога
                log_entry = self.parse_caddy_log(log_line)
                if not log_entry or log_entry['ip'] == 'unknown':
                    continue
                
                # Анализируем трафик
                if self.traffic_analyzer.analyze_request(log_entry):
                    ip = log_entry['ip']
                    self.block_ip_globally(ip)
                    
        except Exception as e:
            logging.error(f"Ошибка в мониторинге: {e}")
            # Если основное подключение не работает, пробуем альтернативный метод
            self.alternative_monitoring()

    def alternative_monitoring(self):
        """Альтернативный метод мониторинга через системный анализ"""
        logging.info("Переход к альтернативному методу мониторинга...")
        
        while self.monitoring:
            try:
                # Проверяем сетевые соединения к Caddy
                caddy_ports = [80, 443, 2019]  # Стандартные порты Caddy
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if (conn.status == psutil.CONN_ESTABLISHED and 
                        conn.laddr.port in caddy_ports and 
                        conn.raddr):
                        
                        remote_ip = conn.raddr.ip
                        # Создаем паттерн трафика
                        traffic_pattern = {
                            'ip': remote_ip,
                            'requests_per_second': 0,  # В реальном мониторинге будет точнее
                            'connection_count': 1,
                            'bytes_sent': conn.raddr.port,  # Заглушка
                            'bytes_received': 0,
                            'suspicious_paths': [],
                            'user_agents': [],
                            'time_window': 1.0
                        }
                        
                        # Анализируем трафик
                        if self.traffic_analyzer.is_anomalous_traffic(remote_ip, traffic_pattern):
                            self.block_ip_globally(remote_ip)
                
                time.sleep(2)  # Пауза между проверками
                
            except Exception as e:
                logging.error(f"Ошибка в альтернативном мониторинге: {e}")
                time.sleep(10)

    def start_protection(self):
        """Запуск защиты уже запущенного Caddy"""
        logging.info("Запуск автоматической защиты для существующего Caddy...")
        
        # Пытаемся найти Caddy контейнер
        if not self.find_caddy_container():
            logging.error("Не удалось найти контейнер Caddy, проверьте запущенные контейнеры")
            return False
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.analyze_and_protect, daemon=True)
        self.monitor_thread.start()
        
        logging.info("Система защиты активирована для существующего Caddy")
        logging.info("Мониторинг работает без остановки оригинального контейнера")
        return True

    def stop_protection(self):
        """Остановка защиты"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logging.info("Система защиты остановлена")

    def get_status(self):
        """Получить статус защиты"""
        return {
            'monitoring': self.monitoring,
            'caddy_container': self.caddy_container.name if self.caddy_container else 'not found',
            'blocked_ips_count': len(self.blocked_ips),
            'learning_phase': self.traffic_analyzer.learning_phase
        }


class TrafficAnalyzer:
    """
    Анализатор трафика для автоматического определения аномалий
    """
    def __init__(self):
        self.traffic_history = defaultdict(deque)
        self.suspicious_ips = defaultdict(int)
        self.learning_phase = True
        self.learning_duration = 300  # 5 минут
        self.start_time = time.time()
        
        self.stats_collector = {
            'avg_rps': deque(maxlen=50),
            'avg_connections': deque(maxlen=50),
        }
        
        self.suspicious_patterns = [
            r'\.\./', r'union.*select', r'<script', r'exec\(', r'bot', r'scanner'
        ]

    def analyze_request(self, log_entry):
        """Анализ запроса на подозрительность"""
        ip = log_entry['ip']
        uri = log_entry['uri']
        user_agent = log_entry['user_agent']
        timestamp = log_entry['timestamp']
        
        # Проверяем подозрительные паттерны
        uri_suspicious = any(re.search(pattern, uri, re.IGNORECASE) for pattern in self.suspicious_patterns)
        ua_suspicious = any(pattern.lower() in user_agent.lower() for pattern in ['bot', 'scanner', 'crawler'])
        
        if self.learning_phase:
            # Фаза обучения - просто собираем данные
            self.stats_collector['avg_rps'].append(1)  # Упрощенно
            
            if time.time() - self.start_time > self.learning_duration:
                self.learning_phase = False
                logging.info("Фаза обучения завершена, активирована защита")
            
            return False
        
        # После обучения применяем правила
        self.traffic_history[ip].append(timestamp)
        
        # Очищаем старые данные (старше 1 минуты)
        cutoff = time.time() - 60
        while self.traffic_history[ip] and self.traffic_history[ip][0] < cutoff:
            self.traffic_history[ip].popleft()
        
        # Проверяем аномальное количество запросов
        request_count = len(self.traffic_history[ip])
        
        is_anomalous = (
            request_count > 50 or  # Более 50 запросов в минуту
            uri_suspicious or
            ua_suspicious
        )
        
        if is_anomalous:
            self.suspicious_ips[ip] += 1
            return self.suspicious_ips[ip] > 2  # Блокируем после 2 подозрений
        
        return False

    def is_anomalous_traffic(self, ip, pattern):
        """Проверка аномального трафика (для альтернативного мониторинга)"""
        if self.learning_phase:
            # Обновляем статистику
            self.stats_collector['avg_connections'].append(pattern['connection_count'])
            return False
        
        # Проверяем аномалии
        threshold = 10  # Максимальное количество соединений
        return pattern['connection_count'] > threshold


def main():
    """Основная функция запуска защиты для существующего Caddy"""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        AutoCaddyProtector - Защита существующего Caddy      ║")
    print("║      Работает без остановки или изменения контейнера        ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("Система:")
    print("• Найдет запущенный контейнер Caddy автоматически")
    print("• Подключится к его логам без остановки")
    print("• Начнет защиту без перезапуска контейнера")
    print("• Блокирует угрозы через iptables хоста")
    print()
    
    try:
        protector = AutoCaddyProtector()
        
        if protector.start_protection():
            print("Система защиты активирована!")
            print("Caddy продолжает работать без изменений")
            print("Для просмотра статуса проверьте логи: /var/log/astracat_guard_auto.log")
            print()
            print("Нажмите Ctrl+C для остановки защиты...")
            
            try:
                while True:
                    time.sleep(30)
                    status = protector.get_status()
                    phase = "обучение" if status['learning_phase'] else "защита"
                    print(f"Статус ({phase}): защищает {status['caddy_container']}, "
                          f"заблокировано {status['blocked_ips_count']} IP")
            except KeyboardInterrupt:
                print("\nОстановка системы защиты...")
                protector.stop_protection()
                print("Защита остановлена.")
        else:
            print("Ошибка активации системы защиты")
            return 1
            
    except Exception as e:
        logging.error(f"Ошибка запуска защиты: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())