#!/usr/bin/env python3
"""
AutoCaddyGuard - Автоматический анализатор логов Caddy
Работает без каких-либо настроек, анализирует логи Caddy и защищает сервер
"""

import os
import sys
import time
import json
import re
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import subprocess
import psutil
import netifaces
from pathlib import Path


class AutoCaddyLogAnalyzer:
    """
    Автоматический анализатор логов Caddy
    Не требует настроек, сам определяет аномалии в трафике
    """
    def __init__(self, log_path="/var/log/caddy/access.log"):
        self.log_path = log_path
        self.log_position = 0  # Позиция в файле для отслеживания новых записей
        self.traffic_stats = defaultdict(lambda: {
            'requests': 0,
            'bytes_sent': 0,
            'error_count': 0,
            'timestamps': deque(maxlen=1000)  # Храним временные метки последних 1000 запросов
        })
        self.suspicious_ips = defaultdict(int)  # Счетчик подозрительных IP
        self.blocked_ips = set()
        self.auto_thresholds = {
            'max_requests_per_minute': 100,  # Будет автоматически пересчитываться
            'max_error_rate': 0.5,  # 50% ошибок
        }
        self.learning_phase = True  # Фаза обучения системы
        self.learning_duration = 300  # 5 минут обучения
        self.start_time = time.time()
        self.request_history = deque(maxlen=10000)  # История последних запросов
        
        # Паттерны для обнаружения подозрительных действий
        self.suspicious_patterns = [
            r'\.\./',  # Path traversal
            r'union.*select',  # SQL injection
            r'<script',  # XSS
            r'exec\(',  # Command execution
            r'bot',  # Bots
            r'scanner',  # Scanners
            r'crawler',  # Crawlers
        ]
        
        self._setup_logging()

    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AutoCaddyGuard - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/astracat_guard.log'),
                logging.StreamHandler()
            ]
        )

    def detect_log_file(self):
        """Автоматическое обнаружение файлов логов Caddy"""
        possible_paths = [
            "/var/log/caddy/access.log",
            "/var/log/caddy/access.json",
            "/usr/local/caddy/access.log",
            "./access.log",
            "/tmp/caddy_access.log"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                self.log_path = path
                logging.info(f"Обнаружен файл логов Caddy: {path}")
                return True
        
        # Если логи не найдены, пробуем определить через процессы
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if 'caddy' in proc.info['name'].lower():
                    # Пытаемся определить параметры запуска Caddy
                    cmd = ' '.join(proc.info['cmdline'])
                    if '--log' in cmd or 'log' in cmd:
                        # В реальной системе можно извлечь путь к логам из параметров
                        logging.info("Найден процесс Caddy, файл логов будет определен автоматически")
                        return True
        except:
            pass
        
        logging.warning(f"Файл логов не найден по стандартным путям. Использую: {self.log_path}")
        return False

    def parse_log_entry(self, line):
        """Парсинг строки лога Caddy (JSON или текст)"""
        try:
            # Пробуем JSON формат (рекомендуется для ASTRACAT_GUARD)
            log_entry = json.loads(line)
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
            # Пробуем текстовый формат
            # Пример: "IP - - [12/Dec/2022:12:34:56 +0000] "GET /path HTTP/1.1" 200 1234"
            match = re.match(r'^(\S+).*"(\w+)\s+([^\s]+)\s+HTTP.*" (\d+) (\d+)', line)
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

    def analyze_request(self, log_entry):
        """Анализ отдельного запроса на предмет подозрительности"""
        if not log_entry:
            return False
            
        ip = log_entry['ip']
        uri = log_entry['uri']
        user_agent = log_entry['user_agent']
        status = log_entry['status']
        timestamp = log_entry['timestamp']
        
        # Обновляем статистику для IP
        self.traffic_stats[ip]['requests'] += 1
        self.traffic_stats[ip]['bytes_sent'] += log_entry['size']
        if 400 <= status < 600:  # Ошибки
            self.traffic_stats[ip]['error_count'] += 1
        self.traffic_stats[ip]['timestamps'].append(timestamp)
        
        # Проверяем на подозрительные паттерны в URI
        uri_suspicious = any(re.search(pattern, uri, re.IGNORECASE) for pattern in self.suspicious_patterns)
        
        # Проверяем User-Agent
        ua_suspicious = any(pattern.lower() in user_agent.lower() for pattern in self.suspicious_patterns)
        
        # В фазе обучения просто собираем статистику
        if self.learning_phase:
            self.request_history.append({
                'ip': ip,
                'timestamp': timestamp,
                'suspicious': uri_suspicious or ua_suspicious
            })
            
            # Проверяем окончание фазы обучения
            if time.time() - self.start_time > self.learning_duration:
                self.learning_phase = False
                self._calculate_dynamic_thresholds()
                logging.info("Завершена фаза обучения, активирована автоматическая защита")
            
            return False
        
        # После обучения применяем правила
        current_time = time.time()
        
        # Рассчитываем количество запросов за последнюю минуту
        recent_requests = sum(1 for t in self.traffic_stats[ip]['timestamps'] 
                             if current_time - t <= 60)
        
        # Рассчитываем коэффициент ошибок
        total_requests = len(self.traffic_stats[ip]['timestamps'])
        error_rate = self.traffic_stats[ip]['error_count'] / max(total_requests, 1)
        
        # Проверяем на аномалии
        is_anomalous = (
            recent_requests > self.auto_thresholds['max_requests_per_minute'] or
            error_rate > self.auto_thresholds['max_error_rate'] or
            uri_suspicious or
            ua_suspicious
        )
        
        if is_anomalous:
            self.suspicious_ips[ip] += 1
            return True
            
        return False

    def _calculate_dynamic_thresholds(self):
        """Расчет динамических порогов на основе собранной статистики"""
        if not self.request_history:
            # Устанавливаем консервативные значения по умолчанию
            self.auto_thresholds['max_requests_per_minute'] = 100
            return
        
        # Рассчитываем среднюю активность
        active_ips = set(entry['ip'] for entry in self.request_history)
        if active_ips:
            avg_requests_per_ip = len(self.request_history) / len(active_ips)
            # Устанавливаем порог в 5 раз выше среднего
            self.auto_thresholds['max_requests_per_minute'] = int(avg_requests_per_ip * 5)
            # Минимум 20 запросов в минуту
            self.auto_thresholds['max_requests_per_minute'] = max(
                self.auto_thresholds['max_requests_per_minute'], 20
            )
        
        logging.info(f"Установлены динамические пороги: {self.auto_thresholds}")

    def block_ip(self, ip):
        """Блокировка IP через iptables"""
        if ip in self.blocked_ips:
            return
            
        try:
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True, capture_output=True, timeout=5)
            self.blocked_ips.add(ip)
            logging.warning(f"IP {ip} заблокирован автоматически из-за подозрительной активности")
        except subprocess.TimeoutExpired:
            logging.error(f"Таймаут при блокировке IP {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Ошибка блокировки IP {ip}: {e}")
        except Exception as e:
            logging.error(f"Неожиданная ошибка блокировки IP {ip}: {e}")

    def read_new_logs(self):
        """Чтение новых записей из лога"""
        try:
            # Проверяем размер файла
            if not os.path.exists(self.log_path):
                return []
                
            file_size = os.path.getsize(self.log_path)
            if file_size < self.log_position:
                # Файл, вероятно, был пересоздан (ротация)
                self.log_position = 0
            
            with open(self.log_path, 'r') as f:
                f.seek(self.log_position)
                new_lines = f.readlines()
                self.log_position = f.tell()
                
            return new_lines
        except Exception as e:
            logging.error(f"Ошибка чтения лога {self.log_path}: {e}")
            return []

    def monitor_logs(self):
        """Основной метод мониторинга логов"""
        # Пытаемся обнаружить файл логов
        self.detect_log_file()
        
        logging.info(f"Начат мониторинг лога Caddy: {self.log_path}")
        
        while True:
            try:
                new_lines = self.read_new_logs()
                
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    log_entry = self.parse_log_entry(line)
                    if log_entry and self.analyze_request(log_entry):
                        ip = log_entry['ip']
                        self.block_ip(ip)
                
                # Периодически очищаем старую статистику (старше 10 минут)
                current_time = time.time()
                for ip in list(self.traffic_stats.keys()):
                    recent_timestamps = [t for t in self.traffic_stats[ip]['timestamps'] 
                                       if current_time - t <= 600]
                    self.traffic_stats[ip]['timestamps'] = deque(recent_timestamps, maxlen=1000)
                    
                    # Если нет активности больше 10 минут, удаляем статистику
                    if not recent_timestamps and ip not in self.blocked_ips:
                        del self.traffic_stats[ip]
                
                time.sleep(1)  # Проверяем каждую секунду
                
            except KeyboardInterrupt:
                logging.info("Остановка мониторинга логов")
                break
            except Exception as e:
                logging.error(f"Ошибка в мониторинге логов: {e}")
                time.sleep(5)  # Пауза перед повторной попыткой


class AutoCaddyGuard:
    """
    Комплексная автоматическая защита для Caddy
    """
    def __init__(self):
        self.log_analyzer = AutoCaddyLogAnalyzer()
        self.monitoring_thread = None
        self.monitoring = False

    def start_protection(self):
        """Запуск автоматической защиты"""
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self.log_analyzer.monitor_logs, daemon=True)
        self.monitoring_thread.start()
        logging.info("Автоматическая защита Caddy запущена")
        logging.info("Система работает без каких-либо настроек!")

    def stop_protection(self):
        """Остановка защиты"""
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        logging.info("Автоматическая защита Caddy остановлена")

    def get_status(self):
        """Получить статус защиты"""
        return {
            'monitoring': self.monitoring,
            'blocked_ips_count': len(self.log_analyzer.blocked_ips),
            'suspicious_ips_count': len(self.log_analyzer.suspicious_ips),
            'learning_phase': self.log_analyzer.learning_phase,
            'log_file': self.log_analyzer.log_path
        }


def main():
    """Основная функция"""
    print("Запуск AutoCaddyGuard - автоматическая защита для Caddy")
    print("Система работает полностью автоматически без настроек...")
    
    guard = AutoCaddyGuard()
    
    try:
        guard.start_protection()
        
        print("Система активирована и работает!")
        print("Для просмотра статуса нажмите Ctrl+C")
        
        while True:
            time.sleep(15)
            status = guard.get_status()
            phase_msg = "обучение" if status['learning_phase'] else "защита"
            print(f"Статус ({phase_msg}): заблокировано {status['blocked_ips_count']} IP, "
                  f"файл логов: {status['log_file']}")
            
    except KeyboardInterrupt:
        print("\nОстановка системы защиты...")
        guard.stop_protection()
        print("Система остановлена.")


if __name__ == "__main__":
    main()