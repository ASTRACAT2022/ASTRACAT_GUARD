#!/usr/bin/env python3
"""
ASTRACAT_GUARD - Автоматическая система анализа трафика
Полностью автоматическое обнаружение и защита без настроек
"""

import os
import sys
import time
import json
import yaml
import logging
import threading
import subprocess
import psutil
import socket
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
import ipaddress
import netifaces  # pip install netifaces
import netaddr    # pip install netaddr


@dataclass
class TrafficPattern:
    """Описание паттерна трафика"""
    ip: str
    requests_per_second: float
    connection_count: int
    bytes_sent: int
    bytes_received: int
    suspicious_paths: List[str]
    user_agents: List[str]
    time_window: float


class AutoTrafficAnalyzer:
    """
    Автоматический анализатор трафика
    Самостоятельно определяет нормальные и аномальные паттерны
    """
    def __init__(self):
        self.traffic_history = defaultdict(deque)  # История трафика по IP
        self.normal_patterns = {}  # Обнаруженные нормальные паттерны
        self.suspicious_ips = defaultdict(int)  # Подозрительные IP и счетчики
        self.learning_phase = True  # Фаза обучения системы
        self.learning_duration = 300  # 5 минут для обучения
        self.start_time = time.time()
        
        # Статистика для автоматического определения порогов
        self.stats_collector = {
            'avg_rps': deque(maxlen=100),  # Средние запросы в секунду
            'avg_connections': deque(maxlen=100),
            'avg_bytes': deque(maxlen=100),
        }
        
        # Автоматические пороги, определяемые системой
        self.auto_thresholds = {
            'rps_multiplier': 5.0,  # Во сколько раз превышает среднее
            'connection_multiplier': 10.0,
            'byte_multiplier': 8.0,
        }

    def collect_traffic_data(self, ip: str, timestamp: float, **kwargs) -> TrafficPattern:
        """Сбор данных о трафике от IP"""
        data = TrafficPattern(
            ip=ip,
            requests_per_second=kwargs.get('rps', 0),
            connection_count=kwargs.get('connections', 0),
            bytes_sent=kwargs.get('bytes_sent', 0),
            bytes_received=kwargs.get('bytes_received', 0),
            suspicious_paths=kwargs.get('suspicious_paths', []),
            user_agents=kwargs.get('user_agents', []),
            time_window=kwargs.get('time_window', 1.0)
        )
        
        self.traffic_history[ip].append((timestamp, data))
        
        # Очистка старых данных (старше 5 минут)
        while (self.traffic_history[ip] and 
               timestamp - self.traffic_history[ip][0][0] > 300):
            self.traffic_history[ip].popleft()
        
        return data

    def calculate_dynamic_thresholds(self) -> Dict[str, float]:
        """Автоматический расчет порогов на основе собранной статистики"""
        if not self.stats_collector['avg_rps']:
            # Возвращаем консервативные значения по умолчанию
            return {
                'max_rps': 10.0,
                'max_connections': 20,
                'max_bytes_per_sec': 1024 * 100  # 100 KB/s
            }
        
        # Рассчитываем средние значения
        avg_rps = sum(self.stats_collector['avg_rps']) / len(self.stats_collector['avg_rps'])
        avg_connections = sum(self.stats_collector['avg_connections']) / len(self.stats_collector['avg_connections'])
        avg_bytes = sum(self.stats_collector['avg_bytes']) / len(self.stats_collector['avg_bytes'])
        
        # Применяем множители для определения порогов
        thresholds = {
            'max_rps': avg_rps * self.auto_thresholds['rps_multiplier'],
            'max_connections': avg_connections * self.auto_thresholds['connection_multiplier'],
            'max_bytes_per_sec': avg_bytes * self.auto_thresholds['byte_multiplier']
        }
        
        # Устанавливаем минимальные пороги для избежания слишком низких значений
        thresholds['max_rps'] = max(thresholds['max_rps'], 10.0)
        thresholds['max_connections'] = max(thresholds['max_connections'], 20)
        thresholds['max_bytes_per_sec'] = max(thresholds['max_bytes_per_sec'], 1024 * 100)
        
        return thresholds

    def is_anomalous_traffic(self, ip: str, pattern: TrafficPattern) -> bool:
        """Проверка, является ли трафик аномальным"""
        # В фазе обучения просто собираем данные
        if self.learning_phase:
            # Обновляем статистику для автоматического определения нормы
            self.stats_collector['avg_rps'].append(pattern.requests_per_second)
            self.stats_collector['avg_connections'].append(pattern.connection_count)
            self.stats_collector['avg_bytes'].append(pattern.bytes_sent + pattern.bytes_received)
            
            # Проверяем, завершена ли фаза обучения
            if time.time() - self.start_time > self.learning_duration:
                self.learning_phase = False
                logging.info("Фаза обучения завершена. Система перешла в режим автоматической защиты.")
            return False
        
        # После обучения используем автоматически рассчитанные пороги
        thresholds = self.calculate_dynamic_thresholds()
        
        # Проверяем аномалии
        is_anomaly = (
            pattern.requests_per_second > thresholds['max_rps'] or
            pattern.connection_count > thresholds['max_connections'] or
            (pattern.bytes_sent + pattern.bytes_received) / pattern.time_window > thresholds['max_bytes_per_sec'] or
            len(pattern.suspicious_paths) > 5 or  # Подозрительные пути
            len([ua for ua in pattern.user_agents if 'bot' in ua.lower() or 'crawler' in ua.lower()]) > 0
        )
        
        if is_anomaly:
            self.suspicious_ips[ip] += 1
            # Если IP становится постоянным нарушителем
            if self.suspicious_ips[ip] > 5:
                return True
        
        return is_anomaly

    def get_reputation_score(self, ip: str) -> float:
        """Получить репутацию IP (0.0 - чистый, 1.0 - полностью подозрительный)"""
        if ip in self.suspicious_ips:
            score = min(self.suspicious_ips[ip] / 10.0, 1.0)
            return score
        return 0.0


class NetworkMonitor:
    """
    Мониторинг сетевого трафика без настроек
    Автоматически определяет интерфейсы и порты
    """
    def __init__(self):
        self.interfaces = self._detect_active_interfaces()
        self.protected_ports = self._detect_active_ports()
        self.current_connections = {}
        self.connection_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
        self.packet_analyzer = AutoTrafficAnalyzer()
        
    def _detect_active_interfaces(self) -> List[str]:
        """Автоматическое обнаружение активных сетевых интерфейсов"""
        try:
            interfaces = []
            for interface in netifaces.interfaces():
                # Проверяем, есть ли у интерфейса IP-адрес
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                    # Пропускаем loopback
                    if interface != 'lo' and not interface.startswith('docker'):
                        interfaces.append(interface)
            return interfaces if interfaces else ['eth0']  # По умолчанию eth0
        except:
            return ['eth0']  # Резервный вариант

    def _detect_active_ports(self) -> List[int]:
        """Автоматическое обнаружение используемых портов"""
        try:
            active_ports = set()
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    active_ports.add(conn.laddr.port)
            
            # Возвращаем только стандартные веб-порты
            web_ports = [port for port in active_ports if port in [80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 8000, 8001, 9000]]
            return web_ports if web_ports else [80, 443]  # По умолчанию HTTP/HTTPS
        except:
            return [80, 443]  # Резервный вариант

    def monitor_traffic(self):
        """Мониторинг текущего трафика"""
        try:
            connections = psutil.net_connections(kind='inet')
            current_timestamp = time.time()
            
            for conn in connections:
                if conn.raddr and conn.laddr.port in self.protected_ports:
                    remote_ip = conn.raddr.ip
                    local_port = conn.laddr.port
                    
                    # Обновляем статистику соединений
                    conn_key = f"{remote_ip}:{conn.raddr.port}"
                    self.connection_stats[remote_ip]['count'] += 1
                    
                    # Пытаемся получить статистику байтов (требует root прав)
                    try:
                        net_io = psutil.net_io_counters(pernic=True)
                        for interface, stats in net_io.items():
                            if interface in self.interfaces:
                                self.connection_stats[remote_ip]['bytes'] += stats.bytes_sent + stats.bytes_recv
                    except:
                        pass  # Игнорируем, если нет прав
            
            # Анализируем collected данные
            for ip, stats in self.connection_stats.items():
                if stats['count'] > 0:
                    # Создаем паттерн трафика
                    pattern = self.packet_analyzer.collect_traffic_data(
                        ip=ip,
                        timestamp=current_timestamp,
                        rps=stats['count'] / 5.0,  # За последние 5 секунд
                        connections=stats['count'],
                        bytes_sent=stats['bytes'],
                        bytes_received=0,
                        time_window=5.0
                    )
                    
                    # Проверяем на аномалии
                    if self.packet_analyzer.is_anomalous_traffic(ip, pattern):
                        self.block_ip(ip)
            
            # Сбрасываем статистику для следующего цикла
            for ip in self.connection_stats:
                self.connection_stats[ip] = {'count': 0, 'bytes': 0}
                
        except Exception as e:
            logging.error(f"Ошибка мониторинга трафика: {e}")

    def block_ip(self, ip):
        """Блокировка IP-адреса"""
        try:
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True, capture_output=True, timeout=5)
            logging.warning(f"IP {ip} заблокирован автоматически системой безопасности")
        except subprocess.TimeoutExpired:
            logging.error(f"Таймаут при блокировке IP {ip}")
        except subprocess.CalledProcessError:
            logging.error(f"Не удалось заблокировать IP {ip}")
        except Exception as e:
            logging.error(f"Ошибка блокировки IP {ip}: {e}")


class AutoProtectionSystem:
    """
    Основная система автоматической защиты
    Работает без каких-либо настроек пользователя
    """
    def __init__(self):
        self.network_monitor = NetworkMonitor()
        self.traffic_analyzer = AutoTrafficAnalyzer()
        self.blocked_ips = set()
        self.monitoring = False
        self.monitor_thread = None
        
        # Настройка логирования
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ASTRACAT_GUARD - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/astracat_guard.log'),
                logging.StreamHandler()
            ]
        )
        
        logging.info("ASTRACAT_GUARD автоматическая защита запущена")
        logging.info(f"Обнаруженные интерфейсы: {self.network_monitor.interfaces}")
        logging.info(f"Обнаруженные защищаемые порты: {self.network_monitor.protected_ports}")

    def start_protection(self):
        """Запуск автоматической защиты"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        logging.info("Система автоматической защиты запущена")

    def stop_protection(self):
        """Остановка защиты"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logging.info("Система автоматической защиты остановлена")

    def _monitoring_loop(self):
        """Основной цикл мониторинга"""
        while self.monitoring:
            try:
                # Мониторим трафик
                self.network_monitor.monitor_traffic()
                
                # Проверяем репутацию IP
                for ip in list(self.traffic_analyzer.suspicious_ips.keys()):
                    reputation = self.traffic_analyzer.get_reputation_score(ip)
                    if reputation > 0.7 and ip not in self.blocked_ips:  # Высокий риск
                        self.network_monitor.block_ip(ip)
                        self.blocked_ips.add(ip)
                
                # Пауза между циклами
                time.sleep(5)
                
            except Exception as e:
                logging.error(f"Ошибка в цикле мониторинга: {e}")
                time.sleep(1)

    def get_status(self):
        """Получить статус защиты"""
        return {
            'monitoring': self.monitoring,
            'detected_interfaces': self.network_monitor.interfaces,
            'protected_ports': self.network_monitor.protected_ports,
            'blocked_ips_count': len(self.blocked_ips),
            'suspicious_ips_count': len(self.traffic_analyzer.suspicious_ips),
            'learning_phase': self.traffic_analyzer.learning_phase
        }


def main():
    """Основная функция запуска системы"""
    print("Запуск ASTRACAT_GUARD - автоматическая система защиты")
    print("Система начнет работу без каких-либо настроек...")
    
    guard = AutoProtectionSystem()
    
    try:
        guard.start_protection()
        
        print("Система активирована!")
        print("Для просмотра статуса нажмите Ctrl+C")
        
        while True:
            time.sleep(10)
            status = guard.get_status()
            if not status['learning_phase']:
                print(f"Статус: защищено {status['blocked_ips_count']} IP, подозрительно {status['suspicious_ips_count']} IP")
            
    except KeyboardInterrupt:
        print("\nОстановка системы защиты...")
        guard.stop_protection()
        print("Система остановлена.")


if __name__ == "__main__":
    main()