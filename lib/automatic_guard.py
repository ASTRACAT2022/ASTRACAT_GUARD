#!/usr/bin/env python3
"""
ASTRACAT_GUARD - Полностью автоматическая система защиты
Работает "из коробки" без каких-либо настроек
"""

import os
import sys
import time
import logging
import threading
import subprocess
import psutil
import netifaces
from pathlib import Path
from datetime import datetime


class AutoSetupGuard:
    """
    Автоматическая система защиты, которая запускается без настроек
    """
    def __init__(self):
        self.setup_logging()
        self.auto_detect_services()
        self.auto_detect_network()
        self.auto_detect_logs()
        self.selected_daemon = None

    def setup_logging(self):
        """Настройка логирования без конфигурации"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ASTRACAT_AUTO - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/astracat_guard_auto.log'),
                logging.StreamHandler()
            ]
        )

    def auto_detect_services(self):
        """Автоматическое определение запущенных сервисов"""
        self.services = {}
        
        # Проверяем запущенные процессы
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline']).lower()
                
                if 'caddy' in name or 'caddy' in cmdline:
                    self.services['caddy'] = {
                        'pid': proc.info['pid'],
                        'cmdline': proc.info['cmdline']
                    }
                elif 'nginx' in name or 'nginx' in cmdline:
                    self.services['nginx'] = {
                        'pid': proc.info['pid'],
                        'cmdline': proc.info['cmdline']
                    }
                elif 'apache' in name or 'httpd' in name:
                    self.services['apache'] = {
                        'pid': proc.info['pid'],
                        'cmdline': proc.info['cmdline']
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        logging.info(f"Обнаружены сервисы: {list(self.services.keys())}")

    def auto_detect_network(self):
        """Автоматическое определение сетевых интерфейсов и активных портов"""
        self.interfaces = []
        self.active_ports = []
        
        # Обнаружение интерфейсов
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs and interface != 'lo':
                self.interfaces.append(interface)
        
        # Обнаружение активных портов
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                self.active_ports.append(conn.laddr.port)
        
        logging.info(f"Обнаружены интерфейсы: {self.interfaces}")
        logging.info(f"Обнаружены активные порты: {list(set(self.active_ports))}")

    def auto_detect_logs(self):
        """Автоматическое определение файлов логов"""
        self.log_files = []
        
        # Стандартные пути для различных сервисов
        common_log_paths = [
            '/var/log/caddy/access.log',
            '/var/log/nginx/access.log',
            '/var/log/apache2/access.log',
            '/var/log/httpd/access_log',
            '/var/log/caddy/access.json',
            '/usr/local/caddy/access.log',
            '/opt/caddy/access.log',
            './access.log',
            '/tmp/access.log'
        ]
        
        for path in common_log_paths:
            if os.path.exists(path):
                self.log_files.append(path)
        
        logging.info(f"Обнаружены файлы логов: {self.log_files}")

    def determine_protection_strategy(self):
        """Определение стратегии защиты на основе обнаруженных сервисов"""
        if 'caddy' in self.services:
            logging.info("Обнаружен Caddy, используется специализированная защита")
            try:
                from auto_caddy_guard import AutoCaddyGuard
                self.selected_daemon = AutoCaddyGuard()
                return "caddy"
            except ImportError:
                # Если не удается импортировать специализированную версию, используем общую
                pass
        
        # Для всех остальных случаев используем общую автоматическую защиту
        try:
            from auto_guard_daemon import AutoProtectionSystem
            self.selected_daemon = AutoProtectionSystem()
            return "general"
        except ImportError:
            logging.error("Не удается загрузить модули защиты")
            return None

    def start_automatic_protection(self):
        """Запуск автоматической защиты"""
        strategy = self.determine_protection_strategy()
        
        if not self.selected_daemon:
            logging.error("Не удалось определить подходящую систему защиты")
            return False
        
        if strategy == "caddy":
            logging.info("Запуск автоматической защиты для Caddy")
            self.selected_daemon.start_protection()
        elif strategy == "general":
            logging.info("Запуск общей автоматической защиты")
            self.selected_daemon.start_protection()
        
        logging.info("Система защиты запущена в автоматическом режиме")
        return True

    def get_status(self):
        """Получить статус системы"""
        if self.selected_daemon and hasattr(self.selected_daemon, 'get_status'):
            return self.selected_daemon.get_status()
        return {'error': 'No active daemon'}

    def run_forever(self):
        """Запуск системы до прерывания"""
        logging.info("ASTRACAT_GUARD запущен в полностью автоматическом режиме")
        logging.info("Защита активирована без каких-либо настроек")
        
        try:
            while True:
                time.sleep(30)
                status = self.get_status()
                logging.info(f"Статус защиты: {status}")
        except KeyboardInterrupt:
            logging.info("Получен сигнал остановки")
            self.stop_protection()

    def stop_protection(self):
        """Остановка защиты"""
        if self.selected_daemon and hasattr(self.selected_daemon, 'stop_protection'):
            self.selected_daemon.stop_protection()
        logging.info("Система защиты остановлена")


def check_dependencies():
    """Проверка необходимых зависимостей"""
    required_packages = ['psutil', 'netifaces', 'netaddr']
    missing = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Установите недостающие пакеты: pip install {' '.join(missing)}")
        return False
    
    return True


def main():
    """Основная функция запуска автоматической защиты"""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                ASTRACAT_GUARD Автоматическая                ║")
    print("║                    Защита 'Из Коробки'                      ║")
    print("║              Работает без каких-либо настроек               ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("Система автоматически:")
    print("• Обнаруживает запущенные веб-серверы (Caddy, Nginx, Apache)")
    print("• Определяет сетевые интерфейсы и порты")
    print("• Находит файлы логов")
    print("• Активирует соответствующую защиту")
    print("• Настраивает пороги автоматически")
    print()
    print("Запуск системы...")
    
    # Проверяем зависимости
    if not check_dependencies():
        return
    
    # Создаем и запускаем систему
    guard = AutoSetupGuard()
    
    if guard.start_automatic_protection():
        print("Система активирована!")
        print("Для просмотра логов проверьте: /var/log/astracat_guard_auto.log")
        print("Для остановки нажмите Ctrl+C")
        print()
        guard.run_forever()
    else:
        print("Ошибка активации системы защиты")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())