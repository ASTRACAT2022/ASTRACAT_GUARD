#!/usr/bin/env python3
"""
ASTRACAT_GUARD Telegram Bot
Provides attack statistics and visualizations via Telegram
"""

import os
import sys
import time
import json
import logging
import threading
import asyncio
import requests
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
from io import BytesIO
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes


class ASTRACATGuardBot:
    def __init__(self, bot_token):
        self.bot_token = bot_token
        self.application = Application.builder().token(bot_token).build()
        self.bot = Bot(bot_token)  # Define the bot instance

        # Set up database for storing stats
        self.db_path = '/opt/astracat_guard/stats.db'
        self.init_db()

        # Channel and user management
        self.authorized_channels = set()  # Will store authorized channel IDs
        self.admin_users = self.load_admin_users()  # Load admin user IDs from file

        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ASTRACAT_GUARD_BOT - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Register handlers
        self.register_handlers()

    def load_admin_users(self):
        """Load admin user IDs from configuration file"""
        admin_file = '/opt/astracat_guard/conf/admin_users.json'
        try:
            if os.path.exists(admin_file):
                with open(admin_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('admin_users', []))
            else:
                # Create default admin file if it doesn't exist
                os.makedirs('/opt/astracat_guard/conf', exist_ok=True)
                default_admins = set()
                with open(admin_file, 'w') as f:
                    json.dump({'admin_users': []}, f)
                return default_admins
        except Exception as e:
            self.logger.error(f"Error loading admin users: {e}")
            return set()
        
    def init_db(self):
        """Initialize SQLite database for storing statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create tables for statistics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    blocked_packets INTEGER,
                    blocked_ips INTEGER,
                    total_requests INTEGER,
                    attack_status TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT
                )
            ''')

            # Create table for storing channel subscriptions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS channel_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER UNIQUE,
                    added_by INTEGER,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            conn.close()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
    
    def register_handlers(self):
        """Register bot command handlers"""
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("stats", self.stats_command))
        self.application.add_handler(CommandHandler("today", self.today_stats_command))
        self.application.add_handler(CommandHandler("blocked", self.blocked_command))
        self.application.add_handler(CommandHandler("graph", self.graph_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("add_channel", self.add_channel_command))
        self.application.add_handler(CommandHandler("remove_channel", self.remove_channel_command))
        self.application.add_handler(CommandHandler("add_admin", self.add_admin_command))
        self.application.add_handler(CommandHandler("remove_admin", self.remove_admin_command))
        self.application.add_handler(CommandHandler("list_admins", self.list_admins_command))
        
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        message = """
🤖 ASTRACAT_GUARD Telegram Bot

Добро пожаловать в систему мониторинга защиты сервера!

Доступные команды:
/stats - Общая статистика защиты
/today - Статистика за сегодня
/blocked - Последние заблокированные IP
/graph - График атак за сегодня
/add_channel - Добавить этот канал в мониторинг
/remove_channel - Удалить канал из мониторинга
/help - Показать это сообщение
        """
        await update.message.reply_text(message)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        message = """
🤖 ASTRACAT_GUARD Telegram Bot

Доступные команды:
/stats - Общая статистика защиты
/today - Статистика за сегодня
/blocked - Последние заблокированные IP
/graph - График атак за сегодня
/add_channel - Добавить этот канал в мониторинг
/remove_channel - Удалить канал из мониторинга
/help - Показать это сообщение

Бот автоматически отправляет уведомления о новых атаках в добавленные каналы.
        """
        await update.message.reply_text(message)
    
    def get_current_stats(self):
        """Get current protection statistics from status file"""
        try:
            with open('/opt/astracat_guard/status/status.json', 'r') as f:
                status_data = json.load(f)
            
            # Get iptables statistics
            try:
                from iptables_manager import IPTablesManager
                iptables_mgr = IPTablesManager()
                iptables_stats = iptables_mgr.get_chain_stats()
            except:
                iptables_stats = {'rules': 0, 'packets': 0, 'bytes': 0}
            
            stats = {
                'active_attack': status_data.get('active', False),
                'blocked_requests_last_minute': status_data.get('blocked_requests_last_minute', 0),
                'total_blocked_requests': status_data.get('total_blocked_requests', 0),
                'total_requests': status_data.get('total_requests', 0),
                'timestamp': status_data.get('timestamp', time.time()),
                'iptables_rules': iptables_stats.get('rules', 0),
                'iptables_packets': iptables_stats.get('packets', 0),
                'iptables_bytes': iptables_stats.get('bytes', 0)
            }
            return stats
        except Exception as e:
            self.logger.error(f"Error getting current stats: {e}")
            return None
    
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command"""
        stats = self.get_current_stats()
        if stats:
            attack_status = "🔴 Атака!" if stats['active_attack'] else "🟢 Норма"
            message = f"""
📊 Статистика ASTRACAT_GUARD:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Статус: {attack_status}
Заблокировано за последнюю минуту: {stats['blocked_requests_last_minute']} запросов
Всего заблокировано: {stats['total_blocked_requests']} запросов
Всего запросов: {stats['total_requests']}
Правила iptables: {stats['iptables_rules']}
Заблокировано пакетов: {stats['iptables_packets']}
Обработано байт: {stats['iptables_bytes']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """
        else:
            message = "❌ Не удалось получить статистику. Проверьте, запущен ли ASTRACAT_GUARD."

        await update.message.reply_text(message)
    
    async def today_stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /today command"""
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COUNT(*), SUM(blocked_packets), SUM(blocked_ips), SUM(total_requests)
            FROM attack_stats
            WHERE timestamp >= ?
        ''', (today_start.strftime('%Y-%m-%d %H:%M:%S'),))

        result = cursor.fetchone()
        if result and result[0] > 0:
            records_count, total_blocked_packets, total_blocked_ips, total_requests = result
            total_blocked_packets = total_blocked_packets or 0
            total_blocked_ips = total_blocked_ips or 0
            total_requests = total_requests or 0

            message = f"""
📈 Статистика за сегодня ({datetime.now().strftime('%d.%m.%Y')}):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Записей статистики: {records_count}
Заблокировано пакетов: {total_blocked_packets:,}
Заблокировано IP: {total_blocked_ips}
Обработано запросов: {total_requests:,}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """
        else:
            message = "📊 Сегодня еще нет статистики."

        conn.close()
        await update.message.reply_text(message)
    
    async def blocked_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /blocked command"""
        try:
            from iptables_manager import IPTablesManager
            iptables_mgr = IPTablesManager()
            blocked_ips = iptables_mgr.get_blocked_ips()

            if blocked_ips:
                message = f"🔒 Последние заблокированные IP ({len(blocked_ips)}):\n"
                for ip in sorted(blocked_ips)[-10:]:  # Show last 10
                    message += f"• {ip}\n"

                if len(blocked_ips) > 10:
                    message += f"\n... и еще {len(blocked_ips) - 10}"
            else:
                message = "🟢 Нет заблокированных IP на данный момент."
        except Exception as e:
            message = f"❌ Ошибка получения заблокированных IP: {e}"

        await update.message.reply_text(message)
    
    def create_attack_graph(self):
        """Create a graph of attacks for today"""
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, blocked_packets, blocked_ips
            FROM attack_stats
            WHERE timestamp >= ?
            ORDER BY timestamp
        ''', (today_start.strftime('%Y-%m-%d %H:%M:%S'),))
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return None
        
        timestamps = []
        blocked_packets = []
        blocked_ips = []
        
        for row in rows:
            timestamps.append(datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
            blocked_packets.append(row[1] or 0)
            blocked_ips.append(row[2] or 0)
        
        # Create the plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Plot blocked packets
        ax1.plot(timestamps, blocked_packets, 'r-', linewidth=2, label='Заблокированные пакеты')
        ax1.set_title('Заблокированные пакеты за сегодня', fontsize=14)
        ax1.set_ylabel('Количество пакетов')
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Format x-axis
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.xaxis.set_major_locator(mdates.HourLocator(interval=2))
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
        
        # Plot blocked IPs
        ax2.plot(timestamps, blocked_ips, 'b-', linewidth=2, label='Заблокированные IP')
        ax2.set_title('Заблокированные IP за сегодня', fontsize=14)
        ax2.set_ylabel('Количество IP')
        ax2.set_xlabel('Время')
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        # Format x-axis
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax2.xaxis.set_major_locator(mdates.HourLocator(interval=2))
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
        
        plt.tight_layout()
        
        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return img_buffer
    
    async def graph_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /graph command"""
        img_buffer = self.create_attack_graph()

        if img_buffer:
            await update.message.reply_photo(photo=img_buffer)
        else:
            await update.message.reply_text("📊 Сегодня еще нет данных для графика.")
    
    async def add_channel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Add current chat to monitoring channels"""
        chat_id = update.effective_message.id if hasattr(update.effective_message, 'id') else update.effective_message.chat_id
        user_id = update.effective_user.id

        # Check if user is admin
        if user_id in self.admin_users:
            try:
                # Add to database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('INSERT OR REPLACE INTO channel_subscriptions (chat_id, added_by) VALUES (?, ?)', (chat_id, user_id))
                conn.commit()

                # Add to in-memory set
                self.authorized_channels.add(chat_id)
                conn.close()

                await update.message.reply_text("✅ Канал добавлен в список мониторинга.")

                # Load all subscribed channels from database when starting the bot
                self.load_authorized_channels()
            except Exception as e:
                self.logger.error(f"Error adding channel: {e}")
                await update.message.reply_text("❌ Ошибка при добавлении канала.")
        else:
            await update.message.reply_text("❌ У вас нет прав для добавления каналов.")

    async def remove_channel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Remove current chat from monitoring channels"""
        chat_id = update.effective_message.id if hasattr(update.effective_message, 'id') else update.effective_message.chat_id
        user_id = update.effective_user.id

        # Check if user is admin
        if user_id in self.admin_users:
            try:
                # Remove from database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM channel_subscriptions WHERE chat_id = ?', (chat_id,))
                conn.commit()

                # Remove from in-memory set
                self.authorized_channels.discard(chat_id)
                conn.close()

                await update.message.reply_text("✅ Канал удален из списка мониторинга.")
            except Exception as e:
                self.logger.error(f"Error removing channel: {e}")
                await update.message.reply_text("❌ Ошибка при удалении канала.")
        else:
            await update.message.reply_text("❌ У вас нет прав для удаления каналов.")

    def load_authorized_channels(self):
        """Load authorized channels from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT chat_id FROM channel_subscriptions')
            rows = cursor.fetchall()
            conn.close()

            self.authorized_channels = {row[0] for row in rows}
            self.logger.info(f"Loaded {len(self.authorized_channels)} authorized channels from database")
        except Exception as e:
            self.logger.error(f"Error loading authorized channels: {e}")
    
    def record_stats(self):
        """Periodically record statistics to database"""
        while True:
            try:
                stats = self.get_current_stats()
                if stats:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT INTO attack_stats 
                        (blocked_packets, blocked_ips, total_requests, attack_status)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        stats['iptables_packets'],
                        stats['iptables_rules'],
                        stats['total_requests'],
                        'active' if stats['active_attack'] else 'normal'
                    ))
                    
                    conn.commit()
                    conn.close()
                    
                    # Send notification to channels if there's an active attack
                    if stats['active_attack']:
                        # Create a new event loop in a separate thread for the async call
                        notification_thread = threading.Thread(
                            target=lambda: asyncio.run(self.send_attack_notification(stats)),
                            daemon=True
                        )
                        notification_thread.start()
                
                time.sleep(60)  # Record every minute
            except Exception as e:
                self.logger.error(f"Error recording stats: {e}")
                time.sleep(60)
    
    async def send_attack_notification(self, stats):
        """Send attack notification to all authorized channels"""
        message = f"""
🚨 ОБНАРУЖЕНА АТАКА! 🚨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
Заблокировано пакетов: {stats['iptables_packets']:,}
Активных блокировок: {stats['iptables_rules']}
Заблокировано за минуту: {stats['blocked_requests_last_minute']:,}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                """

        for chat_id in self.authorized_channels:
            try:
                # Use the application's bot instance to send messages
                await self.application.bot.send_message(chat_id=chat_id, text=message)
                self.logger.info(f"Attack notification sent to {chat_id}")
            except Exception as e:
                self.logger.error(f"Error sending notification to {chat_id}: {e}")

    def send_periodic_summary(self):
        """Send periodic summary to channels"""
        while True:
            try:
                # Send summary every hour
                time.sleep(3600)

                stats = self.get_current_stats()
                if stats:
                    message = f"""
📊 ПЕРИОДИЧЕСКАЯ СТАТИСТИКА:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
Статус: {'🔴 Атака' if stats['active_attack'] else '🟢 Норма'}
Заблокировано пакетов: {stats['iptables_packets']:,}
Активных блокировок: {stats['iptables_rules']}
Всего запросов: {stats['total_requests']:,}
Заблокировано за минуту: {stats['blocked_requests_last_minute']:,}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    """

                    def send_summary():
                        import asyncio
                        async def send_to_channels():
                            for chat_id in self.authorized_channels:
                                try:
                                    await self.application.bot.send_message(chat_id=chat_id, text=message)
                                    self.logger.info(f"Periodic summary sent to {chat_id}")
                                except Exception as e:
                                    self.logger.error(f"Error sending summary to {chat_id}: {e}")

                        asyncio.run(send_to_channels())

                    # Run the async function in a separate thread
                    summary_thread = threading.Thread(target=send_summary, daemon=True)
                    summary_thread.start()
            except Exception as e:
                self.logger.error(f"Error in periodic summary: {e}")
    
    async def run(self):
        """Start the bot"""
        self.logger.info("Starting ASTRACAT_GUARD Telegram Bot...")

        # Load authorized channels from database on start
        self.load_authorized_channels()

        # Start background threads
        stats_thread = threading.Thread(target=self.record_stats, daemon=True)
        summary_thread = threading.Thread(target=self.send_periodic_summary, daemon=True)

        stats_thread.start()
        summary_thread.start()

        # Start bot polling
        await self.application.run_polling()


async def main():
    # Get bot token from environment variable
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')

    if not bot_token:
        print("Error: TELEGRAM_BOT_TOKEN environment variable not set")
        print("Please set it: export TELEGRAM_BOT_TOKEN='your_bot_token'")
        return

    bot = ASTRACATGuardBot(bot_token)
    await bot.run()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())