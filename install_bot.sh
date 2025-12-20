#!/bin/bash
#
# ASTRACAT_GUARD Telegram Bot Installer
# Установка Telegram бота для мониторинга атак

set -e  # Exit on any error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         ASTRACAT_GUARD Telegram Bot Installer             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}Running as root - proceeding with installation${NC}"
else
   echo -e "${RED}This script must be run as root (use sudo)!${NC}"
   exit 1
fi

# Activate virtual environment
source /opt/astracat_guard/myenv/bin/activate

# Install required Python packages
echo -e "${BLUE}Installing required Python packages...${NC}"

pip install python-telegram-bot matplotlib requests

echo -e "${GREEN}Python packages installed${NC}"

# Make the bot script executable
chmod +x /root/astracat_guard/telegram_bot.py

# Create a systemd service for the bot
cat > /etc/systemd/system/astracat-guard-bot.service << EOF
[Unit]
Description=ASTRACAT_GUARD Telegram Bot
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/astracat_guard
Environment=TELEGRAM_BOT_TOKEN=
ExecStart=/opt/astracat_guard/myenv/bin/python /root/astracat_guard/telegram_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    INSTALLATION COMPLETE                   ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║ Telegram Bot installed successfully!                         ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║ To configure the bot:                                        ║${NC}"
echo -e "${GREEN}║ 1. Get a bot token from @BotFather on Telegram               ║${NC}"
echo -e "${GREEN}║ 2. Set the environment variable:                             ║${NC}"
echo -e "${GREEN}║    sudo systemctl edit astracat-guard-bot                   ║${NC}"
echo -e "${GREEN}║ 3. Add:                                                      ║${NC}"
echo -e "${GREEN}║    [Service]                                                  ║${NC}"
echo -e "${GREEN}║    Environment=TELEGRAM_BOT_TOKEN=your_token_here             ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║ To start the bot:                                            ║${NC}"
echo -e "${GREEN}║   sudo systemctl start astracat-guard-bot                    ║${NC}"
echo -e "${GREEN}║   sudo systemctl enable astracat-guard-bot                   ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║ Available commands in the bot:                               ║${NC}"
echo -e "${GREEN}║ /start - Start the bot                                       ║${NC}"
echo -e "${GREEN}║ /stats - Current protection statistics                       ║${NC}"
echo -e "${GREEN}║ /today - Statistics for today                                ║${NC}"
echo -e "${GREEN}║ /blocked - Recently blocked IPs                              ║${NC}"
echo -e "${GREEN}║ /graph - Attack graph for today                              ║${NC}"
echo -e "${GREEN}║ /add_channel - Add current channel to monitoring             ║${NC}"
echo -e "${GREEN}║ /help - Show help message                                    ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"