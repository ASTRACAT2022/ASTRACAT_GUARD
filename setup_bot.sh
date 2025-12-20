#!/bin/bash
#
# ASTRACAT_GUARD Telegram Bot Quick Setup
# Быстрая настройка бота с токеном

if [ $# -eq 0 ]; then
    echo "Usage: $0 <telegram_bot_token>"
    echo "Example: $0 123456789:ABCdefGhIjKLMnoPQRstUvWxYz"
    exit 1
fi

TOKEN=$1

# Check if token format looks valid (basic check)
if [[ ! "$TOKEN" =~ ^[0-9]+:[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Invalid bot token format"
    exit 1
fi

# Create a temporary override file
sudo mkdir -p /etc/systemd/system/astracat-guard-bot.service.d
cat > /tmp/override.conf << EOF
[Service]
Environment=TELEGRAM_BOT_TOKEN=$TOKEN
EOF

sudo mv /tmp/override.conf /etc/systemd/system/astracat-guard-bot.service.d/override.conf

# Reload systemd and restart the bot
sudo systemctl daemon-reload
sudo systemctl restart astracat-guard-bot

echo "✅ Telegram bot configured and restarted!"
echo "📝 Bot token has been set in the service configuration"
echo "🚀 Bot should be running. Check status with: sudo systemctl status astracat-guard-bot"
echo ""
echo "🤖 To start using the bot:"
echo "1. Search for your bot in Telegram (@botusername)"
echo "2. Send /start to initialize"
echo "3. Send /help to see all available commands"
echo ""
echo "📊 The bot will automatically monitor ASTRACAT_GUARD statistics and can be added to channels"