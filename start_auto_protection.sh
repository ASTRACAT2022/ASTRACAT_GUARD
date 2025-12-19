#!/bin/bash
#
# AutoCaddyGuardStarter - Главный скрипт запуска автоматической защиты
# файл: /opt/astracat_guard/start_auto_protection.sh

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              ASTRACAT_GUARD Auto Protection                 ║"
echo "║     Автоматическая защита уже запущенного Caddy в Docker    ║"
echo "║              Работает без остановки контейнера              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Проверка root прав
if [[ $EUID -eq 0 ]]; then
   echo "✓ Запущено с root правами"
else
   echo "Ошибка: Этот скрипт должен быть запущен с root правами (sudo)"
   exit 1
fi

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo "Ошибка: Docker не установлен или недоступен"
    exit 1
else
    echo "✓ Docker установлен"
fi

# Проверка Python и зависимостей
echo "Проверка Python зависимостей..."
MISSING_DEPS=()
for pkg in docker psutil netifaces netaddr; do
    if ! python3 -c "import $pkg" &> /dev/null; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Установите недостающие Python пакеты: pip install ${MISSING_DEPS[*]}"
    read -p "Установить автоматически? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip3 install "${MISSING_DEPS[@]}"
    else
        exit 1
    fi
fi

echo "✓ Python зависимости установлены"

# Поиск запущенного Caddy
echo "Поиск запущенного Caddy контейнера..."
CADDY_CONTAINER=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}" | grep -i caddy | head -1 | awk '{print $1}')

if [ -z "$CADDY_CONTAINER" ]; then
    # Поиск по портам
    for container_id in $(docker ps -q); do
        ports=$(docker port "$container_id" 2>/dev/null || true)
        if echo "$ports" | grep -E "(80|443|2019)" &>/dev/null; then
            CADDY_CONTAINER=$container_id
            CADDY_NAME=$(docker ps --format "table {{.ID}}\t{{.Names}}" | grep "$CADDY_CONTAINER" | awk '{print $2}')
            echo "Найден контейнер Caddy по портам: $CADDY_NAME"
            break
        fi
    done
fi

if [ -z "$CADDY_CONTAINER" ]; then
    echo "Ошибка: Не найден запущенный контейнер Caddy"
    echo "Проверьте запущенные контейнеры:"
    docker ps
    exit 1
fi

echo "✓ Найден контейнер: $CADDY_NAME (${CADDY_CONTAINER:0:12})"

# Проверка, работает ли защита
if [ -f /tmp/astracat_protect_existing.pid ]; then
    PID=$(cat /tmp/astracat_protect_existing.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo "⚠ Защита уже запущена (PID: $PID)"
        read -p "Остановить и перезапустить? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ./scripts/auto_connect_existing.sh stop
            sleep 2
        else
            exit 0
        fi
    fi
fi

echo "Запуск автоматической защиты..."

# Запуск защиты
if ./scripts/auto_connect_existing.sh start; then
    echo
    echo "🎉 УСПЕХ! 🎉"
    echo
    echo "ASTRACAT_GUARD автоматическая защита запущена для вашего Caddy!"
    echo
    echo "Что происходит:"
    echo "✓ Caddy продолжает работать без изменений"
    echo "✓ Защита анализирует логи в реальном времени" 
    echo "✓ Подозрительные IP автоматически блокируются"
    echo "✓ Защита адаптируется к вашему трафику"
    echo
    echo "Команды управления:"
    echo "  ./scripts/auto_connect_existing.sh status  # проверить статус"
    echo "  ./scripts/auto_connect_existing.sh stop    # остановить защиту"
    echo "  ./scripts/auto_connect_existing.sh info    # информация о Caddy"
    echo
    echo "Логи защиты: /var/log/astracat_guard_auto.log"
    echo
else
    echo "Ошибка запуска защиты"
    exit 1
fi