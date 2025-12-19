#!/bin/bash
#
# AutoConnectScript - Автоматическое подключение к существующему Caddy
# файл: /opt/astracat_guard/scripts/auto_connect_existing.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          AutoConnectScript для ASTRACAT_GUARD              ║${NC}"
echo -e "${BLUE}║      Подключение к уже запущенному Docker Caddy            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Проверка зависимостей
check_dependencies() {
    echo -e "${BLUE}Проверка зависимостей...${NC}"
    
    missing_deps=()
    
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if ! python3 -c "import docker" &> /dev/null; then
        missing_deps+=("docker python package")
    fi
    
    if ! python3 -c "import psutil" &> /dev/null; then
        missing_deps+=("psutil python package")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${RED}Отсутствующие зависимости:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo -e "${YELLOW}Установите зависимости:${NC}"
        echo "  pip install docker psutil netifaces netaddr"
        echo "  sudo apt-get install docker.io python3"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Все зависимости установлены${NC}"
}

# Поиск Caddy контейнера
find_caddy_container() {
    echo -e "${BLUE}Поиск запущенного Caddy контейнера...${NC}"
    
    # Пытаемся найти контейнер по имени или образу
    CADDY_CONTAINER=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}" | grep -i caddy | head -1 | awk '{print $1}')
    
    if [ -z "$CADDY_CONTAINER" ]; then
        # Если не найден по имени, пробуем найти по открытым портам
        echo -e "${YELLOW}Контейнер Caddy не найден по имени, пробуем найти по портам...${NC}"
        
        for container_id in $(docker ps -q); do
            ports=$(docker port "$container_id" 2>/dev/null || true)
            if echo "$ports" | grep -E "(80|443|2019)" &>/dev/null; then
                CADDY_CONTAINER=$container_id
                CADDY_NAME=$(docker ps --format "table {{.ID}}\t{{.Names}}" | grep "$CADDY_CONTAINER" | awk '{print $2}')
                echo -e "${GREEN}✓ Найден контейнер по портам: $CADDY_NAME${NC}"
                break
            fi
        done
    fi
    
    if [ -z "$CADDY_CONTAINER" ]; then
        echo -e "${RED}Не найден запущенный контейнер Caddy${NC}"
        echo -e "${YELLOW}Проверьте список контейнеров:${NC}"
        docker ps
        exit 1
    fi
    
    echo -e "${GREEN}✓ Найден Caddy контейнер: $CADDY_NAME (ID: ${CADDY_CONTAINER:0:12})${NC}"
}

# Создание специального лог-файла для мониторинга
setup_log_monitoring() {
    echo -e "${BLUE}Настройка мониторинга логов...${NC}"
    
    # Создаем директорию для логов
    mkdir -p /var/log/astracat_guard
    
    # Проверяем, можно ли получить логи контейнера
    if docker logs "$CADDY_CONTAINER" 2>/dev/null | head -5 &>/dev/null; then
        echo -e "${GREEN}✓ Доступ к логам контейнера подтвержден${NC}"
    else
        echo -e "${YELLOW}⚠ Нет прямого доступа к логам контейнера${NC}"
        echo -e "${BLUE}Пробуем альтернативный метод...${NC}"
    fi
}

# Запуск защиты существующего Caddy
start_protection() {
    echo -e "${BLUE}Запуск защиты для существующего Caddy...${NC}"
    
    # Запускаем Python скрипт защиты
    python3 /root/astracat_guard/lib/auto_protect_existing.py &
    
    PROTECT_PID=$!
    
    # Сохраняем PID для возможной остановки
    echo $PROTECT_PID > /tmp/astracat_protect_existing.pid
    
    echo -e "${GREEN}✓ Защита запущена (PID: $PROTECT_PID)${NC}"
    echo -e "${GREEN}✓ Caddy продолжает работать без изменений${NC}"
    echo -e "${GREEN}✓ Защита мониторит логи и защищает в реальном времени${NC}"
}

# Проверка статуса защиты
check_status() {
    if [ -f /tmp/astracat_protect_existing.pid ]; then
        PID=$(cat /tmp/astracat_protect_existing.pid)
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Защита активна (PID: $PID)${NC}"
            echo -e "${BLUE}Логи защиты: /var/log/astracat_guard_auto.log${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠ Защита не активна${NC}"
            rm -f /tmp/astracat_protect_existing.pid
        fi
    else
        echo -e "${YELLOW}⚠ Защита не запущена${NC}"
    fi
    return 1
}

# Остановка защиты
stop_protection() {
    if [ -f /tmp/astracat_protect_existing.pid ]; then
        PID=$(cat /tmp/astracat_protect_existing.pid)
        if ps -p $PID > /dev/null 2>&1; then
            kill $PID
            rm -f /tmp/astracat_protect_existing.pid
            echo -e "${GREEN}✓ Защита остановлена${NC}"
        else
            echo -e "${YELLOW}⚠ Процесс защиты не найден${NC}"
            rm -f /tmp/astracat_protect_existing.pid
        fi
    else
        echo -e "${YELLOW}ℹ Защита не была запущена${NC}"
    fi
}

# Вывод информации о Caddy
show_caddy_info() {
    echo -e "${BLUE}Информация о найденном Caddy контейнере:${NC}"
    echo "ID: ${CADDY_CONTAINER:0:12}"
    echo "Имя: $CADDY_NAME"
    echo "Порты:"
    docker port "$CADDY_CONTAINER"
    echo ""
    echo "Статус:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep "$CADDY_NAME"
}

# Основная логика
main() {
    case "${1:-start}" in
        start)
            check_dependencies
            find_caddy_container
            setup_log_monitoring
            show_caddy_info
            start_protection
            ;;
        status)
            check_status
            ;;
        stop)
            stop_protection
            ;;
        restart)
            stop_protection
            sleep 2
            main start
            ;;
        info)
            check_dependencies
            find_caddy_container
            show_caddy_info
            ;;
        *)
            echo "Использование: $0 {start|stop|restart|status|info}"
            echo "  start  - запустить защиту для существующего Caddy"
            echo "  stop   - остановить защиту"
            echo "  restart - перезапустить защиту"
            echo "  status - проверить статус защиты"
            echo "  info   - показать информацию о Caddy контейнере"
            exit 1
            ;;
    esac
}

# Выполнение основной функции
main "$@"