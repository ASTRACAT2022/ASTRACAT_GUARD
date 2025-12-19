#!/bin/bash
#
# Скрипт интеграции ASTRACAT_GUARD с Caddy в Docker-среде
# файл: /opt/astracat_guard/scripts/caddy_setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}┌─────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│    ASTRACAT_GUARD + CADDY Integration   │${NC}"
echo -e "${BLUE}│           Setup Script                  │${NC}"
echo -e "${BLUE}└─────────────────────────────────────────┘${NC}"

# Проверка, запущен ли скрипт в Docker
check_docker_env() {
    if [ -f /.dockerenv ]; then
        echo -e "${GREEN}✓ Running inside Docker container${NC}"
        IS_DOCKER=true
    else
        echo -e "${YELLOW}⚠ Running outside Docker environment${NC}"
        IS_DOCKER=false
    fi
}

# Настройка специфичных для Docker параметров
setup_docker_specifics() {
    echo -e "${BLUE}Configuring Docker-specific settings...${NC}"
    
    # Создание директории для логов в Docker
    mkdir -p /var/log/astracat_guard
    touch /var/log/astracat_guard.log
    
    # Если используется Docker, настраиваем специфичные параметры
    if [ "$IS_DOCKER" = true ]; then
        # Копируем специфичную конфигурацию
        cp /opt/astracat_guard/conf/caddy_integration.yaml /opt/astracat_guard/conf/config.yaml
        
        echo -e "${GREEN}✓ Docker-specific configuration applied${NC}"
    fi
}

# Настройка Caddy для работы с ASTRACAT_GUARD
setup_caddy_config() {
    echo -e "${BLUE}Setting up Caddy integration...${NC}"
    
    # Пример конфигурации Caddy, если используется Caddy API
    cat > /opt/astracat_guard/caddy_example_config.txt << 'EOF'
{
    "admin": {
        "listen": "localhost:2019"
    }
}

localhost:80 {
    # Логирование для ASTRACAT_GUARD
    log {
        output file /var/log/caddy/access.log {
            roll_size 10MB
            roll_keep 3
        }
    }
    
    # Защита от быстрого повторения запросов
    @flood {
        expression `{http.request.headers.Referer}[0]`
    }
    
    # Обычный reverse proxy к вашему приложению
    reverse_proxy localhost:3000 {
        # Установка заголовков для правильного определения IP
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
    
    # Для чувствительных путей можно добавить дополнительные проверки
    route /admin* {
        # Дополнительные ограничения для админ-панели
        @sensitive {
            remote_ip 0.0.0.0/0
        }
        # Здесь ASTRACAT_GUARD будет применять свои правила
        reverse_proxy localhost:3001
    }
}
EOF

    echo -e "${GREEN}✓ Caddy example configuration created${NC}"
}

# Настройка прав доступа в Docker
setup_permissions() {
    echo -e "${BLUE}Setting up file permissions...${NC}"
    
    # Установка прав для работы в Docker
    chown -R root:root /opt/astracat_guard/
    chmod -R 644 /opt/astracat_guard/conf/
    chmod 755 /opt/astracat_guard/bin/
    chmod 755 /opt/astracat_guard/lib/
    chmod 755 /opt/astracat_guard/scripts/
    
    # Разрешение на запись в логи для Docker
    touch /var/log/astracat_guard.log
    chmod 666 /var/log/astracat_guard.log
    
    echo -e "${GREEN}✓ File permissions configured${NC}"
}

# Создание Docker-специфичного старта
create_docker_entrypoint() {
    echo -e "${BLUE}Creating Docker entrypoint...${NC}"
    
    cat > /opt/astracat_guard/docker_start.sh << 'EOF'
#!/bin/bash
# Docker entrypoint для ASTRACAT_GUARD

# Инициализация
echo "Initializing ASTRACAT_GUARD for Docker..."

# Запуск ASTRACAT_GUARD в фоне
python3 /opt/astracat_guard/lib/optimized_guard_daemon.py &

# Если переданы аргументы, выполнить их
if [ $# -gt 0 ]; then
    exec "$@"
else
    # По умолчанию - держим контейнер запущенным
    tail -f /dev/null
fi
EOF

    chmod +x /opt/astracat_guard/docker_start.sh
    
    echo -e "${GREEN}✓ Docker entrypoint created${NC}"
}

# Инструкции по интеграции
print_integration_notes() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    INTEGRATION NOTES                         ║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║ For Caddy + ASTRACAT_GUARD integration:                     ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║ 1. Ensure Caddy logs to /var/log/caddy/access.log           ║${NC}"
    echo -e "${BLUE}║ 2. Configure Caddy to pass real IP headers:                 ║${NC}"
    echo -e "${BLUE}║    - X-Real-IP                                               ║${NC}"
    echo -e "${BLUE}║    - X-Forwarded-For                                         ║${NC}"
    echo -e "${BLUE}║ 3. Mount logs directory if running in separate containers   ║${NC}"
    echo -e "${BLUE}║ 4. Use the caddy_integration.yaml config                    ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║ Example Caddyfile additions for security:                   ║${NC}"
    echo -e "${BLUE}║   log {                                                     ║${NC}"
    echo -e "${BLUE}║     output file /var/log/caddy/access.log                   ║${NC}"
    echo -e "${BLUE}║   }                                                         ║${NC}"
    echo -e "${BLUE}║   reverse_proxy localhost:YOUR_APP_PORT {                  ║${NC}"
    echo -e "${BLUE}║     header_up X-Real-IP {remote_host}                       ║${NC}"
    echo -e "${BLUE}║     header_up X-Forwarded-For {remote_host}                 ║${NC}"
    echo -e "${BLUE}║   }                                                         ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Основная функция
main() {
    check_docker_env
    setup_docker_specifics
    setup_caddy_config
    setup_permissions
    create_docker_entrypoint
    print_integration_notes
}

main "$@"