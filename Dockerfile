# Dockerfile для ASTRACAT_GUARD с поддержкой Caddy
# файл: /opt/astracat_guard/Dockerfile

FROM python:3.9-slim

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    dnsutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Установка Python пакетов
RUN pip install pyyaml psutil setproctitle

# Создание рабочей директории
WORKDIR /opt/astracat_guard

# Копирование файлов
COPY . .

# Установка прав
RUN chmod +x /opt/astracat_guard/bin/astracat-guard
RUN chmod +x /opt/astracat_guard/lib/*.py
RUN chmod +x /opt/astracat_guard/scripts/*.sh

# Настройка конфигурации по умолчанию
RUN cp /opt/astracat_guard/conf/caddy_integration.yaml /opt/astracat_guard/conf/config.yaml

# Создание директории для логов
RUN mkdir -p /var/log/astracat_guard
RUN touch /var/log/astracat_guard.log

# Экспорт необходимых портов (если нужно управлять сервисами)
EXPOSE 2019

# Установка entrypoint
ENTRYPOINT ["/opt/astracat_guard/docker_start.sh"]

CMD ["tail", "-f", "/dev/null"]