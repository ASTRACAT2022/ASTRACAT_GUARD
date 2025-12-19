# Интеграция ASTRACAT_GUARD с Caddy в Docker

## Обзор

Этот документ описывает, как интегрировать ASTRACAT_GUARD с Caddy в Docker-среде для комплексной защиты от DDoS атак и других угроз.

## Архитектура интеграции

```
Интернет -> Caddy (reverse proxy) -> ASTRACAT_GUARD -> Ваши приложения
```

## Установка и настройка

### Шаг 1: Подготовка файлов

Скопируйте все файлы ASTRACAT_GUARD в ваш Docker проект:

```bash
# Уже созданы следующие файлы:
- Dockerfile
- docker-compose.yml  
- Caddyfile_example
- conf/caddy_integration.yaml
- scripts/caddy_setup.sh
```

### Шаг 2: Настройка Caddy

1. Скопируйте `Caddyfile_example` как `Caddyfile`
2. Отредактируйте под свои домены и пути:

```bash
cp Caddyfile_example Caddyfile
nano Caddyfile
```

3. Обязательно настройте логирование в формате JSON:
```caddy
log {
    output file /var/log/caddy/access.log
    format json {
        # ... формат лога как в примере
    }
}
```

4. Убедитесь, что передаются заголовки для реального IP:
```caddy
reverse_proxy localhost:3000 {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
}
```

### Шаг 3: Настройка docker-compose

1. Отредактируйте `docker-compose.yml` под свои нужды
2. Обязательно включите нужные capabilities:

```yaml
astracat-guard:
  # ...
  cap_add:
    - NET_ADMIN  # Необходимо для iptables
    - NET_RAW    # Необходимо для сетевых операций
  # ВАЖНО: используйте network_mode: host если нужен полный контроль над iptables
  network_mode: host
```

### Шаг 4: Запуск системы

```bash
# Сборка и запуск
docker-compose up -d --build

# Проверка статуса
docker-compose ps
```

## Настройка для разных сценариев

### Сценарий 1: Caddy и ASTRACAT_GUARD в одном контейнере

Если вы хотите запускать оба сервиса в одном контейнере:

```dockerfile
FROM caddy:2-alpine

# Установка зависимостей ASTRACAT_GUARD
RUN apk add --no-cache python3 py3-pip iptables net-tools
RUN pip3 install pyyaml psutil setproctitle

# Копирование ASTRACAT_GUARD
COPY . /opt/astracat_guard

# Установка прав
RUN chmod +x /opt/astracat_guard/bin/astracat-guard
RUN chmod +x /opt/astracat_guard/lib/*.py

# Копирование конфигурации
RUN cp /opt/astracat_guard/conf/caddy_integration.yaml /opt/astracat_guard/conf/config.yaml

# Кастомный entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

### Сценарий 2: Отдельные контейнеры с общим логированием

Используйте volume для общего доступа к логам:

```yaml
volumes:
  caddy_logs:
  
services:
  caddy:
    volumes:
      - caddy_logs:/var/log/caddy
  
  astracat-guard:
    volumes:
      - caddy_logs:/var/log/caddy:ro  # Только для чтения
```

## Проверка работоспособности

### Проверка логов ASTRACAT_GUARD:

```bash
# Проверить логи защиты
docker-compose logs astracat-guard

# Или через CLI
docker-compose exec astracat-guard astracat-guard stats
```

### Проверка защиты:

```bash
# Посмотреть статистику
docker-compose exec astracat-guard astracat-guard stats

# Посмотреть статус сервиса
docker-compose exec astracat-guard astracat-guard status

# Добавить IP в белый список
docker-compose exec astracat-guard astracat-guard whitelist add YOUR_IP
```

## Расширенные настройки

### Настройка чувствительности защиты

Отредактируйте `conf/caddy_integration.yaml`:

```yaml
protection:
  rate_limit:
    threshold: 150  # Повысьте для высоконагруженных сайтов
    window_size: 60
  http_flood:
    max_requests_per_second: 20  # Увеличьте при необходимости
```

### Настройка белого списка для доверенных подсетей

```yaml
whitelist:
  ips:
    - "127.0.0.1"
    - "::1" 
    - "YOUR_TRUSTED_IP"
    - "YOUR_PROXY_IP_RANGE/24"
```

## Устранение неполадок

### Проблема: ASTRACAT_GUARD не блокирует IP

**Решение**: Проверьте capabilities и network mode:

```bash
# Должно быть
cap_add:
  - NET_ADMIN
# Или
network_mode: host
```

### Проблема: Caddy не передает реальные IP

**Решение**: Проверьте заголовки в Caddyfile:

```caddy
reverse_proxy backend:3000 {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
}
```

### Проблема: Высокое потребление ресурсов

**Решение**: Оптимизируйте настройки в конфиге:

```yaml
protection:
  rate_limit:
    threshold: 200  # Повысьте порог
  connection_limit:
    max_connections_per_ip: 30  # Увеличьте лимит
```

## Безопасность

### Рекомендации:

1. Не запускайте ASTRACAT_GUARD с `privileged: true` если не требуется
2. Используйте network_mode: host только если обязательно нужно управлять iptables
3. Ограничьте доступ к Caddy admin API
4. Регулярно обновляйте конфигурации и правила

## Мониторинг

### Сбор метрик:

```bash
# Проверка статуса защиты
docker-compose exec astracat-guard astracat-guard stats

# Проверка логов на подозрительную активность
docker-compose exec astracat-guard tail -f /var/log/astracat_guard.log
```

## Обновление

Для обновления системы:

```bash
# Остановите сервисы
docker-compose down

# Обновите конфигурации
git pull  # или скопируйте новые файлы

# Пересоберите образы
docker-compose build

# Запустите снова
docker-compose up -d
```

Теперь ваша система будет защищена ASTRACAT_GUARD при использовании Caddy в Docker-окружении!