# MTProto Proxy — быстрый старт

## Требования
- Go 1.22+ (https://go.dev/dl/)
- Сервер с публичным IP (Linux/macOS)

## 1. Установить зависимости

```bash
go mod tidy
```

## 2. Сгенерировать секрет

### Fake-TLS (рекомендуется — трафик выглядит как HTTPS)
```bash
go run ./cmd/gen-secret \
  -faketls \
  -domain www.google.com \
  -host YOUR_SERVER_IP \
  -port 443
```

Пример вывода:
```
Secret type : fake-TLS (ee)
Domain      : www.google.com
Secret      : ee<32hex><hex_domain>

tg://proxy?server=1.2.3.4&port=443&secret=ee...

Add to config.yaml:
  secret: "ee..."
```

### Простой obfuscated2
```bash
go run ./cmd/gen-secret -host YOUR_SERVER_IP -port 443
```

## 3. Настроить config.yaml

```yaml
listen: "0.0.0.0:443"
secret: "ee<ваш секрет>"   # вставить из gen-secret
addr_family: "ipv4"
metrics:
  enabled: true
  listen: "0.0.0.0:9090"
log:
  level: "info"
  format: "json"
```

## 4. Запустить

```bash
# Собрать и запустить напрямую
make run

# Или через Docker
make docker
docker-compose up -d
```

## 5. Подключить в Telegram

Вставьте ссылку `tg://proxy?...` в браузер на устройстве с Telegram,
или в Telegram → Настройки → Данные и хранилище → Тип прокси → MTProto.

## Архитектура

```
Клиент Telegram
    │
    │  (fake-TLS или obfuscated2)
    ▼
[ Proxy — ваш сервер ]
    │  obfs.New() — AES-256-CTR, ключ = SHA256(nonce[8:40] + secret)
    │
    │  (plain TCP + protocol tag)
    ▼
[ Telegram DC 1–5 ]
    149.154.175.50:443 ... 91.108.56.130:443
```

## Метрики Prometheus

Endpoint: `http://YOUR_SERVER:9090/metrics`

| Метрика | Описание |
|---------|----------|
| `mtproxy_active_connections` | Активные соединения |
| `mtproxy_total_connections_total` | Всего принято |
| `mtproxy_rejected_connections_total` | Отклонено / ошибки |
| `mtproxy_bytes_from_clients_total` | Байт от клиентов |
| `mtproxy_bytes_from_dcs_total` | Байт от Telegram DC |
| `mtproxy_handshake_errors_total{reason}` | Ошибки хэндшейка по причинам |
| `mtproxy_connections_by_dc_total{dc}` | Соединения по DC |

## Безопасность

- **Fake-TLS** (`ee` префикс): трафик неотличим от HTTPS на SNI уровне
- **HMAC защита**: каждый ClientHello содержит HMAC-SHA256 дайджест — replay-атаки невозможны
- **Временно́е окно**: timestamp в ClientHello проверяется (±1 час)
- **Минимальный Docker образ**: `scratch` base, только статический бинарь, `--read-only`, `no-new-privileges`
- **AES-256-CTR**: ключи производятся через SHA256(key_material + secret), уникальны для каждой сессии
