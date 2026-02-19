# Ecliptix Server Management

## ✅ Сервер запущений і працює!

Сервер Ecliptix зараз запущений та готовий до підключень:
- **URL:** `http://localhost:5051`
- **PID:** `26930`
- **Логи:** `/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/logs/server.log`

## 🛠️ Керування сервером

Використовуйте скрипт `manage-server.sh` для керування сервером:

```bash
cd /Users/oleksandrmelnychenko/RiderProjects/Ecliptix

# Перевірити статус
./manage-server.sh status

# Переглянути логи в реальному часі
./manage-server.sh logs

# Зупинити сервер
./manage-server.sh stop

# Запустити сервер
./manage-server.sh start

# Перезапустити сервер
./manage-server.sh restart
```

## 📱 Підключення десктоп додатку

Десктоп додаток автоматично підключається до `http://127.0.0.1:5051`

Запустити десктоп:
```bash
cd /Users/oleksandrmelnychenko/RiderProjects/ecliptix-desktop
dotnet run --project Ecliptix.Core/Ecliptix.Core.Desktop/Ecliptix.Core.Desktop.csproj
```

## 🔍 Перевірка роботи

```bash
# Перевірити, чи порт слухає
lsof -i :5051 -P -n | grep LISTEN

# Переглянути останні логи
tail -50 /Users/oleksandrmelnychenko/RiderProjects/Ecliptix/logs/server.log

# Перевірити процес
ps aux | grep "dotnet.*Ecliptix.Core"
```

## 🐳 Docker (в процесі налаштування)

Docker збірка має проблеми з ARM64 архітектурою (grpc-tools compatibility).
Для продакшн використання рекомендується:
1. Збирати на linux/amd64 платформі
2. Використовувати CI/CD для збірки образів

## 📝 Примітки

- Сервер працює в Development режимі
- База даних: PostgreSQL (налаштування в `appsettings.Development.Local.json`)
- Використовує OPAQUE протокол для аутентифікації
- End-to-end шифрування для всіх повідомлень
- Health check endpoint: `/health` (HTTP/2 only)

## 🔐 OTP коди

Під час входу в десктоп додаток, OTP коди виводяться в логи сервера:
```bash
./manage-server.sh logs | grep "Generated OTP"
```

---
**Автоматично запущено:** 2026-02-16 14:05:34
