# Dogma VPN Ruleset

Веб-сервис поиска связанных доменов и формирования JSON ruleset для sing-box.

## Что Реализовано

- Backend на FastAPI.
- JWT Bearer авторизация.
- Роли `admin` и `user`.
- Управление пользователями для администратора.
- `must_change_password`.
- Argon2id-хеширование паролей.
- Глобальная парольная политика.
- API запуска анализа домена со статусами.
- Перенесенная логика `prefix_finder`: v2fly/domain-list-community и browser traffic через Playwright.
- Нормализация, дедупликация и фильтрация доменов.
- Генерация sing-box ruleset `version: 3` с `domain_suffix`.
- Скачивание JSON-файла.
- Frontend на React/Vite.

## Локальный Запуск Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

На сервере без Docker можно запустить один процесс, который отдает и API, и собранный frontend:

```bash
PORT=8090 ./scripts/start-server.sh
```

По умолчанию используется SQLite-файл `dogma_vpn.db`.

Первый администратор создается автоматически:

```text
login: admin
password: admin12345A!
```

Перед реальным использованием задайте свой `SECRET_KEY` и `BOOTSTRAP_ADMIN_PASSWORD` через `.env`.

## Локальный Запуск Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend ожидает API по адресу `http://localhost:8000/api`.

Если нужен другой адрес:

```bash
VITE_API_BASE=http://localhost:8000/api npm run dev
```

## Playwright / Browser Discovery

Для browser traffic discovery нужен установленный browser для Playwright.

```bash
cd backend
playwright install chromium
```

Если browser discovery недоступен, сервис продолжит работать через v2fly-источник.

Отключить browser discovery можно через env:

```text
ENABLE_BROWSER_DISCOVERY=false
```

## Основные API

```text
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
POST /api/auth/change-password

POST /api/domain/scan
GET  /api/domain/scans/{scan_id}

GET /api/ruleset/{scan_id}
POST /api/domain-json-export
GET  /api/dashboard
GET  /api/domains/catalog
PUT  /api/domains/selection
GET  /api/domains/ruleset
GET  /api/domains/ruleset/download
GET  /api/public/ruleset/{token}.json
GET  /api/logs

GET   /api/admin/users
POST  /api/admin/users
GET   /api/admin/users/{user_id}
PATCH /api/admin/users/{user_id}
POST  /api/admin/users/{user_id}/password

GET /api/admin/password-policy
PUT /api/admin/password-policy
```

OpenAPI доступен по адресу:

```text
http://localhost:8000/docs
```

## Формат Ruleset

```json
{
  "version": 3,
  "rules": [
    {
      "domain_suffix": [
        "googlevideo.com",
        "youtube.com",
        "ytimg.com"
      ]
    }
  ]
}
```

## Тесты

```bash
cd backend
pytest
```

## Конфигурация

См. `.env.example`.

## Прием Domain JSON Export

Endpoint принимающего сервера:

```text
POST /api/domain-json-export
```

Текущий URL сервиса:

```text
http://10.147.0.4:8090/api/domain-json-export
```

Bearer token задается через `DOMAIN_JSON_EXPORT_TOKEN` в `.env`.

Файл сохраняется сюда:

```text
/home/opencode/dogma_vpn/exports/domains-export.json
```

Успешный ответ: `204 No Content`.

## Домены И Пользовательский Ruleset

Вкладка `Домены` строится из файла `/home/opencode/dogma_vpn/exports/domains-export.json`.

Пользователь выбирает группы и сервисы переключателями, затем нажимает `Сохранить`. После сохранения backend формирует персональный JSON для sing-box и публичную ссылку вида:

```text
http://<host>:8090/api/public/ruleset/<token>.json
```

Пользователь также может создавать custom-сервисы, добавлять в них домены и удалять свои custom-данные.

В custom-сервисы можно добавлять:

```text
Домен
IP CIDR
```

CIDR принимается только в формате `ip/netmask`, например `8.8.8.8/32`. Локальные и служебные диапазоны запрещены.

После нажатия `Сохранить` итоговый sing-box JSON записывается атомарно в основной файл:

```text
/var/www/files/data.json
```

Также создается архивная копия:

```text
/var/www/files/YYYY-MM-DD-HH-MM-SS-data.json
```

Файл для sing-box через nginx должен быть доступен по адресу:

```text
http://<server-ip>/files/data.json
```

Вкладка `Логи` показывает пользователю его действия. Администратор видит действия всех пользователей, включая действия администраторов.

## Docker Развертывание

Проект можно собрать и запустить через Docker:

```bash
docker compose up -d --build
```

Контейнер слушает порт `8090`.

Volume с готовыми файлами:

```text
./data/files:/var/www/files
```

Для полной установки на Ubuntu-сервере с настройкой nginx:

```bash
sudo ./scripts/install-server.sh
```

Скрипт:

- установит Docker и nginx;
- скопирует проект в `/opt/dogma-vpn`;
- запустит `docker compose up -d --build`;
- настроит nginx;
- сделает доступным файл `http://<server-ip>/files/data.json`.
