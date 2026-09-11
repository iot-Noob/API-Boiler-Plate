# API Boilerplate

This project is a FastAPI-based backend starter with async SQLAlchemy, JWT authentication, Redis-backed refresh token tracking, admin authorization, and cookie-based login support.

It includes:
- User login and signup flows
- JWT access + refresh tokens
- Redis-based refresh token storage and family tracking
- Cookie auth via CSO and refresh_token cookies
- Admin bootstrap and permission checks
- CORS, rate limiting, and maintenance kill-switch support

## Requirements

- Python 3.10+
- PostgreSQL instance
- Redis instance
- Virtual environment recommended

## Local project setup

```bash
cd /mnt/talha_linux/talha/Documents/DEv/Python/API-Boiler-Plate
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the environment is managed with uv, this project also supports the installed dependencies in the workspace environment already.

## Environment configuration

Create a `.env` file in the project root with the following values:

```env
# SECURITY
SECRET_KEY=73ea8bd4bbcfb26cb44bea2bc2042d05
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=790

# POSTGRESQL
DATABASE_HOST=127.0.0.1
DATABASE_PORT=5433
DATABASE_USER=Talha
DATABASE_PASSWORD=Talha6295
DATABASE_NAME=testdb
DATABASE_SCHEMA=public
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20
DATABASE_POOL_RECYCLE=3600
DATABASE_POOL_TIMEOUT=30
DATABASE_ECHO=false
DATABASE_CONNECT_TIMEOUT=10
ASYNC_MODE=true

# REDIS
REDIS_URL=redis://192.168.1.10:6379/0

# LOGGING
LOG_FILEPATH=./logs/

# RATE LIMITING
RATE_LIMIT_DEFAULT=10

# MAINTENANCE
KILL_SWITCH_ENABLED=false

# ARGON2
MEMORY_COST=65536
PARALLELISM=2
HASH_LENGTH=32
SALT_LENGTH=16

# ADMIN
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin@123

# APP
ENVIRONMENT=development
ALLOWED_ORIGINS=*
COOKIE_SECURE=false
HTTPS_ONLY=true
```

### Important notes

- `SECRET_KEY` is used for JWT signing.
- `REDIS_URL` must point to a valid Redis instance for refresh token tracking.
- `COOKIE_SECURE=false` is intended for local development. Set to true in production behind HTTPS.
- `HTTPS_ONLY=true` is used for cookie behavior in local dev and should be adjusted for production.
- The project loads environment variables through `App/core/settings.py` using `pydantic-settings`.

## Database setup

This project uses async SQLAlchemy with PostgreSQL. The database URL is generated in `App/core/settings.py` from the env values.

If you need to initialize the database schema, run the migrations or create the required tables according to your local setup.

## Redis

Redis is required for:
- refresh token storage
- family-based refresh token tracking
- refresh reuse detection
- cookie-session token validation metadata

The app expects Redis at:

```text
redis://192.168.100.9:6379/0
```

## Start the app

Run the API on port 2026:

```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 2026
```

Then open:

- Swagger UI: http://localhost:2026/docs
- OpenAPI: http://localhost:2026/openapi.json
- QA report: http://localhost:2026/

## Default admin account

The app auto-creates or promotes the admin account at startup via `App/core/CreateAdmin.py`.

Default values:

```text
username: admin
email: admin@example.com
password: Admin@123
```

Important: for this project, admin login is performed using the username field, not the email address.

Example:

```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

## Default user account used for QA

The project was validated with:

```text
username: talha
password: Talha@6295
```

## API routes

### Auth

- `POST /app/v1/auth/basic_auth/login`
  - Body: `username`, `password`
  - Can return JWT tokens or set cookies when `cookie_login=true`

- `POST /app/v1/auth/basic_auth/signup`
  - Creates a user account

### User routes

- `GET /app/v1/users/users_config/me`
  - Reads the currently authenticated user

- `POST /app/v1/users/users_config/refresh`
  - Rotates the refresh token and returns a new access token

### Admin routes

- `GET /app/v1/admin/admin_access/users`
  - Admin-only user listing

- `POST /app/v1/admin/admin_access/account/disable/{user_id}`
- `POST /app/v1/admin/admin_access/account/enable/{user_id}`
- `POST /app/v1/admin/admin_access/account/restore/{user_id}`
- `POST /app/v1/admin/admin_access/account/temp_token/{user_id}`
- `PUT /app/v1/admin/admin_access/account/password/{user_id}`
- `DELETE /app/v1/admin/admin_access/account/{user_id}`

## Cookie-based login behavior

When calling the login endpoint with cookie mode enabled, the app sets:

- `CSO` cookie with the access token
- `refresh_token` cookie with the refresh token

These are managed through the Redis-based refresh token store.

## Example requests

### User login

```bash
curl -X POST http://localhost:2026/app/v1/auth/basic_auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"talha","password":"Talha@6295"}'
```

### Admin login

```bash
curl -X POST http://localhost:2026/app/v1/auth/basic_auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123"}'
```

### Cookie login

```bash
curl -X POST 'http://localhost:2026/app/v1/auth/basic_auth/login?cookie_login=true' \
  -H 'Content-Type: application/json' \
  -d '{"username":"talha","password":"Talha@6295"}'
```

### Fetch profile with token

```bash
curl http://localhost:2026/app/v1/users/users_config/me \
  -H 'Authorization: Bearer <access_token>'
```

## Notes

- The app loads admin creation in the application lifespan hook.
- Redis must be active or refresh/login features will fail.
- The service is currently configured for local development; use secure settings in production.
- This README reflects the current environment and tested setup for this repository.


## Running Locally

```bash
uvicorn main:app --reload
```

## Logging

Logs are written to the directory configured by `LOG_FILEPATH` in `.env`.

## Security

- Argon2 is used for password hashing.
- JWT tokens secure authentication.
- Rate limiting and a kill-switch middleware are included.

## Notes

- Replace placeholder values in `.env` with your real configuration.
- Ensure PostgreSQL is running and migrations are applied before starting the app.
- The admin and user routes are mounted under `/app/v1`.

---

Private project: `iotNoob` by Talha.
# API Boilerplate

This project is a FastAPI-based backend starter with async SQLAlchemy, JWT authentication, Redis-backed refresh token tracking, admin authorization, and cookie-based login support.

It includes:
- User login and signup flows
- JWT access + refresh tokens
- Redis-based refresh token storage and family tracking
- Cookie auth via CSO and refresh_token cookies
- Admin bootstrap and permission checks
- CORS, rate limiting, and maintenance kill-switch support

## Requirements

- Python 3.10+
- PostgreSQL instance
- Redis instance
- Virtual environment recommended

## Local project setup

```bash
cd /mnt/talha_linux/talha/Documents/DEv/Python/API-Boiler-Plate
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the environment is managed with uv, this project also supports the installed dependencies in the workspace environment already.

## Environment configuration

Create a `.env` file in the project root with the following values:

```env
# SECURITY
SECRET_KEY=73ea8bd4bbcfb26cb44bea2bc2042d05
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=790

# POSTGRESQL
DATABASE_HOST=127.0.0.1
DATABASE_PORT=5433
DATABASE_USER=Talha
DATABASE_PASSWORD=Talha6295
DATABASE_NAME=testdb
DATABASE_SCHEMA=public
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20
DATABASE_POOL_RECYCLE=3600
DATABASE_POOL_TIMEOUT=30
DATABASE_ECHO=false
DATABASE_CONNECT_TIMEOUT=10
ASYNC_MODE=true

# REDIS
REDIS_URL=redis://192.168.100.9:6379/0

# LOGGING
LOG_FILEPATH=./logs/

# RATE LIMITING
RATE_LIMIT_DEFAULT=10

# MAINTENANCE
KILL_SWITCH_ENABLED=false

# ARGON2
MEMORY_COST=65536
PARALLELISM=2
HASH_LENGTH=32
SALT_LENGTH=16

# ADMIN
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin@123

# APP
ENVIRONMENT=development
ALLOWED_ORIGINS=*
COOKIE_SECURE=false
HTTPS_ONLY=true
```

### Important notes

- `SECRET_KEY` is used for JWT signing.
- `REDIS_URL` must point to a valid Redis instance for refresh token tracking.
- `COOKIE_SECURE=false` is intended for local development. Set to true in production behind HTTPS.
- `HTTPS_ONLY=true` is used for cookie behavior in local dev and should be adjusted for production.
- The project loads environment variables through `App/core/settings.py` using `pydantic-settings`.

## Database setup

This project uses async SQLAlchemy with PostgreSQL. The database URL is generated in `App/core/settings.py` from the env values.

If you need to initialize the database schema, run the migrations or create the required tables according to your local setup.

## Redis

Redis is required for:
- refresh token storage
- family-based refresh token tracking
- refresh reuse detection
- cookie-session token validation metadata

The app expects Redis at:

```text
redis://192.168.100.9:6379/0
```

## Start the app

Run the API on port 2026:

```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 2026
```

Then open:

- Swagger UI: http://localhost:2026/docs
- OpenAPI: http://localhost:2026/openapi.json
- QA report: http://localhost:2026/

## Default admin account

The app auto-creates or promotes the admin account at startup via `App/core/CreateAdmin.py`.

Default values:

```text
username: admin
email: admin@example.com
password: Admin@123
```

Important: for this project, admin login is performed using the username field, not the email address.

Example:

```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

## Default user account used for QA

The project was validated with:

```text
username: talha
password: Talha@6295
```

## API routes

### Auth

- `POST /app/v1/auth/basic_auth/login`
  - Body: `username`, `password`
  - Can return JWT tokens or set cookies when `cookie_login=true`

- `POST /app/v1/auth/basic_auth/signup`
  - Creates a user account

### User routes

- `GET /app/v1/users/users_config/me`
  - Reads the currently authenticated user

- `POST /app/v1/users/users_config/refresh`
  - Rotates the refresh token and returns a new access token

### Admin routes

- `GET /app/v1/admin/admin_access/users`
  - Admin-only user listing

- `POST /app/v1/admin/admin_access/account/disable/{user_id}`
- `POST /app/v1/admin/admin_access/account/enable/{user_id}`
- `POST /app/v1/admin/admin_access/account/restore/{user_id}`
- `POST /app/v1/admin/admin_access/account/temp_token/{user_id}`
- `PUT /app/v1/admin/admin_access/account/password/{user_id}`
- `DELETE /app/v1/admin/admin_access/account/{user_id}`

## Cookie-based login behavior

When calling the login endpoint with cookie mode enabled, the app sets:

- `CSO` cookie with the access token
- `refresh_token` cookie with the refresh token

These are managed through the Redis-based refresh token store.

## Example requests

### User login

```bash
curl -X POST http://localhost:2026/app/v1/auth/basic_auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"talha","password":"Talha@6295"}'
```

### Admin login

```bash
curl -X POST http://localhost:2026/app/v1/auth/basic_auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123"}'
```

### Cookie login

```bash
curl -X POST 'http://localhost:2026/app/v1/auth/basic_auth/login?cookie_login=true' \
  -H 'Content-Type: application/json' \
  -d '{"username":"talha","password":"Talha@6295"}'
```

### Fetch profile with token

```bash
curl http://localhost:2026/app/v1/users/users_config/me \
  -H 'Authorization: Bearer <access_token>'
```

## Notes

- The app loads admin creation in the application lifespan hook.
- Redis must be active or refresh/login features will fail.
- The service is currently configured for local development; use secure settings in production.
- This README reflects the current environment and tested setup for this repository.


## Running Locally

```bash
uvicorn main:app --reload
```

## Logging

Logs are written to the directory configured by `LOG_FILEPATH` in `.env`.

## Security

- Argon2 is used for password hashing.
- JWT tokens secure authentication.
- Rate limiting and a kill-switch middleware are included.

## Notes

- Replace placeholder values in `.env` with your real configuration.
- Ensure PostgreSQL is running and migrations are applied before starting the app.
- The admin and user routes are mounted under `/app/v1`.

---

Private project: `iotNoob` by Talha.
