# Nonce

Open-source Authentication Backend-as-a-Service (Auth BaaS) in Go. Multi-tenant, Clean Architecture, PostgreSQL + sqlc, Chi, Argon2id, JWT RS256.

## Prerequisites

- Go 1.22+
- PostgreSQL 16+
- (Optional) [goose](https://github.com/pressly/goose) for migrations

## Setup

1. **Dependencies**

   ```bash
   go mod tidy
   ```

2. **Database**

   Create a database and run migrations:

   ```bash
   # Install goose: go install github.com/pressly/goose/v3/cmd/goose@latest
   goose -dir migrations postgres "postgres://postgres:postgres@localhost:5432/nonce?sslmode=disable" up
   ```

3. **JWT key**

   Generate an RSA private key for signing JWTs:

   ```bash
   ./scripts/gen-dev-jwt-key.sh
   # Or: openssl genrsa -out scripts/dev-jwt-private.pem 2048
   ```

4. **Run**

   Use the seeded dev project API key `dev-key` (see `migrations/00002_seed_dev_project.sql`).

   ```bash
   export JWT_PRIVATE_KEY_PATH=./scripts/dev-jwt-private.pem
   export DATABASE_URL="postgres://postgres:postgres@localhost:5432/nonce?sslmode=disable"
   go run ./cmd/nonce
   ```

   Then:

   - **Signup:** `POST /auth/signup` with header `X-Nonce-Project-Key: dev-key` and body `{"email":"u@example.com","password":"password123"}`
   - **Login:** `POST /auth/login` with same header and body
   - **Refresh:** `POST /auth/refresh` with body `{"refresh_token":"..."}`

## Docker

```bash
./scripts/gen-dev-jwt-key.sh   # create scripts/dev-jwt-private.pem
docker compose up --build
```

API at http://localhost:8080. Use `X-Nonce-Project-Key: dev-key` for the seeded project.

## Configuration

Env (or Viper config file):

- `PORT` – server port (default `8080`)
- `DATABASE_URL` – Postgres connection string
- `JWT_PRIVATE_KEY_PATH` – path to RSA private key PEM (required)
- `JWT_ISSUER`, `JWT_AUDIENCE` – optional JWT claims
- `JWT_ACCESS_EXPIRY`, `JWT_REFRESH_EXPIRY` – seconds (default 900, 604800)
- `ARGON2_MEMORY`, `ARGON2_ITERATIONS`, `ARGON2_PARALLELISM` – Argon2id params

## License

Apache 2.0 or MIT.
