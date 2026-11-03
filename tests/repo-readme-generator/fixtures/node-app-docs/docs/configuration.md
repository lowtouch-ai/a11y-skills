# Configuration

> Every environment variable and config file orders-api reads.

- **Status:** Verified against commit `0000000` on 2026-11-03
- **Legend:** Implemented = found in code · Planned = documented intent · TBD = unknown, needs an owner
- **Related:** [Development guide](development-guide.md)

## Environment variables

| Variable | Purpose | Required | Default | Read in | Example |
|---|---|---|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | Yes | none | [`src/server.js`](../src/server.js) | `postgres://user:pass@localhost:5432/orders` (placeholder) |
| `REDIS_URL` | Redis URL (read, not yet used) | No | none | [`src/server.js`](../src/server.js) | `redis://localhost:6379` |
| `PORT` | HTTP listen port | No | `3000` | [`src/server.js`](../src/server.js) | `3000` |

## Files

- [`.env.example`](../.env.example): template; copy to `.env`. Real values are never committed.
- [`docker-compose.yml`](../docker-compose.yml): service definitions and ports.

## Secrets

Credentials are supplied through `DATABASE_URL`. No secret manager integration found (TBD).

## Open questions (TBD)

- Per-environment configuration (staging, production).
