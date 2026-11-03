# Development Guide

> Set up, run, test and ship a change to orders-api.

- **Status:** Verified against commit `0000000` on 2026-11-03
- **Legend:** Implemented = found in code · Planned = documented intent · TBD = unknown, needs an owner
- **Related:** [Configuration](configuration.md) · [Architecture](architecture.md)

## Prerequisites

- Node.js 20 or newer (`engines` in [`package.json`](../package.json)).
- Docker and Docker Compose for PostgreSQL and Redis.

## Setup and run

Commands are taken from `package.json` and `docker-compose.yml`; they were not executed while writing this guide.

```bash
npm ci
cp .env.example .env
docker compose up -d db cache
npm run dev
```

## Test and lint

```bash
npm test
npm run lint
```

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs `npm ci` and `npm test` on push.

## Conventions

No contribution guide, branching rules or commit convention found (TBD).

## Open questions (TBD)

- Release process; database migration workflow.
