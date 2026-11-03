# Codebase Map

> Where code lives in orders-api and where to make a given change. Read this before editing.

- **Status:** Verified against commit `0000000` on 2026-11-03
- **Legend:** Implemented = found in code · Planned = documented intent · TBD = unknown, needs an owner
- **Related:** [Architecture](architecture.md) · [Development guide](development-guide.md)

## Directory map

| Path | Role | Notes |
|---|---|---|
| [`src/server.js`](../src/server.js) | Entry point: Express app, routes, `pg` pool | Implemented. All routes live here. |
| [`src/orders.js`](../src/orders.js) | Orders module stub (`list`) | Not imported by the server yet. |
| [`tests/`](../tests/orders.test.js) | Jest tests | One file. |
| [`Dockerfile`](../Dockerfile), [`docker-compose.yml`](../docker-compose.yml) | Container image and local stack | Services: api, db, cache. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | CI | `npm ci` then `npm test`. |

## Where to change what

| To change | Edit | Also check |
|---|---|---|
| Add or change an endpoint | [`src/server.js`](../src/server.js) | [API table in README](../README.md#apis-and-interfaces) |
| Business logic for orders | [`src/orders.js`](../src/orders.js), then import it in `src/server.js` | [`tests/orders.test.js`](../tests/orders.test.js) |
| Environment variable | [`src/server.js`](../src/server.js), [`.env.example`](../.env.example) | [Configuration](configuration.md) |
| Ports or services | [`docker-compose.yml`](../docker-compose.yml), [`Dockerfile`](../Dockerfile) | [Architecture](architecture.md) |

## Conventions

- CommonJS modules (`require`), no TypeScript. Source in `src/`, tests in `tests/`.
- Lint with `npm run lint` (ESLint); no formatter configuration found.

## Do not edit by hand

- `package-lock.json` if present (use npm), `node_modules/`.

## Open questions (TBD)

- Intended structure once `orders.js` is wired in (routes vs services split).
