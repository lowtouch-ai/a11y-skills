# AGENTS.md

## Project
orders-api is an Express service exposing order endpoints backed by PostgreSQL. See [README.md](README.md).

## Map
- Entry point: `src/server.js` (Express app and all routes).
- Layout and "where to change what": [docs/codebase-map.md](docs/codebase-map.md).
- Do not edit by hand: `node_modules/`, `package-lock.json` (use npm).

## Commands
Run from the repository root.

| Task | Command | Notes |
|---|---|---|
| Install | `npm ci` | Node >= 20 (from package.json, not run) |
| Run (dev) | `npm run dev` | needs PostgreSQL (`docker compose up -d db`); port 3000 |
| Test | `npm test` | Jest (from package.json, not run) |
| Lint | `npm run lint` | ESLint |

## Conventions
- CommonJS modules; source in `src/`, tests in `tests/`.
- Commit and PR rules: TBD (none found).

## Architecture rules
- All HTTP routes are registered in `src/server.js`; `src/orders.js` is not wired in yet.
Read [docs/architecture.md](docs/architecture.md) before changing component boundaries.

## Definition of done
1. `npm test` and `npm run lint` pass.
2. New behavior has a test in `tests/`.
3. Docs updated when required (see Documentation rules).

## Boundaries
- Safe without asking: read files, run tests and lint.
- Ask first: installing dependencies, changing CI or Docker files, running containers, touching `.env` files.
- Never: commit real credentials or edit generated files by hand.

## Documentation map
| Need | Read |
|---|---|
| Overview and setup | [README.md](README.md) |
| Where code lives | [docs/codebase-map.md](docs/codebase-map.md) |
| How it is built | [docs/architecture.md](docs/architecture.md) |
| Env vars | [docs/configuration.md](docs/configuration.md) |
| Run, test, CI | [docs/development-guide.md](docs/development-guide.md) |

## Documentation rules
Update the README and affected files under `docs/` when a change adds or rewires components, changes routes, commands, environment variables, versions, Docker or CI files. Run `<skill-dir>/scripts/validate_docs.py` afterwards. If you change a spec in `docs/diagrams/src/`, re-run `<skill-dir>/scripts/make_svg.py`.

## Gotchas
- `REDIS_URL` is read but nothing uses Redis; do not assume a cache exists.
- `POST /orders` returns 201 without persisting.
