# AGENTS.md template

`AGENTS.md` is the first file a coding agent reads. Keep it short, exact and operational. Detail lives in `docs/`; link to it. Hard limit 32 KiB (Codex truncates beyond that); aim for about 150 lines. If an `AGENTS.md` already exists, preserve its content and add or update sections; never delete the owner's rules.

Every command must come from a manifest, script, Makefile, Dockerfile or CI file. Mark each as `(verified: run)` or `(from <file>, not run)`. Unknown steps: `TBD`.

```markdown
# AGENTS.md

## Project
<2 to 3 sentences: what the project does and its main technologies. Link to README.md.>

## Map
- Entry points: `<path>` (<what it starts>)
- Source layout: see [docs/codebase-map.md](docs/codebase-map.md). Key directories: `<dir>/` <role>, ...
- Do not edit by hand: `<generated/vendored/lock paths>`

## Commands
Run from the repository root unless noted.

| Task | Command | Notes |
|---|---|---|
| Install | `<cmd>` | <prereqs, e.g. Node >= 20> |
| Build | `<cmd>` | |
| Run (dev) | `<cmd>` | needs <services>; listens on <port> |
| Test (all) | `<cmd>` | |
| Test (one) | `<cmd for a single file or test>` | |
| Lint / format | `<cmd>` | |
| Type check | `<cmd>` | |

## Conventions
- Language/style rules enforced by tooling: <eslint/prettier/ruff/black/...> (config: `<file>`)
- Naming, layering and error-handling patterns visible in the code (with an example path each).
- Commit/PR rules: <from CONTRIBUTING or git history, else TBD>

## Architecture rules
- <boundary 1: e.g. "handlers call services; services never import handlers">
- <invariant: e.g. "votes are queued in Redis, only the worker writes to the database">
Read [docs/architecture.md](docs/architecture.md) before changing component boundaries.

## Definition of done
1. Code builds and the relevant tests pass (`<cmd>`).
2. New behavior has tests following `<test dir/pattern>`.
3. Lint/format clean.
4. Docs updated when required (see Documentation rules).

## Boundaries
- Safe without asking: read files, run tests and linters, build locally.
- Ask first: installing or upgrading dependencies, changing CI/CD or infra files, running migrations, touching secrets or `.env` files, deleting files, network calls to external services, force pushes.
- Never: commit secrets or real credentials, edit generated or vendored files by hand, disable tests or hooks to make a change pass.

## Documentation map
| Need | Read |
|---|---|
| Overview and setup | [README.md](README.md) |
| Where code lives | [docs/codebase-map.md](docs/codebase-map.md) |
| How it is built | [docs/architecture.md](docs/architecture.md) |
| Config and env vars | [docs/configuration.md](docs/configuration.md) |
| APIs | [docs/api-reference.md](docs/api-reference.md) |
| Data | [docs/data-model.md](docs/data-model.md) |
| Running and deploying | [docs/development-guide.md](docs/development-guide.md), [docs/deployment-and-operations.md](docs/deployment-and-operations.md) |
(only list files that exist)

## Documentation rules
<insert the block from agents-md-snippet.md>

## Gotchas
- <non-obvious facts that cause failures: ordering of services, required env, flaky tests, slow commands, platform quirks>. Each backed by a file or a documented issue.
```

Sections with nothing verified are omitted, not filled. Prefer a table row `TBD` over a guess.
