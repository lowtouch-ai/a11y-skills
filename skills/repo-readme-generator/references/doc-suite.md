# Documentation suite

For when the task is "document this project properly", "docs for a CLI agent", "onboarding docs", or anything beyond a single README. The goal: a developer or coding agent with no prior knowledge can understand the system, find the right file, run, change and verify it, without asking anyone.

## Scope tiers

| Tier | Creates | Use when |
|---|---|---|
| `readme` | `README.md` only (17-section template) | Default. User said "README". |
| `standard` | README + `AGENTS.md` + `docs/architecture.md`, `docs/codebase-map.md`, `docs/development-guide.md`, `docs/configuration.md`, plus `docs/api-reference.md` and `docs/data-model.md` when an API / datastore exists | "Document the repo", onboarding, preparing a repo for coding agents |
| `full` | Everything applicable in the table below | "As much detail as possible", handover, audit, new-hire or agent-first repos |

If unsure, say which tier you chose and why, and offer the next one up. Never create a document whose subject does not exist in the repo: skip it and list it as "Not applicable: <reason>" in the README documentation index.

## The documents

Paths are relative to the repo root. Every `docs/*.md` starts with the standard header (see below).

| File | Audience question it answers | Create when | Must contain | Evidence |
|---|---|---|---|---|
| `README.md` | What is this and where do I start? | always | 17-section template (see `readme-template.md`) plus a **Documentation** index linking every file below | all |
| `AGENTS.md` | How must an agent work here? | standard, full | See `agents-md-template.md`. Under 32 KiB, aim for ~150 lines, link out for detail | scripts, CI, configs, conventions |
| `docs/codebase-map.md` | Where is the code for X? Where do I make change Y? | standard, full | Directory-by-directory map; entry points; "to change X, edit A and B"; key files; naming and layering conventions; generated or vendored paths to leave alone; hot spots (large or fragile files) | tree, entry points, imports |
| `docs/architecture.md` | How is it built and how do the parts interact? | standard, full | Context diagram, logical architecture diagram, component details (responsibility, interfaces, dependencies, state), key flows with sequence diagrams, cross-cutting concerns (logging, errors, auth, config), boundaries and invariants, what is NOT built yet | code, compose, infra |
| `docs/tech-stack-and-dependencies.md` | What is it built with and what does it depend on? | full | Languages and runtimes with versions; frameworks; table of direct dependencies (name, version/range, purpose, manifest); dev/test tooling; external services and SaaS; base images; license of the project; notes on unpinned or outdated versions (only what manifests show) | manifests, lockfiles, Dockerfiles |
| `docs/design-and-decisions.md` | Why is it designed this way? | full | Patterns observed (layering, queues, CQRS, plugin points), each with the file that shows it; decision log in ADR style: **Context / Decision / Consequences**, with `Source: documented` (from ADRs, commit messages, comments) or `Source: inferred from code` (label clearly); trade-offs and constraints visible in code; open design questions as `TBD` | ADRs, code, git history |
| `docs/development-guide.md` | How do I set up, build, run, debug, ship a change? | standard, full | Prerequisites and versions, setup, build, run, debug, lint/format, test commands, branching/commit/PR conventions, CI pipeline walkthrough, release process, common tasks ("add an endpoint", "add a migration") only when the repo shows how | manifests, CI, CONTRIBUTING |
| `docs/testing.md` | How is quality verified? | full (standard if tests exist) | Test types and locations, frameworks, how to run all/one/watch, fixtures and test data, mocks, coverage config, what is untested (observed), CI test jobs, how to add a test | test dirs, configs, CI |
| `docs/configuration.md` | What can I configure? | standard, full | Variable table (name, purpose, required, default, where read, example placeholder), config files and precedence, per-environment differences, secrets handling (never values), feature flags | env templates, code, compose, helm |
| `docs/api-reference.md` | What interfaces does it expose or consume? | when an API, CLI, queue or event contract exists | Per interface: method/path or command, parameters, request/response shapes, auth, errors, example; events/queue contracts; links to OpenAPI/Proto/GraphQL; outbound integrations | routes, handlers, specs |
| `docs/data-model.md` | What data does it store and how? | when a datastore exists | Entities/tables/collections with fields and types, keys and indexes, relationships (ER diagram), migrations and how to run them, caches and queues (key formats, TTL), retention, data ownership per component | models, migrations, SQL |
| `docs/deployment-and-operations.md` | How does it run in real environments? | when infra, CI/CD or Docker exist | Environments, deployment diagram, build and release pipeline, infra resources, scaling and replicas, health checks, logging/metrics/alerts, backup and restore, runbooks (start, stop, rollback) only where the repo supports them | Dockerfiles, compose, k8s, terraform, CI, monitoring configs |
| `docs/security.md` | What are the security properties and risks? | full | AuthN/AuthZ as implemented, secrets handling, network exposure (ports, CORS, TLS), input validation, dependency and image risks visible in manifests, hardcoded credentials or sample defaults found (state the file, not the value), reporting process if SECURITY.md exists. Observations, not a pen-test | code, config, manifests |
| `docs/troubleshooting.md` | Something broke, what now? | full (standard folds into development guide) | Symptom, cause, fix table grounded in code and config; log locations; diagnostic commands; known issues | code, config, issues in repo |
| `docs/glossary.md` | What do these terms mean? | full, when domain terms or acronyms are non-obvious | Domain terms and acronyms as used in the code, with where they appear | code, docs |
| `docs/diagrams/` | Visuals | whenever a diagram is used as SVG | `src/<name>.json` (spec) and `<name>.svg` (rendered). See `svg-guide.md` | |

Do not create `CONTRIBUTING.md`, `CHANGELOG.md`, `SECURITY.md`, or `LICENSE`; link to them if they exist, and list them as `TBD` gaps in the report if missing.

## Standard header for every `docs/*.md`

```markdown
# <Title>

> <One sentence: what this document covers and who should read it.>

- **Status:** Verified against commit `<sha>` on <YYYY-MM-DD>
- **Related:** [Architecture](architecture.md) · [Codebase map](codebase-map.md)
- **Legend:** Implemented = found in code · Planned = documented intent · TBD = unknown, needs an owner
```

Rules:
- One topic per file. Put detail in the specific doc and keep the README to a summary plus a link. Do not duplicate tables across files; link instead.
- Same facts everywhere: component names, ports, commands and variable names must match across all documents. Choose the names used in code.
- Every claim traceable: link the source file (relative link, with `#L<line>` only if stable) or name it in backticks.
- Write for lookup: descriptive headings, tables for enumerations, short paragraphs, commands in fenced blocks, no marketing language.
- For agents specifically: prefer exact commands and exact paths over prose; state preconditions (services that must run first); say what output means success; list files that must not be edited by hand (generated, vendored, lockfiles); say which actions need human approval.
- Each document ends with `## Open questions (TBD)` listing what could not be verified. Omit the section only when empty.

## Order of work

1. `discover.py`, then read the key files (see `discovery-checklist.md`).
2. Build one internal model: components, flows, data, config, interfaces, dependencies, conventions.
3. Write in this order so later docs can link to earlier ones: `codebase-map` → `architecture` (with diagrams) → `tech-stack-and-dependencies` → `data-model` → `api-reference` → `configuration` → `development-guide` → `testing` → `deployment-and-operations` → `security` → `design-and-decisions` → `troubleshooting` → `glossary` → `AGENTS.md` → `README.md` (index last, so it links only what exists).
4. Verify the documents against the code (`verification-checklist.md`).
5. **Finalize `README.md` and `AGENTS.md` last, even if a README already exists**: the Documentation index links every file in `docs/`, the summary sections, commands and versions match the finished docs and code, the AGENTS.md documentation map lists every doc, and the README footer commit/date is refreshed. A suite is not complete until both files are updated.
6. Validate the whole suite with `validate_docs.py` (it errors when the README does not link every doc or `AGENTS.md` is missing); fix; re-run.

## Update mode for a suite

Run `check_drift.py README.md --docs docs`. It reports undocumented scripts, variables, services, entry points and files changed since the recorded commit. Map each finding to the document that owns it (table above), edit only those sections, regenerate affected SVGs from their specs, refresh the `Verified against commit` line in the files you touched, and re-run `validate_docs.py`.
