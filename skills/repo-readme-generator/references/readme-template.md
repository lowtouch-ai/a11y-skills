# README template

Use these headings, in this order, so READMEs look the same across repositories. Replace guidance with verified content. Omit a section's body only when it truly does not apply, and keep the heading with one line saying why (for example "Not applicable: this repository is a library with no deployment").

Mark every statement that cannot be verified from the repository: `TBD` (unknown, needs an owner), `Planned` (documented intent, not implemented). Never fill gaps with plausible guesses.

```markdown
# <Project name>

> <One-sentence purpose, taken from manifests, docs or code. If none exists, write "TBD: purpose not documented".>

<badges only if the repo already has CI or a registry listing>

## Table of Contents
<clickable links to every H2, one per line>

## Project Overview
Name, purpose, problem solved, intended users, capabilities, how the system behaves at a high level.
Evidence: package/pyproject description, existing docs, entry points, routes.

## Documentation
(Suite scope only; see doc-suite.md.) Table of every document with a one-line description, linking `AGENTS.md` and each `docs/*.md`. Add "Not applicable: <doc> (<reason>)" for skipped ones. The README keeps summaries; detail lives in those files.

## Technology Stack
| Layer | Technology | Purpose | Source |
|---|---|---|---|
Languages, frameworks, datastores, messaging, build tools, test tools, infra. Versions only if pinned in a manifest.

## High-Level Logical Architecture
One Mermaid `flowchart TB` or `LR` (see mermaid-guide.md), or an SVG generated with `make_svg.py` (see svg-guide.md) with subgraphs: Clients, Entry points, Services, Internal modules, Data stores, External integrations.
Then 3 to 8 bullets explaining the main flows and relationships shown, each naming real files or modules.

## Component Inventory
| Component | Responsibility | Source location | Depends on |
|---|---|---|---|
Every box in the diagram appears here. Add interfaces (public functions, endpoints, events) and key implementation notes below the table for non-obvious components.

## Repository Structure
Annotated tree (depth 2 to 3). Exclude generated and dependency folders (node_modules, dist, build, .venv, __pycache__, target).
One short annotation per entry, only for entries that exist.

## Application Execution Flow
Startup, configuration loading, initialization, request/job processing, persistence, integrations, shutdown.
Add a Mermaid `sequenceDiagram` (or generated SVG) when two or more components interact in a non-trivial order.

## Development Prerequisites
Runtimes and versions (from .nvmrc, engines, requires-python, go.mod, toolchain files), package managers, tools, containers, databases, accounts, how secrets are supplied (never the values).

## Local Development Setup
Numbered, copy-paste commands: clone, install, configure, start dependencies, initialize data, build, run, verify. Each command must exist in a manifest, script, Makefile or CI file. Unknown steps: `TBD`.

## Build Instructions
Dev and production builds, outputs, clean/rebuild, only where supported.

## Running the Application
Start/stop/restart, ports, URLs, health checks, logging, debugging.

## Testing
Test types found (unit, integration, e2e), frameworks, verified commands, where tests live, coverage tooling if configured. If no tests exist, say so.

## Configuration
| Variable | Description | Required | Default | Used in |
|---|---|---|---|---|
From env templates and code reads. Never print real values.

## APIs and Interfaces
Verified endpoints (method, path, auth, purpose), events/queues, CLI commands, contracts, links to OpenAPI/Proto/GraphQL files.

## Deployment Architecture
Existing infrastructure code, CI/CD pipelines, environments. Optional Mermaid deployment diagram. If nothing exists: "No deployment configuration found in this repository."

## Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
Only issues grounded in the repo (required env var missing, port in config, version constraint, migration step).

## Development Guidelines
Conventions that exist: linters, formatters, pre-commit, commit/branch rules, CONTRIBUTING.md, architecture boundaries visible in the code.

## Known Limitations and Future Work
Only gaps documented in the repo (TODOs, issues links, roadmap docs) or discovered during this analysis (label which).

<!-- repo-readme-generator: commit=<git HEAD sha> date=<YYYY-MM-DD> -->
```

The final HTML comment records the commit the README was verified against. `check_drift.py` uses it to find what changed since.

## Empty or near-empty repository

Create only: title, a "Status: starter skeleton, no implementation yet" notice, the section headings with `TBD` bodies, and the table of contents. Do not draw an architecture diagram; put a `TBD` note where it will go.
