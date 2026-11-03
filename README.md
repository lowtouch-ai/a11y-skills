# a11y-skills

Codex skills by lowtouch.ai.

| Skill | What it does |
|---|---|
| [`wave-a11y-scan`](skills/wave-a11y-scan) | Scans pages with the same checks as the WAVE tool (WebAIM) and writes a client-ready report. Findings fall into WAVE's six categories (Errors, Contrast Errors, Alerts, Features, Structural Elements, ARIA) and each links to its WCAG 2.x success criteria, with a Section 508 note. Needs Playwright (see below). |
| [`repo-readme-generator`](skills/repo-readme-generator) | Creates or updates project documentation from verified evidence: an architecture-focused `README.md`, or a full documentation suite for developers and coding agents (`AGENTS.md`, codebase map, architecture, stack and dependencies, design decisions, development guide, testing, configuration, API, data model, operations, security). Diagrams as Mermaid or generated SVG. Includes validators and a drift checker. No extra dependencies. |

## Install a skill in Codex

You need: [Codex](https://developers.openai.com/codex) (CLI or IDE extension), Python 3.9+, and git. On Windows, use the same steps inside WSL, or in PowerShell where noted.

### 1. Get the repo

```bash
git clone https://github.com/lowtouch-ai/a11y-skills.git
cd a11y-skills
```

If the repo is private, you must be signed in to GitHub with access (`gh auth login`, or an SSH key / personal access token).

### 2. Copy the skill into Codex's skills folder

Replace `<skill>` with `wave-a11y-scan` or `repo-readme-generator`. Install both by repeating the copy.

macOS / Linux / WSL:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -r skills/<skill> "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Windows PowerShell:

```powershell
$dest = if ($env:CODEX_HOME) { "$env:CODEX_HOME\skills" } else { "$env:USERPROFILE\.codex\skills" }
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item -Recurse skills\<skill> $dest
```

To update later, `git pull` and copy again (or use a symlink instead of `cp` so a pull is enough).

### 3. Install dependencies (`wave-a11y-scan` only, once)

`repo-readme-generator` needs nothing extra: skip to step 4.


```bash
python3 -m pip install -r "${CODEX_HOME:-$HOME/.codex}/skills/wave-a11y-scan/requirements.txt"
python3 -m playwright install chromium
```

(On Windows use `python` instead of `python3`, and the skill folder from step 2.) The second command downloads a private copy of Chromium, about 150 MB.

### 4. Restart Codex and check

Quit and reopen Codex so it picks up the new skill. Then ask:

> Use the wave-a11y-scan skill to scan https://example.com

or

> Use the repo-readme-generator skill to create a README for this repository.

You can also type `$wave-a11y-scan` or `$repo-readme-generator` to select a skill explicitly.

#### Alternative: install with Codex's built-in installer

Inside Codex you can ask:

> $skill-installer install https://github.com/lowtouch-ai/a11y-skills/tree/main/skills/<skill>

Then do step 3 if the skill needs it, and restart Codex.

## wave-a11y-scan

### Use it without Codex

The scanner is a plain Python script:

```bash
python3 skills/wave-a11y-scan/scripts/scan.py https://example.com --out ./a11y-report --title "Client name"
```

It writes `report.html` (give this to the client), `report.md`, and one JSON file per page into `a11y-report/`. Scan several pages by listing more URLs. See [`SKILL.md`](skills/wave-a11y-scan/SKILL.md) for all options, including logged-in pages.

### Compare with the WAVE extension

1. Run the [WAVE Chrome extension](https://chromewebstore.google.com/detail/wave-evaluation-tool/jbbplnpkjmmeebjpijfedlgcdilocofh) on a page and note the count for each item in its Details tab.
2. Save them as JSON using WAVE item IDs: `{"alt_missing": 29, "contrast": 2}`. IDs are in [`references/wave-rule-catalog.json`](skills/wave-a11y-scan/references/wave-rule-catalog.json).
3. Run `python3 skills/wave-a11y-scan/scripts/compare.py a11y-report/<page>.json wave_counts.json`.

### Calibration status

Checked against the WAVE Chrome extension on one page so far: the W3C "Before" demo (`https://www.w3.org/WAI/demos/bad/before/home.html`, WAVE counts in [`tests/calibration/`](tests/calibration)). All 23 item types and all six category totals match. Several rules (spacer images, redundant links, small text, possible headings) were tuned on that single page, so treat other sites as unverified until compared. Add more pages to `tests/calibration/` as they are checked. WAVE's newer "AIM score" is not reproduced.

### Troubleshooting (wave-a11y-scan)

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: playwright` | Run the `pip install` line from step 3 with the same Python that runs the scan. |
| `Executable doesn't exist` / browser not found | Run `python3 -m playwright install chromium`. |
| Exit code 3, or "Pages that could not be scanned" in the report | A URL did not load (typo, DNS, timeout, TLS). The message says why; the other pages are still reported. A URL without `https://` is scanned as `https://`. |
| Report warns about a "Just a moment..." page | The site's bot protection blocked the scanner. Scan a staging copy, or pass `--storage-state` from a logged-in session. |
| Codex doesn't list the skill | Confirm the folder is `~/.codex/skills/wave-a11y-scan/SKILL.md`, then restart Codex. |

### What it does and does not check

It reproduces WAVE's 110-item rule set. Detection thresholds for judgment-based alerts are approximations, so counts can differ slightly from the extension. Automated checks cover only part of WCAG: a clean report does not prove a page is accessible, and manual keyboard and screen-reader testing is still required. Background on WAVE's behavior is in [`docs/WAVE-analysis.md`](docs/WAVE-analysis.md).

## repo-readme-generator

Creates, updates or audits project documentation. Every component, command and dependency in the output comes from a file in the repository; anything unverifiable is labeled `TBD` or `Planned`, and design rationale inferred from code is labeled as inferred. Codex does not install dependencies or start services without asking, and it ends with a summary of what changed and what it could not verify.

### Scopes

| You say | Scope | Output |
|---|---|---|
| "Generate a README for this repo" | `readme` | `README.md` (17 fixed sections, table of contents, diagrams) |
| "Document this repo", "onboarding docs", "docs for coding agents" | `standard` | README + `AGENTS.md` + `docs/` codebase map, architecture, development guide, configuration (+ API reference, data model when they exist) |
| "As much detail as possible", "full documentation: architecture, stack, design, dependencies" | `full` | Everything applicable: adds tech stack and dependency tables, design and decisions, testing, deployment and operations, security, troubleshooting, glossary |

Modes: **create**, **update** (edits only stale sections), **audit** (reports, changes nothing). Documents whose subject does not exist in the repo are skipped and listed as "Not applicable". What each document contains and where its evidence comes from: [`doc-suite.md`](skills/repo-readme-generator/references/doc-suite.md).

### Diagrams: Mermaid or SVG

Mermaid is the default (renders natively on GitHub, easy to diff). For SVG, Codex writes a small JSON spec and `make_svg.py` renders a clean, accessible diagram (architecture with groups, lanes and legend; sequence flows). Use SVG when you ask for it, when the docs are read outside GitHub (PDF, wiki, Confluence), or when a diagram is large. Specs live in `docs/diagrams/src/` so diagrams can be regenerated when the architecture changes. Guide: [`svg-guide.md`](skills/repo-readme-generator/references/svg-guide.md).

Example prompts:

> Use the repo-readme-generator skill to create a README for this repository.
>
> Use the repo-readme-generator skill to build the full documentation suite for this repo, with SVG diagrams, so a coding agent can work on it.
>
> Use the repo-readme-generator skill to update the docs, we added a worker service.

### Keep docs current with AGENTS.md
In suite scope Codex creates `AGENTS.md` for you (commands, conventions, boundaries, docs map, and the documentation-maintenance rules). In README scope, ask "Add the README maintenance rules to AGENTS.md", or copy the block from [`agents-md-snippet.md`](skills/repo-readme-generator/references/agents-md-snippet.md). Afterwards Codex checks for drift whenever a change touches architecture, commands, configuration or infrastructure.

### Run the scripts directly
Read-only except `make_svg.py` (writes the SVG you name), no dependencies. From the target repository's root:

```bash
SK="${CODEX_HOME:-$HOME/.codex}/skills/repo-readme-generator/scripts"
python3 "$SK/discover.py" . --out /tmp/readme-facts.json        # facts: deps, scripts, services, env vars, data model, tooling
python3 "$SK/make_svg.py" docs/diagrams/src/architecture.json docs/diagrams/architecture.svg
python3 "$SK/check_drift.py" README.md --docs docs              # undocumented or changed since the docs were verified
python3 "$SK/validate_readme.py" README.md                      # one README (exit 1 on errors)
python3 "$SK/validate_docs.py"                                  # whole suite incl. SVGs and AGENTS.md (exit 1 on errors)
```

`--strict` (both validators) treats warnings as errors, useful in CI. The validators are static: they do not run the documented commands or render Mermaid, so a clean result does not prove setup works or diagrams render. `tests/repo-readme-generator/fixtures/node-app-docs/` is a small worked example of a full suite.

| Symptom | Fix |
|---|---|
| `discover.py` warns "stopped at 20000 files" | You pointed it at a folder that is not a single repository. Run it at the project root, or pass `--max-files`. |
| Many `path-ref` warnings | They flag backticked paths that do not exist (often generated output). Keep them if intended. |
| `check_drift.py` says baseline unknown | The folder is not a git repo, or the docs were never committed. Drift is judged from file contents only. |
| SVG labels collide or lines cross awkwardly | Reorder `nodes` or adjust `groups` in the spec, then re-run `make_svg.py`. |
| `AGENTS.md` warning about 32 KiB | Codex reads only the first 32 KiB by default. Move detail into `docs/` and link it. |

## Development

```bash
python3 tests/smoke_test.py                          # wave-a11y-scan: scans a fixture with known violations
python3 tests/repo-readme-generator/test_skill.py    # repo-readme-generator: scripts against fixtures
```
