# a11y-skills

Codex skills by lowtouch.ai.

| Skill | What it does |
|---|---|
| [`wave-a11y-scan`](skills/wave-a11y-scan) | Scans pages with the same checks as the WAVE tool (WebAIM) and writes a client-ready report. Findings fall into WAVE's six categories (Errors, Contrast Errors, Alerts, Features, Structural Elements, ARIA) and each links to its WCAG 2.x success criteria, with a Section 508 note. Needs Playwright (see below). |
| [`repo-readme-generator`](skills/repo-readme-generator) | Creates or updates a repository's root `README.md` from verified evidence: architecture with Mermaid diagrams, component inventory, setup/build/run/test, configuration, APIs, deployment. Includes a validator and a drift checker. No extra dependencies. |

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
| Report warns about a "Just a moment..." page | The site's bot protection blocked the scanner. Scan a staging copy, or pass `--storage-state` from a logged-in session. |
| Codex doesn't list the skill | Confirm the folder is `~/.codex/skills/wave-a11y-scan/SKILL.md`, then restart Codex. |

### What it does and does not check

It reproduces WAVE's 110-item rule set. Detection thresholds for judgment-based alerts are approximations, so counts can differ slightly from the extension. Automated checks cover only part of WCAG: a clean report does not prove a page is accessible, and manual keyboard and screen-reader testing is still required. Background on WAVE's behavior is in [`docs/WAVE-analysis.md`](docs/WAVE-analysis.md).

## repo-readme-generator

Creates, updates or audits a repository's root `README.md`. Ask Codex:

| You say | Mode |
|---|---|
| "Generate a README for this repo" | create |
| "Update the README, we added a worker service" | update (edits only stale sections, keeps accurate text) |
| "Is the README out of date?" | audit (reports, changes nothing) |

Every component and command in the README comes from a file in the repository; anything unverifiable is labeled `TBD` or `Planned`. Codex does not install dependencies or start services without asking, and ends with a summary of what changed and what it could not verify. Section list: [`readme-template.md`](skills/repo-readme-generator/references/readme-template.md).

**Keep READMEs current with AGENTS.md.** Ask Codex "Add the README maintenance rules to AGENTS.md", or copy the block from [`agents-md-snippet.md`](skills/repo-readme-generator/references/agents-md-snippet.md) into your repository's `AGENTS.md`.

**Run the scripts directly** (read-only, no dependencies), from the target repository's root:

```bash
SK="${CODEX_HOME:-$HOME/.codex}/skills/repo-readme-generator/scripts"
python3 "$SK/discover.py" . --out /tmp/readme-facts.json   # facts about the repo
python3 "$SK/check_drift.py" README.md                     # undocumented or changed since the README was verified
python3 "$SK/validate_readme.py" README.md                 # structure, links, commands, Mermaid, secrets (exit 1 on errors)
```

`validate_readme.py --strict` treats warnings as errors (useful in CI). The validator is static: it does not run the documented commands or render Mermaid, so a clean result does not prove setup works or diagrams render.

| Symptom | Fix |
|---|---|
| `discover.py` warns "stopped at 20000 files" | You pointed it at a folder that is not a single repository. Run it at the project root, or pass `--max-files`. |
| Many `path-ref` warnings | They flag backticked paths that do not exist (often generated output). Keep them if intended. |
| `check_drift.py` says baseline unknown | The folder is not a git repo, or the README was never committed. Drift is judged from file contents only. |

## Development

```bash
python3 tests/smoke_test.py                          # wave-a11y-scan: scans a fixture with known violations
python3 tests/repo-readme-generator/test_skill.py    # repo-readme-generator: scripts against fixtures
```
