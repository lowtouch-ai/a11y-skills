# a11y-skills

Codex skills for accessibility work, by lowtouch.ai.

| Skill | What it does |
|---|---|
| [`wave-a11y-scan`](skills/wave-a11y-scan) | Scans pages with the same checks as the WAVE tool (WebAIM) and writes a client-ready report. Findings fall into WAVE's six categories (Errors, Contrast Errors, Alerts, Features, Structural Elements, ARIA) and each links to its WCAG 2.x success criteria, with a Section 508 note. |

## Install the skill in Codex

You need: [Codex](https://developers.openai.com/codex) (CLI or IDE extension), Python 3.9+, and git. On Windows, use the same steps inside WSL, or in PowerShell where noted.

### 1. Get the repo

```bash
git clone https://github.com/lowtouch-ai/a11y-skills.git
cd a11y-skills
```

If the repo is private, you must be signed in to GitHub with access (`gh auth login`, or an SSH key / personal access token).

### 2. Copy the skill into Codex's skills folder

macOS / Linux / WSL:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -r skills/wave-a11y-scan "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Windows PowerShell:

```powershell
$dest = if ($env:CODEX_HOME) { "$env:CODEX_HOME\skills" } else { "$env:USERPROFILE\.codex\skills" }
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item -Recurse skills\wave-a11y-scan $dest
```

To update later, `git pull` and copy again (or use a symlink instead of `cp` so a pull is enough).

### 3. Install the scanner's dependencies (once)

```bash
python3 -m pip install -r "${CODEX_HOME:-$HOME/.codex}/skills/wave-a11y-scan/requirements.txt"
python3 -m playwright install chromium
```

(On Windows use `python` instead of `python3`, and the skill folder from step 2.) The second command downloads a private copy of Chromium, about 150 MB.

### 4. Restart Codex and check

Quit and reopen Codex so it picks up the new skill. Then ask:

> Use the wave-a11y-scan skill to scan https://example.com

or type `$wave-a11y-scan` in Codex to select it. Codex runs the scan and tells you where the report is.

#### Alternative: install with Codex's built-in installer

Inside Codex you can ask:

> $skill-installer install https://github.com/lowtouch-ai/a11y-skills/tree/main/skills/wave-a11y-scan

Then do step 3 and restart Codex.

## Use it without Codex

The scanner is a plain Python script:

```bash
python3 skills/wave-a11y-scan/scripts/scan.py https://example.com --out ./a11y-report --title "Client name"
```

It writes `report.html` (give this to the client), `report.md`, and one JSON file per page into `a11y-report/`. Scan several pages by listing more URLs. See [`SKILL.md`](skills/wave-a11y-scan/SKILL.md) for all options, including logged-in pages.

## Compare with the WAVE extension

1. Run the [WAVE Chrome extension](https://chromewebstore.google.com/detail/wave-evaluation-tool/jbbplnpkjmmeebjpijfedlgcdilocofh) on a page and note the count for each item in its Details tab.
2. Save them as JSON using WAVE item IDs: `{"alt_missing": 29, "contrast": 2}`. IDs are in [`references/wave-rule-catalog.json`](skills/wave-a11y-scan/references/wave-rule-catalog.json).
3. Run `python3 skills/wave-a11y-scan/scripts/compare.py a11y-report/<page>.json wave_counts.json`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: playwright` | Run the `pip install` line from step 3 with the same Python that runs the scan. |
| `Executable doesn't exist` / browser not found | Run `python3 -m playwright install chromium`. |
| Report warns about a "Just a moment..." page | The site's bot protection blocked the scanner. Scan a staging copy, or pass `--storage-state` from a logged-in session. |
| Codex doesn't list the skill | Confirm the folder is `~/.codex/skills/wave-a11y-scan/SKILL.md`, then restart Codex. |

## What it does and does not check

It reproduces WAVE's 110-item rule set. Detection thresholds for judgment-based alerts are approximations, so counts can differ slightly from the extension. Automated checks cover only part of WCAG: a clean report does not prove a page is accessible, and manual keyboard and screen-reader testing is still required. Background on WAVE's behavior is in [`docs/WAVE-analysis.md`](docs/WAVE-analysis.md).

## Development

```bash
python3 tests/smoke_test.py   # scans a fixture with known violations
```
