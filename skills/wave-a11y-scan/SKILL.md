---
name: wave-a11y-scan
description: Scan web pages for accessibility problems using the same checks as the WAVE tool (WebAIM) and produce a client-ready report. Use when asked to run an accessibility or WAVE-style scan, audit a URL for WCAG 2.x A/AA or Section 508, check contrast, alt text, labels, headings, landmarks or ARIA, or compare results with the WAVE browser extension. Reports Errors, Contrast Errors, Alerts, Features, Structural Elements and ARIA, each mapped to WCAG success criteria.
---

# WAVE-style accessibility scan

Runs the WAVE rule set (110 items, six categories) against live pages in headless Chromium and writes a Markdown, HTML and JSON report. Every finding carries its WCAG 2.x success criteria and a Section 508 note.

## Prerequisites (once per machine)

```bash
python3 -m pip install -r <skill-dir>/requirements.txt
python3 -m playwright install chromium
```

`<skill-dir>` is the folder holding this file (usually `~/.codex/skills/wave-a11y-scan`). If `import playwright` fails or Chromium is missing, run the two commands above before scanning.

## Run a scan

```bash
python3 <skill-dir>/scripts/scan.py URL [URL ...] --out ./a11y-report --title "Client name"
```

Useful options: `--format md,html,json` (default all), `--viewport 1280x900`, `--wait 2000` (ms after load, raise for slow single-page apps), `--max-instances 10`, `--storage-state state.json` (logged-in pages, a Playwright storage-state file).

Outputs in `--out`: `report.md`, `report.html` (hand to the client), and one `<page>.json` per URL with every instance (selector, HTML snippet, contrast colors and ratios).

Exit code 2 means a page returned a bot-protection or access-denied screen (for example a Cloudflare "Just a moment..." page). Those results are invalid. Do not report them; tell the user, and try a logged-in `--storage-state`, a different network, or ask for a staging URL.

## Reading the results

- **Errors** and **Contrast Errors** are failures. Lead with these.
- **Alerts** need human review; never present them as confirmed defects.
- **Features**, **Structural Elements** and **ARIA** are informational. ARIA means "present", not "correct".
- Some WAVE items map to no WCAG criterion (for example PDF links, small text). The report says "none listed by WAVE"; do not invent a criterion.
- Never state that a page is accessible or conformant. Automated checks cover part of WCAG. Say what was checked and what still needs manual testing (keyboard, screen reader, captions, focus order).

## Compare with the WAVE extension

1. Run WAVE on the same page and note the count for each item shown in its Details panel.
2. Save them as `{"alt_missing": 29, "contrast": 2, ...}` using the item IDs from `references/wave-rule-catalog.json`.
3. `python3 <skill-dir>/scripts/compare.py <page>.json wave_counts.json`

Report per-item matches and gaps. Differences in alert heuristics (suspicious alt text, small text, possible heading) are expected; treat them as thresholds to tune in `scripts/wave_checks.js`.

## Files

- `scripts/scan.py` runs scans and builds reports. `scripts/wave_checks.js` holds the checks that run in the page. `scripts/compare.py` diffs against WAVE.
- `references/wave-rule-catalog.json` is WAVE's official rule catalog (IDs, titles, categories, WCAG mapping).

## Known limits

- `table_caption_possible` is not implemented. Contrast over background images or gradients is skipped and counted in the report.
- Only the DOM present at scan time is checked; menus, dialogs and tabs closed at load are not seen.
- Detection thresholds for alert-type items are approximations of WAVE's. Matched 100% against the extension on one page (W3C "bad before" demo); other pages are unverified. Add comparisons under `tests/calibration/`.
- WAVE's "AIM score" is not reproduced.
