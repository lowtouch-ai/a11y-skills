---
name: wave-a11y-scan
description: Scan a project's source code for accessibility problems using the WAVE rule set and produce a client-ready report. Use when asked to run an accessibility or WAVE-style audit of a repo or folder of HTML, templates, JSX/TSX, Vue, Svelte or Astro files, or to check WCAG 2.x A/AA and Section 508 issues such as alt text, labels, headings, landmarks, ARIA, link and button names, tables and contrast. Reports Errors, Contrast Errors, Alerts, Features, Structural Elements and ARIA with file and line, each mapped to WCAG success criteria.
---

# WAVE-style accessibility scan of source code

Reads source files, applies the WAVE rule set (110 items, six categories) and writes a Markdown, HTML and JSON report. Every finding has a file and line and carries its WCAG 2.x success criteria and a Section 508 note. No browser, network or install is needed: it needs only Python 3.

## Run a scan

```bash
python3 <skill-dir>/scripts/scan.py PATH [PATH ...] --out ./a11y-report --title "Client name"
```

`PATH` is a file or a directory (scanned recursively). `<skill-dir>` is usually `~/.codex/skills/wave-a11y-scan`.

Options: `--format md,html,json` (default all), `--max-instances 10` (examples per rule), `--max-files 25` (rows in the per-file summary), `--include-tests` (also scan test, spec and story files).

Outputs in `--out`: `report.md`, `report.html` (hand to the client), and `results.json` with every finding (file, line, selector, snippet, contrast colors and ratios).

Scanned: `.html .htm .jsx .tsx .vue .svelte .astro` and common template types (`.php .erb .ejs .hbs .njk .liquid .twig .jinja .cshtml .razor`), plus `.js` files that import React. Skipped: `node_modules`, build output (`dist`, `build`, `.next`, `.nuxt`, `out`), `vendor`, tests and stories, minified files, files over 1 MB.

Exit codes: `0` ok (findings do not change it); `2` bad option; `3` a path does not exist or no markup files were found (no report is written).

## Reading the results

- **Errors** and **Contrast Errors** are failures. Lead with these.
- **Alerts** need human review; never present them as confirmed defects.
- **Features**, **Structural Elements** and **ARIA** are informational. ARIA means "present", not "correct".
- Some items map to no WCAG criterion (for example PDF links, small text). The report says "none listed in the catalog"; do not invent a criterion.
- Never state that code is accessible or conformant. Automated checks cover part of WCAG. Say what was checked and what still needs manual testing (keyboard, screen reader, captions, focus order).

## How source scanning behaves

- A value that is only known at runtime (`alt={desc}`, `:alt="x"`, `<?= $x ?>`, `{{ x }}`, spread props) is treated as present and is never reported. Elements rendered by components defined elsewhere are treated as unknown content, except icon components imported from icon libraries (lucide-react, react-icons, heroicons, MUI icons, Font Awesome and similar), which count as a glyph with no text. An icon-only button or link with no `aria-label`, `title` or text is reported as empty.
- References by id (`for`, `aria-labelledby`, `#anchor`) are resolved across all scanned files. They are not reported when any element in the file has a dynamic id.
- Document-level rules (`lang`, `<title>`, missing headings or landmarks) apply to files with a full `<html>` page. Single-page-app shells with an empty mount element are not reported for missing headings.
- Event-handler, `tabindex` and `accesskey` checks apply to native elements only, not custom components.
- Contrast is computed from CSS in `<style>` blocks, linked and imported `.css` files, inline styles and CSS-in-JS object literals, with `var(--x)` resolved. Elements whose colors come from dynamic classes or utility classes such as `bg-primary` or `text-gray-500` (Tailwind palette and theme values are not resolved), gradients, images or other files are counted as skipped in the report, not guessed.

## Files

- `scripts/scan.py` finds files, runs the checks and builds the reports.
- `scripts/source_parser.py` parses HTML, JSX, Vue, Svelte and template syntax into an element tree with line numbers.
- `scripts/source_checks.py` holds the rule checks. `scripts/source_css.py` resolves CSS for contrast and text-size checks.
- `references/wave-rule-catalog.json` is the rule catalog (IDs, titles, categories, WCAG mapping).

## Known limits

- Rules that need a rendered page are not implemented: `heading_possible`, `list_possible`, `table_caption_possible`, `longdesc_invalid`. The report lists them.
- Only what appears in source is checked; menus, dialogs and tabs built at runtime are not seen.
- WAVE's "AIM score" is not reproduced.
