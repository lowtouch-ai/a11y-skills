# a11y-skills

Codex skills by lowtouch.ai.

| Skill | What it does |
|---|---|
| [`wave-a11y-scan`](skills/wave-a11y-scan) | WAVE-style accessibility scan of web pages with a client-ready report (WCAG 2.x, Section 508 note). |
| [`repo-readme-generator`](skills/repo-readme-generator) | Creates or updates a repo's README, or a full documentation suite with `AGENTS.md` and diagrams, from verified evidence. |

## Install

In Codex, run the command for the skill you want, then restart Codex.

```
$skill-installer install https://github.com/lowtouch-ai/a11y-skills/tree/main/skills/wave-a11y-scan
```

```
$skill-installer install https://github.com/lowtouch-ai/a11y-skills/tree/main/skills/repo-readme-generator
```

`wave-a11y-scan` installs its own dependencies (Playwright and Chromium, about 150 MB) the first time it runs.

## Test

Open Codex in the folder you want to work on and run:

```
$wave-a11y-scan scan https://example.com
```

```
$repo-readme-generator create the README for this repo
```

For the full documentation suite: `$repo-readme-generator document this repo fully`

## More

- Skill details: [`wave-a11y-scan/SKILL.md`](skills/wave-a11y-scan/SKILL.md), [`repo-readme-generator/SKILL.md`](skills/repo-readme-generator/SKILL.md)
- Automated checks do not prove a page is accessible; manual keyboard and screen-reader testing is still required.
