# WAVE (WebAIM) — Reverse-Engineering Analysis

Purpose: understand how WAVE works so we can later build a skill that reproduces its checks and reports against WCAG 2.x A/AA and Section 508. This document is analysis only; no skill is built here.

Date: 2026-11-02
Companion file: `wave-rule-catalog.json` (raw, official WAVE rule catalog, 110 items, downloaded from `https://wave.webaim.org/api/docs`).

---

## 0. How to read this document (evidence levels)

WAVE's engine is closed source. Only the rule *catalog* is published. Every statement below is tagged:

| Tag | Meaning |
|---|---|
| **[DOC]** | Stated on WebAIM's official pages or in the official JSON catalog |
| **[STD]** | Follows from a public standard (WCAG formula, HTML/ARIA spec) |
| **[INF]** | Inferred from documented rule names/summaries. A reasonable reconstruction, **not** confirmed WAVE behavior |
| **[MEM]** | From general knowledge of WAVE, not re-verified in this session. Needs confirmation |

Anything tagged [INF] or [MEM] must be validated by running WAVE on test pages (section 11) before we claim parity.

---

## 1. Executive summary

- WAVE is a **rule-based, DOM-inspection** tool. It loads the rendered page (after JS/CSS), walks every element, applies a fixed list of **110 named checks**, and reports each hit as an *item* in one of **six categories**. [DOC]
- It is **not** a full WCAG conformance checker. It never says "pass". Zero errors does not mean accessible. [DOC]
- Every check has a stable ID (e.g. `alt_missing`), a title, a summary, a category, and a list of WCAG success criteria (SC). The mapping is public and is already machine-readable. [DOC]
- Only **1 of 110 checks is a contrast check**, and only **22 are hard errors**. Most of WAVE (88 items) is *alerts, features, structure and ARIA*, which are informational, not failures. This matters for matching WAVE's counts. [DOC]
- The Chrome extension runs **entirely in the browser**; nothing is sent to WAVE servers. [DOC]
- The published catalog maps to **WCAG success criteria only**. There is no per-item Section 508 mapping in the catalog. A 508 mapping would have to be derived (section 7). [DOC + INF]
- Biggest risk to a "matches WAVE" claim: the exact detection thresholds (e.g. "very small text", "long alt text", "possible heading") are not published in detail. We can match the *rule set* exactly and the *logic* approximately; exact count parity needs empirical calibration.

---

## 2. What WAVE is (product map)

| Product | Description | Source |
|---|---|---|
| Online tool (`wave.webaim.org`) | Paste URL; server fetches and evaluates. May not execute all scripts (security limits) | [DOC] |
| Bookmarklet | Submits current page to the online tool | [DOC] |
| **Browser extensions** (Chrome, Firefox, Edge) | Evaluate the page *as rendered in your browser*, including private/intranet/authenticated/dynamic pages. Local processing | [DOC] |
| **WAVE API (subscription)** | Credit-based JSON API, returns structured results | [DOC] |
| **Stand-alone API / Testing Engine** | Self-hosted engine for bulk/private testing | [DOC] (existence only) |
| Site-wide tooling | Multi-page scanning (separate offerings) | [DOC] (existence only) |

The engagement uses the **Chrome extension**, so the reference behavior is "in-browser, post-render DOM".

---

## 3. Architecture and execution model

### 3.1 In-browser extension flow [DOC unless tagged]

1. User triggers: toolbar icon, `Ctrl+Shift+U` (`Cmd+Shift+U` on Mac), or context menu "WAVE this page".
2. Extension injects a content script and its UI into the **live page** (sidebar + icons).
3. The evaluation runs on the **rendered DOM** (post-JS, post-CSS), so computed styles are available. This is how contrast and visibility are determined. [DOC for "after JS and CSS"; INF for the mechanism]
4. Results are drawn two ways: a **sidebar** (Summary / Details / Reference / Contrast) and **icons injected inline** next to the offending elements.
5. Clicking the icon again, or refreshing, removes the UI.

### 3.2 Key architectural properties

| Property | Detail | Tag |
|---|---|---|
| Local only | "No information is sent to the WAVE server" from the extension | DOC |
| Post-render | JS and CSS applied before checks | DOC |
| Hidden content **is evaluated** | Elements hidden by CSS, `hidden`, `aria-hidden="true"`, or `tabindex="-1"` are still evaluated. Their icons are *dimmed* with a tooltip | DOC |
| Single-state snapshot | One evaluation of the page as it is at click time. Content behind interaction (menus, modals, tabs) is only seen if already in the DOM | INF |
| Single-document scope | Evaluates the current page; iframes are reported as structural items (`iframe`). Whether it descends into iframe content is not documented | DOC (iframe item) / unknown (descent) |
| Variable results | Results can differ by browser, location, cookies, time, and script support | DOC |
| Icon injection can alter layout | Injected icons may shift or overlap page elements | DOC |

### 3.3 Implication for our skill

To reproduce WAVE we need a **real browser engine** (computed styles, accessibility tree, post-JS DOM), not static HTML parsing. A headless Chromium driven by Playwright/Puppeteer, evaluating the same DOM in-page, is the closest analogue to the extension. Static HTML parsing would diverge on contrast, visibility and dynamic content.

---

## 4. UI model (what a client sees in WAVE)

| Panel | Purpose | Tag |
|---|---|---|
| **Summary** | Counts per category: Errors, Contrast Errors, Alerts, Features, Structural Elements, ARIA | DOC (via secondary sources) |
| **Details** | Every item type found, with counts, filterable/toggleable per icon type | DOC (via secondary sources) |
| **Reference** | Explanation of the selected item, why it matters, how to fix, WCAG links | DOC |
| **Contrast** | Lists contrast failures, foreground/background colors, ratio; manual color checker | DOC (via secondary sources) |
| **Styles toggle (no-styles view)** | Turns CSS off to linearize the page, show reading/tab order, reveal icons for hidden content | DOC |
| **Code tab** | Shows the markup/DOM for a selected icon | DOC |

Icon colors: errors red, alerts yellow, features green. Structure and ARIA colors vary in third-party descriptions (blue/purple/pink), so check the extension before replicating a visual style. Contrast errors are listed in the panel and (in practice) also marked on the page. [DOC + secondary, low confidence on colors]

Design takeaway: for the client report, mirror this vocabulary (same six category names, same counts layout, item IDs) so the client can compare side-by-side with their WAVE output.

---

## 5. The six categories

Counts are from the official catalog (`wave-rule-catalog.json`). Total = **110**.

| Category | Count | Nature | Pass/fail semantics |
|---|---:|---|---|
| Errors | 22 | Definite problems likely to block some users | Fail |
| Contrast Errors | 1 | Text below WCAG contrast ratio | Fail |
| Alerts | 42 | Likely or possible issues needing human review | Review (not a fail) |
| Features | 13 | Accessibility features correctly present | Positive signal |
| Structural Elements | 22 | Headings, lists, landmarks, tables, iframe | Informational |
| ARIA | 10 | ARIA present. Presence reported, **not** correctness | Informational |

Important nuances:

- **"ARIA" in WAVE is mostly presence reporting.** Only 2 ARIA-related items are *errors* (`aria_reference_broken`, `aria_menu_broken`) and they live in the Errors category. The ARIA category itself (10 items) has no failures. So "whether they're used correctly" in the brief is only partly true: WAVE validates a small number of ARIA misuses, not general ARIA validity. [DOC]
- **Alerts are not failures.** A client report must not count them as defects without human review. [DOC]
- **Features and Structure are positive/neutral.** They inflate the total number of items; compare category by category, not total.

---

## 6. Complete rule catalog with WCAG mapping

Source: official catalog. SC = WCAG success criterion. `-` = no SC listed by WAVE.

### 6.1 Errors (22)

| ID | Title | What it flags | WCAG SC |
|---|---|---|---|
| alt_missing | Missing alternative text | Image with no alt attribute | 1.1.1 |
| alt_link_missing | Linked image missing alt | Image in a link with no alt (empty link) | 1.1.1, 2.4.4 |
| alt_spacer_missing | Spacer image missing alt | Layout spacer without alt attribute | 1.1.1 |
| alt_input_missing | Image button missing alt | `input type=image` without alt | 1.1.1, 2.4.4 |
| alt_area_missing | Image map area missing alt | `<area>` without alt | 1.1.1, 2.4.4 |
| alt_map_missing | Image map missing alt | Image with hot spots, no alt attr | 1.1.1 |
| longdesc_invalid | Invalid longdesc | longdesc is not a URL | 1.1.1 |
| label_missing | Missing form label | Control with no label | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| label_empty | Empty form label | Label present with no content | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| label_multiple | Multiple form labels | Control with more than one label | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| aria_reference_broken | Broken ARIA reference | aria-labelledby/describedby target missing | 1.3.1, 4.1.2 |
| aria_menu_broken | Broken ARIA menu | ARIA menu lacks required menu items | 2.1.1, 4.1.2 |
| title_invalid | Missing or uninformative page title | No/non-descriptive `<title>` | 2.4.2 |
| language_missing | Language missing or invalid | No/invalid `lang` | 3.1.1 |
| meta_refresh | Page refreshes or redirects | `<meta http-equiv=refresh>` | 2.2.1, 2.2.2 |
| heading_empty | Empty heading | Heading with no content | 1.3.1, 2.4.1, 2.4.6 |
| button_empty | Empty button | Button with no text/value | 1.1.1, 2.4.4 |
| link_empty | Empty link | Link with no text | 2.4.4 |
| link_skip_broken | Broken skip link | Skip link target missing or not keyboard accessible | 2.1.1, 2.4.1 |
| th_empty | Empty table header | `<th>` with no text | 1.3.1 |
| blink | Blinking content | `<blink>` or blinking | 2.2.2 |
| marquee | Marquee | `<marquee>` | 2.2.2 |

(The catalog contains 22 error entries; the list above is the full set.)

### 6.2 Contrast Errors (1)

| ID | Title | What it flags | WCAG SC |
|---|---|---|---|
| contrast | Very low contrast | Text/background contrast below threshold | 1.4.3 |

### 6.3 Alerts (42)

| ID | Title | What it flags | WCAG SC |
|---|---|---|---|
| alt_suspicious | Suspicious alternative text | Alt likely insufficient/extraneous (e.g. filename, "image", "graphic") | 1.1.1 |
| alt_redundant | Redundant alternative text | Alt same as nearby/adjacent text | 1.1.1 |
| alt_duplicate | Nearby image has same alt | Adjacent images share alt | 1.1.1 |
| alt_long | Long alternative text | Very long alt (about 100+ chars) | 1.1.1 |
| longdesc | Long description | longdesc present | 1.1.1 |
| image_title | Image with title | title but no alt | 1.1.1 |
| label_orphaned | Orphaned form label | Label not tied to a control | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| label_title | Unlabeled control with title | No label, only title | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| select_missing_label | Select missing label | `<select>` without label | 1.3.1, 2.4.6, 3.3.2 |
| fieldset_missing | Missing fieldset | Radio/checkbox group not in fieldset | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| legend_missing | Fieldset missing legend | fieldset without legend | 1.1.1, 1.3.1, 2.4.6, 3.3.2 |
| heading_missing | No heading structure | Page has no headings | 1.3.1, 2.4.6 |
| h1_missing | Missing first level heading | No `<h1>` | 1.3.1, 2.4.6 |
| region_missing | No page regions | No landmarks/regions | 1.3.1, 2.4.1 |
| heading_skipped | Skipped heading level | e.g. h2 to h4 | 1.3.1, 2.4.1, 2.4.6 |
| heading_possible | Possible heading | Heading-styled text not a heading | 1.3.1, 2.4.1, 2.4.6 |
| table_layout | Layout table | Table used for layout | 1.3.1, 1.3.2 |
| table_caption_possible | Possible table caption | Caption-like text not in `<caption>` | 1.3.1 |
| list_possible | Possible list | List-like text without list markup | 1.3.1 |
| link_internal_broken | Broken same-page link | `#target` with no matching ID | 2.1.1 |
| link_suspicious | Suspicious link text | "click here", "more", etc. | 2.4.4 |
| link_redundant | Redundant link | Adjacent links, same URL | 2.4.4 |
| link_word | Link to Word document | .doc/.docx | - |
| link_excel | Link to Excel spreadsheet | .xls/.xlsx | - |
| link_powerpoint | Link to PowerPoint | .ppt/.pptx | - |
| link_pdf | Link to PDF | .pdf | - |
| link_document | Link to document | Other non-HTML doc | - |
| audio_video | Audio/Video | Audio/video file or link | 1.2.1, 1.2.2, 1.2.3, 1.2.5, 1.4.2 |
| html5_video_audio | HTML5 video or audio | `<video>`/`<audio>` | 1.2.1, 1.2.2, 1.2.3, 1.2.5, 1.4.2 |
| youtube_video | YouTube video | Embedded/linked YouTube | 1.2.1, 1.2.2, 1.2.3 |
| flash | Flash | Flash content | 1.2.1, 1.2.2, 1.2.3, 1.2.5, 2.1.2 |
| applet | Java applet | `<applet>` | - |
| plugin | Plugin | Unidentified plugin | - |
| noscript | Noscript element | `<noscript>` | - |
| event_handler | Device dependent event handler | e.g. mouse-only handlers | 2.1.1 |
| javascript_jumpmenu | JavaScript jump menu | `select onchange` navigation | 2.1.1, 3.2.2 |
| accesskey | Accesskey | accesskey attribute | 2.4.1 |
| tabindex | Tabindex | Positive tabindex | 2.4.3 |
| text_small | Very small text | Very small text (docs summary: about 10px or smaller) | - |
| text_justified | Justified text | Fully justified text | - |
| underline | Underlined text | Underlined non-link text | - |
| title_redundant | Redundant title text | title duplicates text/alt | - |

### 6.4 Features (13)

| ID | Title | WCAG SC |
|---|---|---|
| alt | Alternative text | 1.1.1 |
| alt_null | Null or empty alt | 1.1.1 |
| alt_spacer | Null alt on spacer | 1.1.1 |
| alt_link | Linked image with alt | 1.1.1, 2.4.4 |
| alt_input | Image button with alt | 1.1.1, 2.4.4 |
| alt_map | Image map with alt | 1.1.1 |
| alt_area | Image map area with alt | 1.1.1, 2.4.4 |
| figure | Figure | 1.1.1 |
| label | Form label | 1.1.1, 1.3.1, 2.4.6 |
| fieldset | Fieldset | 1.1.1, 1.3.1, 2.4.6 |
| link_skip | Skip link | 2.4.1 |
| link_skip_target | Skip link target | 2.4.1 |
| lang | Language (document or element) | 3.1.2 |

### 6.5 Structural Elements (22)

| ID | Title | WCAG SC |
|---|---|---|
| h1 to h6 | Heading levels 1-6 (six separate items) | 1.3.1, 2.4.1, 2.4.6 |
| ol / ul / dl | Ordered / unordered / description lists | 1.3.1 |
| header | `<header>` or banner landmark | 1.3.1, 2.4.1 |
| nav | `<nav>` or navigation landmark | 1.3.1, 2.4.1 |
| search | Search landmark | 1.3.1, 2.4.1 |
| main | `<main>` or main landmark | 1.3.1, 2.4.1 |
| aside | `<aside>` or complementary landmark | 1.3.1, 2.4.1 |
| footer | `<footer>` or contentinfo landmark | 1.3.1, 2.4.1 |
| region | Generic ARIA region | 1.3.1, 2.4.1 |
| table_data | Data table | 1.3.1 |
| table_caption | Table caption | 1.3.1 |
| th | Table header cell | 1.3.1 |
| th_col | Column header (`scope=col`) | 1.3.1 |
| th_row | Row header (`scope=row`) | 1.3.1 |
| iframe | Inline frame | - |

### 6.6 ARIA (10)

| ID | Title | WCAG SC |
|---|---|---|
| aria | ARIA role/state/property present | 4.1.2 |
| aria_label | aria-label / aria-labelledby present | 1.1.1, 1.3.1, 2.4.6, 2.5.3, 4.1.2 |
| aria_describedby | aria-describedby present | 1.3.1, 4.1.2 |
| aria_live_region | Alert or live region | 3.3.1, 4.1.3 |
| aria_menu | ARIA menu | 2.1.1, 4.1.2 |
| aria_button | role="button" element | 2.1.1, 4.1.2 |
| aria_expanded | aria-expanded present | 4.1.2 |
| aria_haspopup | Element triggers popup/menu/dialog | 4.1.2 |
| aria_tabindex | tabindex of 0 or less | 2.1.1 |
| aria_hidden | Content hidden with ARIA | 4.1.2 |

### 6.7 Catalog observations

1. **WCAG SC coverage in the whole catalog**: 1.1.1, 1.2.1, 1.2.2, 1.2.3, 1.2.5, 1.3.1, 1.3.2, 1.4.2, 1.4.3, 2.1.1, 2.1.2, 2.2.1, 2.2.2, 2.4.1, 2.4.2, 2.4.3, 2.4.4, 2.4.6, 2.5.3, 3.1.1, 3.1.2, 3.2.2, 3.3.1, 3.3.2, 4.1.2, 4.1.3. That is **26 distinct SC**. WCAG 2.1/2.2 A+AA has roughly 50+ SC, so WAVE touches about half and detects only a narrow slice of most of them.
2. **Only 1.4.3 has an automated pass/fail measure** beyond structural presence. No checks for 1.4.11 (non-text contrast), 1.4.10 (reflow), 1.4.12 (text spacing), 2.4.7 (focus visible), 2.5.8 (target size), 3.3.x beyond 3.3.1/3.3.2, 4.1.1.
3. **Version note**: the Help page text references WCAG 2.2, but the catalog contains no 2.2-only SC (no 2.4.11, 2.5.7, 2.5.8, 3.3.7, 3.3.8). Treat WAVE's effective coverage as WCAG 2.0/2.1. [DOC, observation]
4. Several items map to **no SC** (`link_pdf`, `link_word`, `text_small`, `text_justified`, `underline`, `title_redundant`, `noscript`, `applet`, `plugin`, `iframe`). Our report must handle "no SC" gracefully rather than invent one.
5. The "every finding should point to a WCAG success criterion" requirement from the brief **cannot be met 1:1 using WAVE's own mapping** for those items. Decision needed (section 12).

---

## 7. WCAG and Section 508 mapping

### 7.1 WCAG

- The catalog maps each item to one or more SC with the SC number, name, level, and a link to the WebAIM checklist. [DOC]
- Levels are given per SC (e.g. "1.1.1 Non-text Content (Level A)"). All SC used are Level A or AA. [DOC]
- Multiple SC per item is normal (e.g. `label_missing` maps to 4 SC). A finding therefore maps to *several* criteria, not one.

### 7.2 Section 508

- The WAVE catalog contains **no Section 508 field**. [DOC, from the JSON structure]
- The revised Section 508 (2017 refresh, 36 CFR 1194, Appendix A/C) **incorporates WCAG 2.0 Level A and AA by reference** for web content (E205.4, 501.1). So a 508 mapping is derivable: every WCAG 2.0 A/AA SC is a 508 requirement. [STD]
- Consequences:
  - A WCAG 2.0 A/AA mapping gives you a 508 mapping essentially for free (table: SC to "508 E205.4 / WCAG 2.0 conformance").
  - SC introduced in WCAG 2.1 / 2.2 (none are used in the WAVE catalog except 4.1.3, 2.5.3 is 2.1, 1.4.x none) are **not** 508 requirements. In this catalog, `2.5.3` (2.1) and `4.1.3` (2.1) are the only post-2.0 SC, and `aria_label` and `aria_live_region` use them. A 508 view should flag them as "WCAG 2.1, not required by revised 508".
  - Legacy (pre-2017) 508 "1194.22(a)-(p)" is a different mapping that older clients may still use. Ask the client which 508 they mean. [INF/needs confirmation]

---

## 8. Detection logic by rule family (reconstruction)

All of this is [INF] unless tagged otherwise. Use it as the design baseline and validate empirically.

### 8.1 Images and alternative text

- Inputs: `<img>`, `<area>`, `input[type=image]`, `<svg>` role=img (WAVE's SVG handling is not documented), CSS background images (WAVE does not evaluate these as images, [MEM]).
- Missing alt: attribute absent. `alt=""` is *not* an error; it is the `alt_null` feature (or `alt_spacer` for spacers). [DOC]
- Linked image with no accessible name: `alt_link_missing` (error), also `link_empty` semantics. [DOC]
- Suspicious: alt matches heuristics such as filename patterns (`.jpg`, `IMG_1234`), or generic words (`image`, `photo`, `graphic`, `spacer`, `picture`), or begins with "image of"/"picture of". [INF/MEM]
- Redundant: alt text equals adjacent link text or neighboring text node. [DOC summary; exact adjacency window unknown]
- Duplicate: adjacent images with identical alt. [DOC summary]
- Long: threshold around 100 characters [DOC via secondary summary; verify exact].
- Accessible-name sources considered: `alt`, `aria-label`, `aria-labelledby`, `title` (title-only yields alert `image_title`). [INF]

### 8.2 Forms

- Label association: `<label for>` matching `id`, wrapping `<label>`, `aria-label`, `aria-labelledby`, and `title` (title-only is an *alert* `label_title`, not an error). [DOC for title case; INF for the rest]
- `label_multiple`: more than one `<label>` for one control.
- `label_empty`: label exists but has no content.
- `label_orphaned`: `<label for="x">` where no `#x` or target not a labelable control.
- `fieldset_missing` / `legend_missing`: groups of radios/checkboxes (same `name`) not inside a `<fieldset>`; fieldset without `<legend>`.
- Excluded control types (inferred): `hidden`, `submit`, `reset`, `button`, `image` (handled elsewhere).

### 8.3 Links and buttons

- `link_empty`: `<a href>` with no text, no image alt, no aria-label content. [DOC summary]
- `button_empty`: `<button>`/`input[type=button|submit|reset]` without text or `value`. [DOC summary]
- `link_suspicious`: link text matches a stoplist ("click here", "here", "more", "read more", "link", "this"). [INF/MEM]
- `link_redundant`: adjacent links with same `href`. [DOC]
- `link_internal_broken`: `href="#x"` with no element id/name `x`. [DOC]
- Document-type alerts keyed on file extension in `href`. [INF]
- Skip links: first same-page links near the top of the DOM; target must exist and be focusable/visible (`link_skip_broken`). [INF]

### 8.4 Headings, landmarks, lists, tables

- Headings: `h1`-`h6` and probably `role=heading`. `heading_skipped` compares each heading level with the previous (increase of more than 1). `h1_missing`, `heading_missing` are page-level. [DOC/INF]
- `heading_possible`: short block of bold/large text that is not in a heading element (font-size/weight heuristics). [INF — thresholds unknown]
- Landmarks: native elements (`header`, `nav`, `main`, `aside`, `footer`) and ARIA roles (`banner`, `navigation`, `main`, `complementary`, `contentinfo`, `search`, `region`). `region_missing` fires when none exist. [DOC]
- `list_possible`: consecutive lines starting with bullet/number characters or `<br>`-separated items. [INF]
- Tables: data vs layout classification (presence of `th`, `caption`, `scope`, `headers`, role=presentation). `table_layout` alert when a table seems used for layout. [INF — classification rule unknown]
- `table_caption_possible`: text immediately before a table that looks like a title. [INF]

### 8.5 Page-level

- `title_invalid`: missing/empty title, or generic/uninformative (e.g. "Untitled", "Home" [INF]).
- `language_missing`: no `lang` on `<html>` or invalid BCP-47 value. `lang` feature reported when valid, including on elements (3.1.2). [DOC]
- `meta_refresh`: `<meta http-equiv="refresh">`. Probably exempt when delay is 0 vs not. Unknown. [INF]

### 8.6 Media and legacy

- `<video>`, `<audio>`, YouTube iframes/links, Flash/object embeds, applets: always an **alert** requesting manual caption/transcript review. WAVE does not check for tracks. [DOC summary/INF]
- `<blink>`, `<marquee>`: errors.

### 8.7 Event handlers and keyboard

- `event_handler`: elements with `onmouseover`, `onmouseout`, `ondblclick`, etc. without keyboard equivalents. [INF]
- `tabindex`: any positive tabindex. `aria_tabindex`: `tabindex` <= 0 (feature-like ARIA item). [DOC]
- `accesskey`, `javascript_jumpmenu`: attribute/pattern detection. [DOC]

### 8.8 ARIA

- Presence detection of `role` and `aria-*` attributes yields `aria`, `aria_label`, `aria_describedby`, `aria_expanded`, `aria_haspopup`, `aria_hidden`, `aria_live_region`, `aria_button`, `aria_menu`. [DOC]
- Correctness checks that *do* exist: broken `aria-labelledby`/`aria-describedby` IDREF targets; ARIA menu without required `menuitem` children. [DOC]
- Not present in the catalog (important for scoping): required parent/child roles in general, invalid role values, invalid attribute values, prohibited attributes, `aria-hidden` on focusable elements, duplicate IDs, name-from-content rules. axe-core covers these; WAVE mostly does not. [INF, from absence in catalog]

### 8.9 Contrast (`contrast`, SC 1.4.3)

Formula [STD]:

1. Convert sRGB channels to linear: `c <= 0.03928 ? c/12.92 : ((c+0.055)/1.055)^2.4`.
2. Relative luminance `L = 0.2126 R + 0.7152 G + 0.0722 B`.
3. Ratio = `(L_lighter + 0.05) / (L_darker + 0.05)`.

Thresholds [DOC/STD]:

| Text type | Min ratio (AA) |
|---|---|
| Normal text | 4.5:1 |
| Large text | 3:1 |
| Large = | at least 18pt (about 24px) regular, or at least 14pt (about 18.66px) bold |

WAVE-specific behaviors to verify empirically [INF/MEM]:

- Uses **computed foreground color** and the **effective background color** (walks ancestors, blends alpha). [INF]
- **Background images and gradients**: WAVE cannot reliably compute them. It likely either skips or uses the background-color only. This is a major source of mismatches vs axe ("incomplete"). [MEM]
- Applies **opacity** and text alpha when computing effective color. [INF]
- Does it report disabled controls, hidden text, placeholder text? Unknown. [open question]
- Ratio display rounding and the exact pass boundary (4.5 vs rounded 4.50) affect parity. [open question]
- Report granularity: one contrast error per text element (or per text node), with counts that can be large. Contrast items are listed in the Contrast panel. [INF]
- Only 1.4.3 (AA) is covered. 1.4.6 (AAA 7:1) and 1.4.11 are not WAVE checks. [DOC]

---

## 9. WAVE API (what is documented and what is not)

- Docs endpoint `https://wave.webaim.org/api/docs` returns the full rule catalog as JSON: `name`, `title`, `type`, `summary`, `guidelines[{name, link}]`. [DOC, verified: 110 entries]
- Item types in JSON: `error`, `contrast`, `alert`, `feature`, `structure`, `aria`. [DOC]
- The scan endpoint (`/api/request`, API key, `url`, `reporttype` 1-4) is **credit-based**. Report types roughly: 1 = category counts only; 2 = + item counts per rule; 3 = + selectors/XPath of each instance; 4 = + contrast data (colors, ratios). Credit cost increases with report type. [MEM — not verified; the docs page fetch did not expose this]
- Typical response shape (from memory): `status`, `statistics` (page title, URL, timing, total elements, credits), `categories` -> each with `count` and `items` -> each with `id`, `description`, `count`, and optionally `selectors`/`contrast`. [MEM]

Use: the JSON catalog is the authoritative source for rule IDs, titles, summaries and WCAG mapping. The scan API could be used as a **ground-truth oracle** during validation, if the client or we hold an API key (cost applies).

---

## 10. Limitations and known gaps (important for the "matches WAVE" story)

Documented: [DOC]

- Cannot judge alt-text quality; only prompts a human.
- Never passes a page; no-errors is not conformance.
- Covers some WCAG and 508 checks, not all.
- Results vary by browser, location, cookies, timing, scripting.

Derived:

- Narrow SC coverage (26 SC; most only partially).
- Presence-only for most ARIA. Little validation of correct ARIA usage.
- No keyboard/focus testing, no focus-visible, no reflow/zoom, no target size, no text spacing, no motion, no form error flow, no multi-page flows, no timing checks.
- Hidden content evaluated, which changes counts vs tools that skip hidden nodes.
- No awareness of states reachable only by interaction.
- Captions/transcripts/audio description: always manual.

What this means for us: a skill that matches WAVE exactly would **inherit WAVE's blind spots**. For a client deliverable, that is a deliberate scoping choice: "parity with WAVE" is the baseline layer. Anything extra (axe-style ARIA validation, focus tests) must be clearly labeled as supplementary so it does not break the count comparison.

---

## 11. Validation plan (how to prove parity later)

1. **Build a corpus**: 15-25 pages (client pages plus synthetic fixtures). Fixtures: one page per rule family with known violations (e.g. 110-item coverage matrix: one test snippet per rule ID).
2. **Gather ground truth** per page from WAVE Chrome extension: export or screenshot Summary and Details counts per item ID. Optionally use the WAVE API report type 3/4 for machine-readable selectors and contrast data.
3. **Compare** per page, per category, per item ID: our count vs WAVE count. Track: exact match, over-report, under-report.
4. **Calibrate** unknown thresholds from diffs: small text size, long alt length, suspicious-alt stoplist, heading-possible heuristics, table layout classification, link stoplist, contrast edge cases, hidden element handling, background image handling.
5. **Target definition**: define "match" up front, e.g. 100% parity on Errors and Contrast on fixtures; for alerts, allow documented heuristic differences.
6. Re-run when WAVE updates (auto-updates in the browser; pin the extension version and record it in the report).

---

## 12. Decisions and open questions for the team

| # | Question | Why it matters |
|---|---|---|
| 1 | Exactly which Section 508 does the client mean (revised 2017 vs legacy 1194.22)? | Drives the mapping table |
| 2 | WAVE maps 10 items to no WCAG SC (`link_pdf`, `text_small`, ...). Report them as "best practice / no SC", or map to a nearest SC (e.g. `text_small` to 1.4.4, `link_pdf` to 2.4.4)? | Brief says every finding must cite an SC; WAVE itself does not |
| 3 | Do we report only the six WAVE categories, or add supplementary checks (axe-style ARIA, focus)? | Scope vs parity story |
| 4 | Is a WAVE API key available for ground truth? | Cheaper, more reliable validation than screenshots |
| 5 | Authenticated pages and dynamic states: should the skill log in and exercise interactions? | WAVE extension sees whatever the browser shows; headless needs scripted state |
| 6 | Version pinning: which WAVE extension version is the client's baseline? | Counts can change between versions |
| 7 | Hidden-content policy: match WAVE (evaluate hidden) or exclude? | Large effect on counts |
| 8 | How to treat Features and Structure in the client report (informational, not defects)? | Prevents the client reading 100s of items as failures |

---

## 13. Design implications for the future skill (not built yet)

- **Engine**: headless Chromium (Playwright), run checks in-page against the live DOM and computed styles. Same model as the extension.
- **Rule layer**: one function per WAVE item ID, using the official catalog (`wave-rule-catalog.json`) as the single source of truth for ID, title, category, summary, and WCAG SC. This gives the SC mapping requirement directly.
- **Contrast module**: implement the WCAG formula, effective background resolution with alpha, large-text rule, and a documented policy for background images/gradients.
- **Mapping tables**: WCAG SC to level (A/AA), SC to Section 508 (via WCAG 2.0 incorporation), flag 2.1+ SC.
- **Report**: mirror WAVE's Summary (six category counts), then per-item tables with element selector, snippet, SC, severity/review-needed marker, and a clear statement that alerts require human review and that automated testing covers a subset of WCAG. Include tool/version/date, page URL, viewport, and rule-engine version.
- **Validation harness**: fixtures plus WAVE comparison diff report (section 11).

---

## 14. Sources

Official WebAIM:
- WAVE help: https://wave.webaim.org/help
- WAVE extension page: https://wave.webaim.org/extension/
- WAVE item documentation: https://wave.webaim.org/api/docs?format=html
- Machine-readable rule catalog: https://wave.webaim.org/api/docs (saved as `wave-rule-catalog.json`)
- WebAIM Contrast Checker (thresholds, large-text definition): https://webaim.org/resources/contrastchecker/
- Chrome Web Store listing: https://chromewebstore.google.com/detail/wave-evaluation-tool/jbbplnpkjmmeebjpijfedlgcdilocofh (not fetched in this session)

Secondary (panel/colour descriptions, lower confidence):
- https://www.webability.io/blog/wave-extension-for-chrome
- https://blog.utc.edu/web-kb/?p=1292
- https://blog.prototypr.io/snapshot-of-the-wave-accessibility-tool-79ae32ad8434

Standards: WCAG 2.x (W3C), WCAG relative luminance and contrast definitions, Section 508 Refresh (36 CFR Part 1194, E205.4).
