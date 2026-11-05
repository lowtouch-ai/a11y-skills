"""Accessibility checks that run on parsed source files. Rule IDs, categories and WCAG mapping come from
references/wave-rule-catalog.json. A check only fires when the evidence is in the source; values that are produced at
runtime (expressions, template tags, spread props, components defined elsewhere) make a check skip, never guess."""
import re

from source_css import NOT_TEXT, UNK, Styler, lum, ratio
from source_parser import DYN, El, static

SUSP_ALT = re.compile(r"^(image|photo|picture|graphic|spacer|icon|logo|img|pic|blank|space|bullet)$|\.(jpe?g|png|gif|svg|bmp)$|^(image|picture|photo|graphic) of\b|^(img|dsc|image)[_-]?\d+", re.I)
SUSP_LINK = re.compile(r"^(click here|here|more|read more|link|this|click|more\.\.\.|learn more|continue|details|info)$", re.I)
GENERIC_TITLE = re.compile(r"^(untitled|home|page|document|new page|untitled document)$", re.I)
MOUSE_EVENTS = ("onmouseover", "onmouseout", "onmousedown", "onmouseup", "ondblclick", "onmousemove")
CONTROLS_SKIP = {"hidden", "submit", "button", "reset", "image"}
LANDMARKS = [("header", {"header"}, "banner"), ("nav", {"nav"}, "navigation"), ("search", set(), "search"), ("main", {"main"}, "main"),
             ("aside", {"aside"}, "complementary"), ("footer", {"footer"}, "contentinfo"), ("region", set(), "region")]
MOUNT_IDS = {"root", "app", "__next", "___gatsby", "svelte", "__nuxt"}

IMPLEMENTED = ["alt_missing", "alt_link_missing", "alt_spacer_missing", "alt_input_missing", "alt_area_missing", "alt_map_missing",
               "label_missing", "label_empty", "label_multiple", "aria_reference_broken", "aria_menu_broken", "title_invalid", "language_missing",
               "meta_refresh", "heading_empty", "button_empty", "link_empty", "link_skip_broken", "th_empty", "blink", "marquee", "contrast",
               "alt_suspicious", "alt_redundant", "alt_duplicate", "alt_long", "longdesc", "image_title", "label_orphaned", "label_title",
               "select_missing_label", "fieldset_missing", "legend_missing", "heading_missing", "h1_missing", "region_missing", "heading_skipped",
               "table_layout", "link_internal_broken", "link_suspicious", "link_redundant", "link_word", "link_excel", "link_powerpoint",
               "link_pdf", "link_document", "audio_video", "html5_video_audio", "youtube_video", "flash", "applet", "plugin", "noscript",
               "event_handler", "javascript_jumpmenu", "accesskey", "tabindex", "text_small", "text_justified", "underline", "title_redundant",
               "alt", "alt_null", "alt_spacer", "alt_link", "alt_input", "alt_map", "alt_area", "figure", "label", "fieldset", "link_skip",
               "link_skip_target", "lang", "h1", "h2", "h3", "h4", "h5", "h6", "ol", "ul", "dl", "header", "nav", "search", "main", "aside",
               "footer", "region", "table_data", "table_caption", "th", "th_col", "th_row", "iframe", "aria", "aria_label", "aria_describedby",
               "aria_live_region", "aria_menu", "aria_button", "aria_expanded", "aria_haspopup", "aria_tabindex", "aria_hidden"]


class Project:
    """Facts gathered from every scanned file, so a reference in one file can resolve to an element in another."""

    def __init__(self):
        self.ids, self.label_for, self.name_attrs = set(), set(), set()

    def collect(self, root):
        for e in root.walk():
            if e.id:
                self.ids.add(e.id)
            n = static(e.attrs.get("name"))
            if n:
                self.name_attrs.add(n)
            if e.tag == "label" and static(e.attrs.get("for")):
                self.label_for.add(e.attrs["for"])


def _txt(el):
    return re.sub(r"\s+", " ", " ".join(c for c in el.children if isinstance(c, str))).strip()


def info(el, skip_img=False):
    """(visible static text of el and its descendants, whether some content is only known at runtime)."""
    text, unk = [], el.dyn or el.spread

    def walk(n):
        nonlocal unk
        for c in n.children:
            if isinstance(c, str):
                text.append(c)
                continue
            if c.comp or c.spread or c.dyn:
                unk = True
            if c.tag in ("script", "style"):
                continue
            if c.tag == "img" or (c.tag == "input" and static(c.attrs.get("type")) == "image"):
                alt = c.attrs.get("alt")
                if alt is not None and DYN in alt:
                    unk = unk or not skip_img
                elif alt and not skip_img:
                    text.append(alt)
                if c.attrs.get("aria-label") and not skip_img:
                    text.append(c.attrs["aria-label"])
            else:
                walk(c)

    walk(el)
    return re.sub(r"\s+", " ", " ".join(text)).strip(), unk


def name_state(el):
    """'named', 'empty' or 'unknown' for the accessible name of el."""
    if (el.attrs.get("aria-labelledby") or "").strip():
        return "named"
    al = el.attrs.get("aria-label")
    if al is not None and (DYN in al or al.strip()):
        return "named"
    t, unk = info(el)
    if t:
        return "named"
    return "unknown" if unk else "empty"


def check_file(root, styles_pool, ext, is_html_like, project, display_text=""):
    """Returns (findings, meta). findings: [(category, rule id, element or None, extra dict)]."""
    out = []
    els = list(root.walk())
    add = lambda cat, rid, el, **x: out.append((cat, rid, el, x))
    tags = {}
    for e in els:
        tags.setdefault(e.tag, []).append(e)
    T = lambda *names: [e for n in names for e in tags.get(n, [])]
    local_ids = {e.id for e in els if e.id}
    dyn_ids = any(DYN in e.attrs.get("id", "") for e in els)
    has_comp = any(e.comp for e in els)
    htmls = T("html")
    is_doc = bool(htmls)
    styler = Styler(styles_pool[0], styles_pool[1], is_doc)
    exists = lambda i: i in local_ids or i in project.ids or i in project.name_attrs
    maybe_unresolvable = dyn_ids

    # ---------- document level
    if is_doc:
        h = htmls[0]
        lang = h.attrs.get("lang")
        if lang is None and not h.spread:
            add("error", "language_missing", h)
        elif lang is not None and DYN not in lang:
            if not re.fullmatch(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*", lang.strip()):
                add("error", "language_missing", h, note=f"invalid lang={lang}")
            else:
                add("feature", "lang", h)
        elif lang is not None:
            add("feature", "lang", h)
        titles = [e for e in T("title") if not e.closest("svg")]
        if titles:
            tt, unk = info(titles[0])
            if not unk and (not tt or GENERIC_TITLE.match(tt)):
                add("error", "title_invalid", titles[0], note=f'title="{tt}"')
        elif is_html_like and T("head") and not has_comp and not any(e.dyn for e in T("head")):
            add("error", "title_invalid", T("head")[0], note="no <title> element")
    for e in els:
        if e.tag != "html" and "lang" in e.attrs:
            add("feature", "lang", e)
    for e in T("meta"):
        if (static(e.attrs.get("http-equiv")) or "").lower() == "refresh":
            add("error", "meta_refresh", e)
    for e in T("blink"):
        add("error", "blink", e)
    for e in T("marquee"):
        add("error", "marquee", e)
    for e in T("noscript"):
        add("alert", "noscript", e)

    # ---------- images
    def link_text(a):
        return info(a, skip_img=True)

    for im in T("img"):
        a = im.closest("a")
        a = a if a is not None and "href" in a.attrs else None
        alt = im.attrs.get("alt")
        aria = im.attrs.get("aria-label", "").strip() or ("x" if (im.attrs.get("aria-labelledby") or "").strip() else "")
        w, h = static(im.attrs.get("width")), static(im.attrs.get("height"))
        spacer = any(v and re.fullmatch(r"[0-3](px)?", v.strip()) for v in (w, h))
        if "usemap" in im.attrs:
            add("feature", "alt_map", im) if alt is not None else add("error", "alt_map_missing", im)
        if alt is None and not aria:
            if im.spread:
                continue
            lt, lunk = link_text(a) if a is not None else ("", False)
            if a is not None and not lt and not lunk:
                add("error", "alt_link_missing", im)
            elif spacer:
                add("error", "alt_spacer_missing", im)
            else:
                add("error", "alt_missing", im)
            if "title" in im.attrs:
                add("alert", "image_title", im)
        elif alt is not None and DYN in alt:
            add("feature", "alt_link" if a is not None else "alt", im)
        elif alt is not None and alt.strip() == "" and not aria:
            lt, lunk = link_text(a) if a is not None else ("", False)
            if a is not None and not lt and not lunk:
                add("error", "alt_link_missing", im)
            else:
                add("feature", "alt_spacer" if spacer else "alt_null", im)
        else:
            alt = (alt or aria).strip()
            flagged = False

            def flag(rid, **x):
                nonlocal flagged
                flagged = True
                add("alert", rid, im, **x)

            if SUSP_ALT.search(alt):
                flag("alt_suspicious", alt=alt)
            if len(alt) > 100:
                flag("alt_long", alt=alt[:60] + "...")
            siblings = im.parent.children if im.parent else []
            k = siblings.index(im) if im in siblings else -1
            near = []
            if a is not None:
                near.append(link_text(a)[0].lower())
            for s in (siblings[k - 1] if k > 0 else None, siblings[k + 1] if 0 <= k < len(siblings) - 1 else None):
                if isinstance(s, str):
                    near.append(s.strip().lower())
            if alt and alt.lower() in near:
                flag("alt_redundant", alt=alt)
            nx = next((s for s in siblings[k + 1:] if not (isinstance(s, str) and not s.strip())), None) if k >= 0 else None
            if alt and isinstance(nx, El) and nx.tag == "img" and (static(nx.attrs.get("alt")) or "").strip() == alt:
                flag("alt_duplicate", alt=alt)
            if static(im.attrs.get("title")) and im.attrs["title"].strip().lower() == alt.lower():
                add("alert", "title_redundant", im)
            if not flagged:
                add("feature", "alt_link" if a is not None else "alt", im, alt=alt)
        if "longdesc" in im.attrs:
            add("alert", "longdesc", im)
    for e in T("input"):
        if static(e.attrs.get("type")) == "image":
            ok = (e.attrs.get("alt") or "").strip() or (e.attrs.get("aria-label") or "").strip() or e.spread
            add("feature", "alt_input", e) if ok else add("error", "alt_input_missing", e)
    for e in T("area"):
        ok = (e.attrs.get("alt") or "").strip() or e.spread
        add("feature", "alt_area", e) if ok else add("error", "alt_area_missing", e)
    for e in T("figure"):
        add("feature", "figure", e)

    # ---------- forms
    labels = T("label")
    radio_groups = {}
    for c in T("input", "select", "textarea"):
        typ = (static(c.attrs.get("type")) or "text").lower() if c.tag == "input" else c.tag
        if typ in CONTROLS_SKIP:
            continue
        cid = c.attrs.get("id")
        wrap = c.closest("label")
        by_for = [l for l in labels if cid and static(cid) and l.attrs.get("for") == cid]
        allv = by_for + ([wrap] if wrap is not None and wrap not in by_for else [])
        aria = (c.attrs.get("aria-label") or "").strip() or (c.attrs.get("aria-labelledby") or "").strip()
        unknown = c.spread or (cid is not None and DYN in cid) or any(DYN in (l.attrs.get("for") or "") for l in labels)
        if len(allv) > 1:
            add("error", "label_multiple", c)
        if allv:
            if all(not (info(l)[0]) and not info(l)[1] for l in allv):
                add("error", "label_empty", c)
            else:
                add("feature", "label", c)
        elif aria:
            add("feature", "label", c)
        elif cid and static(cid) and cid in project.label_for:
            add("feature", "label", c)
        elif "title" in c.attrs:
            add("alert", "label_title", c)
        elif unknown or c.closest("label") is not None:
            pass
        elif c.tag == "select":
            add("alert", "select_missing_label", c)
        else:
            add("error", "label_missing", c)
        nm = static(c.attrs.get("name"))
        if typ in ("radio", "checkbox") and nm:
            radio_groups.setdefault((typ, nm), []).append(c)
    for l in labels:
        f = static(l.attrs.get("for"))
        if f and not any(e.id == f and e.tag in ("input", "select", "textarea", "button", "meter", "output", "progress") for e in els):
            if not dyn_ids and not has_comp and f not in project.ids:
                add("alert", "label_orphaned", l)
    for g in radio_groups.values():
        grouped = g[0].closest("fieldset") is not None or any((n.attrs.get("role") in ("group", "radiogroup")) for n in _ancestors(g[0]))
        if len(g) > 1 and not grouped:
            add("alert", "fieldset_missing", g[0])
    for f in T("fieldset"):
        add("feature", "fieldset", f)
        if not any(c.tag == "legend" for c in f.els()) and not f.spread and not has_comp:
            add("alert", "legend_missing", f)
    for e in T("select"):
        oc = static(e.attrs.get("onchange"))
        if oc and re.search(r"location|href|window\.open", oc, re.I):
            add("alert", "javascript_jumpmenu", e)

    # ---------- links and buttons
    links = [a for a in T("a") if "href" in a.attrs]
    prev = None
    for i, a in enumerate(links):
        st = name_state(a)
        n = info(a)[0]
        if st == "empty" and not any(d.tag in ("img", "input") for d in a.walk()):
            add("error", "link_empty", a)
        elif SUSP_LINK.match(n):
            add("alert", "link_suspicious", a, text=n)
        h = static(a.attrs.get("href")) or ""
        nxt = links[i + 1] if i + 1 < len(links) else None
        if nxt is not None and h and h == static(nxt.attrs.get("href")) and not SUSP_LINK.match(n) and not SUSP_LINK.match(info(nxt)[0]):
            for x in (a, nxt):
                if not any(o[2] is x and o[1] == "link_redundant" for o in out):
                    add("alert", "link_redundant", x)
        if re.search(r"\.docx?($|\?)", h, re.I):
            add("alert", "link_word", a)
        elif re.search(r"\.xlsx?($|\?)", h, re.I):
            add("alert", "link_excel", a)
        elif re.search(r"\.pptx?($|\?)", h, re.I):
            add("alert", "link_powerpoint", a)
        elif re.search(r"\.pdf($|\?)", h, re.I):
            add("alert", "link_pdf", a)
        elif re.search(r"\.(zip|rtf|odt|txt|csv)($|\?)", h, re.I):
            add("alert", "link_document", a)
        if re.search(r"youtube\.com|youtu\.be", h):
            add("alert", "youtube_video", a)
        if re.search(r"\.(mp3|mp4|wav|mov|avi|wmv|mpg|swf)($|\?)", h, re.I):
            add("alert", "audio_video", a)
        if h.startswith("#") and len(h) > 1 and "/" not in h and not h.startswith("#!"):
            if not exists(h[1:]) and not maybe_unresolvable and not has_comp:
                add("alert", "link_internal_broken", a, target=h)
    for a in links[:5]:
        h = static(a.attrs.get("href")) or ""
        if h.startswith("#") and len(h) > 1 and re.search(r"skip|jump|main|content", info(a)[0], re.I):
            add("feature", "link_skip", a)
            tgt = next((e for e in els if e.id == h[1:]), None)
            if tgt is not None:
                add("feature", "link_skip_target", tgt)
            elif not exists(h[1:]) and is_doc and not maybe_unresolvable:
                add("error", "link_skip_broken", a)
    for b in T("button", "input"):
        if b.tag == "input":
            typ = static(b.attrs.get("type")) or ""
            if typ not in ("button", "submit", "reset"):
                continue
            v = b.attrs.get("value")
            ok = (v is not None and (DYN in v or v.strip())) or (b.attrs.get("aria-label") or "").strip() or typ in ("submit", "reset") or b.spread
            if not ok:
                add("error", "button_empty", b)
        elif name_state(b) == "empty":
            add("error", "button_empty", b)

    # ---------- headings, landmarks, lists, tables
    heads = [e for e in els if re.fullmatch(r"h[1-6]", e.tag) or e.attrs.get("role") == "heading"]
    prev_lv = 0
    for h in heads:
        lv = int(h.tag[1]) if re.fullmatch(r"h[1-6]", h.tag) else int(static(h.attrs.get("aria-level")) or 2)
        add("structure", f"h{min(max(lv, 1), 6)}", h)
        if name_state(h) == "empty":
            add("error", "heading_empty", h)
        if prev_lv and lv > prev_lv + 1:
            add("alert", "heading_skipped", h, **{"from": f"h{prev_lv}", "to": f"h{lv}"})
        prev_lv = lv
    lm = 0
    for rid, tagset, role in LANDMARKS:
        for e in els:
            if (e.tag in tagset and not (e.tag in ("header", "footer") and e.closest("article", "section", "main", "aside", "nav"))) or e.attrs.get("role") == role:
                add("structure", rid, e)
                lm += 1
    whole_page = is_doc and is_html_like and not has_comp and not any(e.dyn for e in T("body"))
    mount_only = any(e.id in MOUNT_IDS and not e.children for e in els)
    if whole_page and not mount_only:
        if not heads:
            add("alert", "heading_missing", T("body")[0] if T("body") else htmls[0])
        elif not any(h.tag == "h1" or h.attrs.get("aria-level") == "1" for h in heads):
            add("alert", "h1_missing", T("body")[0] if T("body") else htmls[0])
        if not lm:
            add("alert", "region_missing", T("body")[0] if T("body") else htmls[0])
    for t in ("ol", "ul", "dl", "iframe"):
        for e in T(t):
            add("structure", t, e)
    for t in T("table"):
        descendants = list(t.walk())
        has_th = any(d.tag == "th" for d in descendants)
        has_cap = any(d.tag == "caption" for d in descendants)
        unknown_body = any(d.comp or d.dyn for d in descendants) or t.dyn
        if t.attrs.get("role") in ("presentation", "none") or (not has_th and not has_cap and "summary" not in t.attrs and not unknown_body):
            add("alert", "table_layout", t)
        else:
            add("structure", "table_data", t)
            if has_cap:
                add("structure", "table_caption", t)
    for th in T("th"):
        add("structure", "th", th)
        sc = static(th.attrs.get("scope"))
        if sc == "col":
            add("structure", "th_col", th)
        elif sc == "row":
            add("structure", "th_row", th)
        if name_state(th) == "empty":
            add("error", "th_empty", th)

    # ---------- attributes and embedded media
    for e in els:
        if "accesskey" in e.attrs:
            add("alert", "accesskey", e)
        if "tabindex" in e.attrs:
            v = static(e.attrs["tabindex"])
            if v is not None:
                add("alert", "tabindex", e) if re.fullmatch(r"[1-9]\d*", v.strip()) else add("aria", "aria_tabindex", e)
        if any(k in e.attrs for k in MOUSE_EVENTS):
            add("alert", "event_handler", e)
        if "title" in e.attrs and e.tag != "img" and static(e.attrs["title"]):
            t = e.attrs["title"].strip().lower()
            if t and info(e)[0].lower() == t:
                add("alert", "title_redundant", e)
    for e in T("video", "audio"):
        add("alert", "html5_video_audio", e)
    for e in T("iframe"):
        if re.search(r"youtube|youtu\.be", static(e.attrs.get("src")) or ""):
            add("alert", "youtube_video", e)
    for e in T("object", "embed"):
        flash = re.search(r"flash|swf", e.raw, re.I)
        add("alert", "flash" if flash else "plugin", e)
    for e in T("applet"):
        add("alert", "applet", e)

    # ---------- ARIA
    for e in els:
        if e.comp:
            continue
        ar = {k: v for k, v in e.attrs.items() if k == "role" or k.startswith("aria-")}
        if not ar:
            continue
        role = static(e.attrs.get("role")) or ""
        add("aria", "aria", e)
        if "aria-label" in ar or "aria-labelledby" in ar:
            add("aria", "aria_label", e)
        if "aria-describedby" in ar:
            add("aria", "aria_describedby", e)
        if "aria-expanded" in ar:
            add("aria", "aria_expanded", e)
        if "aria-haspopup" in ar:
            add("aria", "aria_haspopup", e)
        if static(ar.get("aria-hidden")) == "true":
            add("aria", "aria_hidden", e)
        if role == "button":
            add("aria", "aria_button", e)
        if role in ("alert", "status", "log") or "aria-live" in ar:
            add("aria", "aria_live_region", e)
        if role in ("menu", "menubar"):
            add("aria", "aria_menu", e)
            if not any(str(d.attrs.get("role", "")).startswith("menuitem") for d in e.walk()) and not any(d.comp or d.dyn for d in e.walk()) and not e.dyn:
                add("error", "aria_menu_broken", e)
        for at in ("aria-labelledby", "aria-describedby"):
            v = static(ar.get(at))
            if v and v.split() and not any(exists(i) for i in v.split()) and not maybe_unresolvable:
                add("error", "aria_reference_broken", e, attr=at)

    # ---------- text style alerts and contrast (resolved from CSS in source)
    undetermined = checked = 0
    for e in els:
        if e.comp or e.tag in NOT_TEXT or e.closest("script", "style", "noscript", "option", "svg"):
            continue
        txt = _txt(e)
        if not txt and not e.dyn:
            continue
        if styler.hidden(e):
            continue
        fs = styler.fs(e)
        if fs != UNK and fs < 10:
            add("alert", "text_small", e, size=f"{fs:g}px")
        if txt and len(txt) > 200 and styler.inherited(e, "text-align") == "justify" and not styler.unknown_chain(e):
            add("alert", "text_justified", e)
        td = (styler.cs(e).get("text-decoration") or styler.cs(e).get("text-decoration-line") or "").lower()
        if ("underline" in td or e.tag == "u") and not e.closest("a") and "dotted" not in td:
            add("alert", "underline", e)
        fg, bg, fw = styler.fg(e), styler.bg(e), styler.fw(e)
        if styler.unknown_chain(e) or fs == UNK or fw == UNK or fg == UNK or bg == UNK or (fg == "none" and not is_doc):
            undetermined += 1
            continue
        if fg == "none":
            fg = (0, 0, 0, 1.0)
        op = styler.opacity(e)
        a = fg[3] * op
        eff = tuple(fg[i] * a + bg[i] * (1 - a) for i in range(3))
        r = ratio(eff, bg)
        large = fs >= 24 or (fs >= 18.66 and fw >= 700)
        need = 3 if large else 4.5
        checked += 1
        if r < need:
            add("contrast", "contrast", e, ratio=round(r, 2), min=need, fg=_hex(eff), bg=_hex(bg), size=f"{fs:g}px", text=txt[:40])
    return out, {"checkedForContrast": checked, "contrastUndetermined": undetermined, "elements": len(els), "isDocument": is_doc}


def _ancestors(el):
    n = el.parent
    while n is not None:
        yield n
        n = n.parent


def _hex(c):
    return "#%02x%02x%02x" % tuple(int(round(v)) for v in c[:3])
