"""Static CSS resolution for source scans: parses stylesheets, matches simple selectors against the parsed element tree and
computes colour, size and weight. Anything that cannot be resolved from source (runtime values, unsupported selectors,
utility-class frameworks) yields UNK so callers skip the check instead of guessing."""
import colorsys
import re

from source_parser import DYN, El

UNK = "?"

NAMED = {"black": (0, 0, 0), "white": (255, 255, 255), "red": (255, 0, 0), "green": (0, 128, 0), "blue": (0, 0, 255),
         "yellow": (255, 255, 0), "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192), "orange": (255, 165, 0),
         "purple": (128, 0, 128), "navy": (0, 0, 128), "teal": (0, 128, 128), "maroon": (128, 0, 0), "lime": (0, 255, 0),
         "aqua": (0, 255, 255), "cyan": (0, 255, 255), "fuchsia": (255, 0, 255), "magenta": (255, 0, 255), "olive": (128, 128, 0),
         "pink": (255, 192, 203), "brown": (165, 42, 42), "gold": (255, 215, 0), "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211),
         "darkgray": (169, 169, 169), "darkgrey": (169, 169, 169), "dimgray": (105, 105, 105), "whitesmoke": (245, 245, 245),
         "lightblue": (173, 216, 230), "darkblue": (0, 0, 139), "darkred": (139, 0, 0), "darkgreen": (0, 100, 0), "lightgreen": (144, 238, 144),
         "crimson": (220, 20, 60), "coral": (255, 127, 80), "tomato": (255, 99, 71), "salmon": (250, 128, 114), "ivory": (255, 255, 240),
         "beige": (245, 245, 220), "khaki": (240, 230, 140), "violet": (238, 130, 238), "indigo": (75, 0, 130), "skyblue": (135, 206, 235),
         "steelblue": (70, 130, 180), "slategray": (112, 128, 144), "gainsboro": (220, 220, 220), "tan": (210, 180, 140)}
KEYWORD_PX = {"xx-small": 9, "x-small": 10, "small": 13, "medium": 16, "large": 18, "x-large": 24, "xx-large": 32}
UA_FS = {"h1": 2, "h2": 1.5, "h3": 1.17, "h5": 0.83, "h6": 0.67, "small": 0.83, "sub": 0.83, "sup": 0.83}
UA_BOLD = {"b", "strong", "th", "h1", "h2", "h3", "h4", "h5", "h6"}
NOT_TEXT = {"script", "style", "noscript", "option", "template", "title", "head", "html"}


def strip_comments(t):
    return re.sub(r"/\*.*?\*/", "", t, flags=re.S)


def parse_decls(text):
    """'a:b;c:d !important' -> [(prop, value, important)]. Skips anything it cannot split."""
    out = []
    for part in re.findall(r"(?:[^;(]|\([^)]*\))+", text):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        v = v.strip()
        imp = bool(re.search(r"!\s*important\s*$", v, re.I))
        v = re.sub(r"\s*!\s*important\s*$", "", v, flags=re.I).strip()
        out.append((k.strip().lower(), v, imp))
    return out


def resolve_vars(v, vars_):
    for _ in range(6):
        if "var(" not in v:
            return v
        def sub(m):
            got = vars_.get(m[1])
            return got if got is not None else (m[2] if m[2] is not None else "\x01")
        v = re.sub(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*))?\)", sub, v)
        if "\x01" in v:
            return None
    return v if "var(" not in v else None


def parse_color(v):
    """Returns (r, g, b, a), or UNK."""
    v = v.strip().lower()
    m = re.fullmatch(r"#([0-9a-f]{3,8})", v)
    if m:
        h = m[1]
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) == 6:
            h += "ff"
        if len(h) == 8:
            return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4)) + (int(h[6:8], 16) / 255,)
        return UNK
    m = re.fullmatch(r"(rgba?|hsla?)\(([^)]*)\)", v)
    if m:
        parts = [x for x in re.split(r"[,\s/]+", m[2].strip()) if x]
        try:
            alpha = 1.0
            if len(parts) > 3:
                alpha = float(parts[3][:-1]) / 100 if parts[3].endswith("%") else float(parts[3])
            if m[1].startswith("rgb"):
                rgb = [float(p[:-1]) * 2.55 if p.endswith("%") else float(p) for p in parts[:3]]
                return (*rgb, alpha)
            h = float(parts[0].replace("deg", "")) / 360
            s, l = float(parts[1].rstrip("%")) / 100, float(parts[2].rstrip("%")) / 100
            r, g, b = colorsys.hls_to_rgb(h % 1, l, s)
            return (r * 255, g * 255, b * 255, alpha)
        except (ValueError, IndexError):
            return UNK
    if v == "transparent":
        return (0, 0, 0, 0.0)
    if v in NAMED:
        return NAMED[v] + (1.0,)
    return UNK


def parse_background(v):
    """Colour of a `background` shorthand; UNK for images and gradients."""
    if re.search(r"gradient\(|url\(", v, re.I):
        return UNK
    m = re.search(r"#[0-9a-fA-F]{3,8}\b|(?:rgba?|hsla?)\([^)]*\)|[A-Za-z]+", v)
    for tok in re.findall(r"#[0-9a-fA-F]{3,8}\b|(?:rgba?|hsla?)\([^)]*\)|[A-Za-z-]+", v):
        c = parse_color(tok)
        if c != UNK:
            return c
    return (0, 0, 0, 0.0) if m is None or v.strip().lower() in ("none", "transparent") else UNK


def parse_size(v, parent_px):
    v = v.strip().lower()
    if v in KEYWORD_PX:
        return float(KEYWORD_PX[v])
    m = re.fullmatch(r"(-?[\d.]+)(px|rem|em|pt|%)?", v)
    if not m:
        return UNK
    x, u = float(m[1]), m[2] or "px"
    return {"px": x, "rem": x * 16, "pt": x * 4 / 3, "em": x * parent_px, "%": x * parent_px / 100}[u]


# ---------------------------------------------------------------- selectors and rules
def parse_selector(sel):
    sel = re.sub(r":root\b", "html", sel.strip())
    if not sel or re.search(r"[:+~|@\\]", sel):
        return None
    parts, comb = [], None
    for tok in re.findall(r">|[^\s>]+", sel):
        if tok == ">":
            comb = ">"
            continue
        m = re.match(r"(\*|[A-Za-z][\w-]*)?", tok)
        rest = tok[m.end():]
        cls = re.findall(r"\.([\w-]+)", rest)
        ids = re.findall(r"#([\w-]+)", rest)
        attrs = re.findall(r"\[([\w-]+)(?:=(\"[^\"]*\"|'[^']*'|[^\]]*))?\]", rest)
        if re.sub(r"\.[\w-]+|#[\w-]+|\[[^\]]*\]", "", rest):
            return None
        parts.append((comb or " " if parts else None, (m[1] or None, cls, ids[0] if ids else None, [(a, (b or "").strip("\"'")) for a, b in attrs])))
        comb = None
    if not parts:
        return None
    ids_n = sum(1 for _, c in parts if c[2])
    cls_n = sum(len(c[1]) + len(c[3]) for _, c in parts)
    tag_n = sum(1 for _, c in parts if c[0] and c[0] != "*")
    return parts, (ids_n, cls_n, tag_n)


class Rule:
    __slots__ = ("parts", "spec", "order", "decls")

    def __init__(self, parts, spec, order, decls):
        self.parts, self.spec, self.order, self.decls = parts, spec, order, decls


def parse_css(text, base_order=0):
    """Returns (rules, custom properties, @import urls). Media queries and nested (SCSS) blocks are ignored."""
    text = strip_comments(text)
    imports = re.findall(r"@import\s+(?:url\()?\s*['\"]?([^'\")\s;]+\.css)", text)
    rules, vars_ = [], {}

    def block(s, order):
        i, n = 0, len(s)
        while i < n:
            j = s.find("{", i)
            if j < 0:
                break
            prelude = s[i:j].split(";")[-1].strip()
            depth, k = 0, j
            while k < n:
                if s[k] == "{":
                    depth += 1
                elif s[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            body = s[j + 1:k]
            i = k + 1
            if prelude.startswith("@"):
                if re.match(r"@(layer|supports)\b", prelude) or re.match(r"@media\s+(all|screen)\s*$", prelude):
                    block(body, order)
                continue
            if "{" in body:
                continue
            decls = parse_decls(body)
            for sel in prelude.split(","):
                ps = parse_selector(sel)
                if ps is None:
                    continue
                parts, spec = ps
                if len(parts) == 1 and parts[0][1][0] in ("html", "body", "*") and not parts[0][1][1] and not parts[0][1][2]:
                    for p, v, _ in decls:
                        if p.startswith("--"):
                            vars_[p] = v
                rules.append(Rule(parts, spec, base_order + len(rules), decls))

    block(text, base_order)
    return rules, vars_, imports


def _tailwind(classes):
    """A few Tailwind utilities that carry literal values. The default palette is not resolved."""
    d = []
    for c in classes:
        m = re.fullmatch(r"(text|bg)-\[(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))\]", c)
        if m:
            d.append(("color" if m[1] == "text" else "background-color", m[2], False))
        m = re.fullmatch(r"text-\[(\d+(?:\.\d+)?)px\]", c)
        if m:
            d.append(("font-size", m[1] + "px", False))
        if c in ("text-white", "text-black", "bg-white", "bg-black"):
            d.append(("color" if c.startswith("text") else "background-color", c.split("-")[1], False))
        elif c == "underline":
            d.append(("text-decoration", "underline", False))
        elif c == "hidden":
            d.append(("display", "none", False))
        elif c == "font-bold":
            d.append(("font-weight", "700", False))
        elif c == "text-justify":
            d.append(("text-align", "justify", False))
    return d


class Styler:
    def __init__(self, rules, vars_, is_doc):
        self.vars, self.is_doc = vars_, is_doc
        self._memo = {}
        self.by_id, self.by_class, self.by_tag, self.universal = {}, {}, {}, []
        for r in rules:
            tag, cls, ident, attrs = r.parts[-1][1]
            if ident:
                self.by_id.setdefault(ident, []).append(r)
            elif cls:
                self.by_class.setdefault(cls[0], []).append(r)
            elif tag and tag != "*":
                self.by_tag.setdefault(tag, []).append(r)
            else:
                self.universal.append(r)
        self.html = El("html")
        self.body = El("body", parent=self.html)
        self.html.children.append(self.body)

    def parent(self, el):
        p = el.parent
        if p is not None and p.tag != "#root":
            return p
        if self.is_doc or el is self.html:
            return None
        return self.body if el is not self.body else self.html

    def _match_compound(self, el, c):
        tag, cls, ident, attrs = c
        if tag and tag != "*" and tag != el.tag:
            return False
        if ident and ident != el.id:
            return False
        if cls and not set(cls) <= el.classes:
            return False
        for a, v in attrs:
            ev = el.attrs.get(a)
            if ev is None or (v and ev != v):
                return False
        return True

    def _match(self, el, parts, i):
        key = (id(el), id(parts), i)
        hit = self._memo.get(key)
        if hit is None:
            hit = self._memo[key] = self._match_uncached(el, parts, i)
        return hit

    def _match_uncached(self, el, parts, i):
        comb, c = parts[i]
        if not self._match_compound(el, c):
            return False
        if i == 0:
            return True
        p = self.parent(el)
        if parts[i][0] == ">":
            return p is not None and self._match(p, parts, i - 1)
        while p is not None:
            if self._match(p, parts, i - 1):
                return True
            p = self.parent(p)
        return False

    def cs(self, el):
        """Cascaded declarations of one element: {prop: value}."""
        if el._cs is not None:
            return el._cs
        cand = list(self.universal) + self.by_tag.get(el.tag, [])
        for c in el.classes:
            cand += self.by_class.get(c, [])
        if el.id:
            cand += self.by_id.get(el.id, [])
        hits = []
        for r in cand:
            if self._match(el, r.parts, len(r.parts) - 1):
                for p, v, imp in r.decls:
                    hits.append(((imp, 0, r.spec, r.order), p, v))
        for p, v, imp in _tailwind(el.classes):
            hits.append(((imp, 0, (0, 1, 0), 10 ** 9), p, v))
        st = el.attrs.get("style")
        if st and DYN not in st:
            for p, v, imp in parse_decls(st):
                hits.append(((imp, 1, (0, 0, 0), 0), p, v))
        hits.sort(key=lambda h: h[0])
        out = {}
        for _, p, v in hits:
            if p.startswith("--"):
                continue
            rv = resolve_vars(v, self.vars)
            out[p] = UNK if rv is None else rv
        el._cs = out
        return out

    def unknown_chain(self, el):
        n = el
        while n is not None:
            if n.style_unknown:
                return True
            n = self.parent(n)
        return False

    def fg(self, el):
        if el._fg is not None:
            return el._fg
        p = self.parent(el)
        up = self.fg(p) if p is not None else None
        v = self.cs(el).get("color")
        if v is None or v.lower() in ("inherit", "unset"):
            r = up
        else:
            r = parse_color(v)
        el._fg = r if r is not None else "none"
        return el._fg

    def bg(self, el):
        """Effective opaque background (r, g, b), or UNK when it cannot be known from source."""
        stack, n = [], el
        while n is not None:
            if n.style_unknown:
                return UNK
            d = self.cs(n)
            if d.get("background-image", "none").lower() not in ("none", "initial"):
                return UNK
            if "background-color" in d:
                c = parse_color(d["background-color"])
            elif "background" in d:
                c = parse_background(d["background"])
            else:
                c = None
            if c == UNK:
                return UNK
            if c is not None and c[3] > 0:
                stack.append(c)
                if c[3] >= 1:
                    break
            n = self.parent(n)
        if not stack or stack[-1][3] < 1:
            if not self.is_doc:
                return UNK                      # a component's background usually comes from a parent in another file
            stack.append((255, 255, 255, 1.0))
        base = stack[-1]
        for f in reversed(stack[:-1]):
            base = tuple(f[i] * f[3] + base[i] * (1 - f[3]) for i in range(3)) + (1.0,)
        return base[:3]

    def fs(self, el):
        if el._fs is not None:
            return el._fs
        p = self.parent(el)
        up = self.fs(p) if p is not None else 16.0
        v = self.cs(el).get("font-size")
        if self.unknown_chain(el) or up == UNK:
            r = UNK
        elif v is None or v.lower() == "inherit":
            r = up * UA_FS.get(el.tag, 1)
        else:
            r = parse_size(v, up)
        el._fs = r
        return r

    def fw(self, el):
        if el._fw is not None:
            return el._fw
        p = self.parent(el)
        up = self.fw(p) if p is not None else 400
        v = self.cs(el).get("font-weight")
        if v is None:
            r = 700 if el.tag in UA_BOLD else up
        else:
            v = v.lower()
            r = {"normal": 400, "bold": 700, "bolder": 700, "lighter": 300}.get(v) or (int(v) if v.isdigit() else (up if v == "inherit" else UNK))
        el._fw = r
        return r

    def inherited(self, el, prop):
        n = el
        while n is not None:
            v = self.cs(n).get(prop)
            if v is not None and v.lower() != "inherit":
                return v.lower()
            n = self.parent(n)
        return None

    def hidden(self, el):
        n = el
        while n is not None:
            if "hidden" in n.attrs or self.cs(n).get("display", "").lower() == "none":
                return True
            n = self.parent(n)
        return False

    def opacity(self, el):
        o, n = 1.0, el
        while n is not None:
            v = self.cs(n).get("opacity")
            if v:
                try:
                    o *= float(v)
                except ValueError:
                    pass
            n = self.parent(n)
        return o


def lum(c):
    f = lambda v: (v / 255 / 12.92) if v / 255 <= 0.03928 else ((v / 255 + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])


def ratio(a, b):
    l1, l2 = lum(a), lum(b)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
