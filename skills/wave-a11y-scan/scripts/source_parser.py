"""Tolerant markup parser for source files: HTML, templates (Jinja, Twig, Blade, ERB, PHP, Handlebars, Liquid, Razor),
JSX/TSX, Vue, Svelte and Astro. It builds an element tree with line numbers. Values that are only known at runtime
(expressions, template tags) are marked with DYN so checks can skip them instead of guessing."""
import bisect
import re

DYN = "\x00"

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
RAW = {"script", "style"}
AUTOCLOSE = {"li": {"li"}, "p": {"p"}, "td": {"td", "th"}, "th": {"td", "th"}, "tr": {"tr", "td", "th"}, "option": {"option"},
             "dt": {"dt", "dd"}, "dd": {"dt", "dd"}, "thead": {"tbody", "tfoot"}, "tbody": {"thead", "tbody"}}
JS_EXT = {".jsx", ".tsx", ".js", ".mjs", ".cjs"}
BRACE_EXT = JS_EXT | {".svelte", ".astro"}
ALIASES = {"Image": "img", "Img": "img", "NextImage": "img", "Link": "a", "NavLink": "a", "RouterLink": "a", "NuxtLink": "a",
           "router-link": "a", "nuxt-link": "a"}

TAG_RE = re.compile(r"<(/?)([A-Za-z][\w.:-]*)")
NAME_RE = re.compile(r"[^\s=/>\"'{]+")
TEMPLATE_RE = re.compile(r"<\?.*?\?>|<%.*?%>|\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.S)


class El:
    __slots__ = ("tag", "attrs", "line", "parent", "children", "comp", "spread", "dyn", "depth", "raw", "classes", "id",
                 "style_unknown", "icon", "_cs", "_fg", "_fs", "_fw", "_bg")

    def __init__(self, tag, attrs=None, line=0, parent=None, comp=False, spread=False, raw=""):
        self.tag, self.attrs, self.line, self.parent = tag, attrs or {}, line, parent
        self.children, self.comp, self.spread, self.raw = [], comp, spread, raw
        self.dyn, self.depth = False, 0
        self.classes, self.id, self.style_unknown, self.icon = set(), None, False, False
        self._cs = self._fg = self._fs = self._fw = self._bg = None

    def els(self):
        return [c for c in self.children if isinstance(c, El)]

    def walk(self):
        for c in self.children:
            if isinstance(c, El):
                yield c
                yield from c.walk()

    def closest(self, *tags):
        n = self.parent
        while n is not None:
            if n.tag in tags:
                return n
            n = n.parent
        return None

    def own_text(self):
        return " ".join(c for c in self.children if isinstance(c, str)).strip()


def static(v):
    """The attribute value if it is fixed in the source, else None."""
    return None if v is None or DYN in v else v


def _norm_attr(name, ext):
    """Returns (normalised name, forced_dynamic)."""
    dyn = False
    n = name
    if n.startswith("v-bind:") or (n.startswith(":") and ext == ".vue"):
        n, dyn = n[7:] if n.startswith("v-bind:") else n[1:], True
    elif n.startswith("[") and n.endswith("]"):
        n, dyn = n[1:-1], True
        if n.startswith("attr."):
            n = n[5:]
        elif n.startswith("class."):
            n = "class"
    elif n.startswith("@") or n.startswith("v-on:"):
        n = "on" + n.split(":", 1)[-1].lstrip("@")
    elif n.startswith("(") and n.endswith(")"):
        n = "on" + n[1:-1]
    if n == "className":
        n = "class"
    elif n == "htmlFor":
        n = "for"
    elif n == "httpEquiv":
        n = "http-equiv"
    elif not n.startswith(("aria-", "data-")):
        n = n.lower()
    return n, dyn


def _skip_braces(t, p):
    """t[p] == '{'. Returns the index after the matching '}' (string/template-literal aware)."""
    depth, n = 0, len(t)
    while p < n:
        c = t[p]
        if c in "\"'`":
            q = c
            p += 1
            while p < n and t[p] != q:
                p += 2 if t[p] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return p + 1
        p += 1
    return n


def _style_from_object(inner):
    """JSX style={{ color: '#aaa', fontSize: 9 }} to a CSS declaration string. Non-literal values become '?'."""
    out = []
    for k, v in re.findall(r"([A-Za-z]\w*)\s*:\s*((?:'[^']*'|\"[^\"]*\"|[^,]+))", inner):
        prop = re.sub(r"([A-Z])", lambda m: "-" + m[1].lower(), k)
        v = v.strip()
        lit = re.fullmatch(r"'([^']*)'|\"([^\"]*)\"", v)
        if lit:
            out.append(f"{prop}:{lit[1] if lit[1] is not None else lit[2]}")
        elif re.fullmatch(r"-?[\d.]+", v):
            out.append(f"{prop}:{v}{'px' if prop in ('font-size', 'width', 'height') else ''}")
        else:
            out.append(f"{prop}:?")
    return ";".join(out)


def _attr_value(t, p, name):
    """t[p] is the first char after '='. Returns (value, end index)."""
    n = len(t)
    if p >= n:
        return "", p
    c = t[p]
    if c in "\"'":
        e = t.find(c, p + 1)
        e = n if e < 0 else e
        return t[p + 1:e], e + 1
    if c == "{":
        e = _skip_braces(t, p)
        inner = t[p + 1:e - 1].strip()
        lit = re.fullmatch(r"\"([^\"\\]*)\"|'([^'\\]*)'|`([^`$\\]*)`", inner)
        if lit:
            return next(g for g in lit.groups() if g is not None), e
        if re.fullmatch(r"-?\d+(\.\d+)?|true|false", inner):
            return inner, e
        if name == "style" and inner.startswith("{") and inner.endswith("}"):
            return _style_from_object(inner[1:-1]), e
        return DYN, e
    m = re.match(r"[^\s>]+", t[p:])
    v = m[0] if m else ""
    if v.endswith("/") and t[p + len(v):p + len(v) + 1] == ">":
        v = v[:-1]
    return v, p + len(v)


ICON_PKG = re.compile(r"lucide-react|react-icons(/\w+)?|@heroicons/react(/[\w/-]+)?|@mui/icons-material(/[\w]+)?|@fortawesome/[\w-]+|@phosphor-icons/react|@tabler/icons-react|react-feather|@radix-ui/react-icons|@ant-design/icons|lucide-vue-next|lucide-svelte")


def icon_names(text):
    """Local names of components imported from icon libraries: they draw a glyph and carry no text."""
    names = set()
    for m in re.finditer(r"import\s+([^;]*?)\s+from\s+['\"]([^'\"]+)['\"]", text):
        if not ICON_PKG.fullmatch(m[2]):
            continue
        clause = m[1]
        for part in re.findall(r"\{([^}]*)\}", clause):
            for item in part.split(","):
                item = item.strip()
                if item:
                    names.add(re.split(r"\s+as\s+", item)[-1].strip())
        d = re.match(r"([A-Za-z_$][\w$]*)\s*(,|$)", clause)
        if d:
            names.add(d[1])
    return names


def _comp_info(raw_name, ext):
    """Returns (tag, is_component)."""
    brace = ext in BRACE_EXT or ext == ".vue"
    if raw_name in ALIASES and brace:
        return ALIASES[raw_name], False
    if brace and (raw_name[:1].isupper() or "." in raw_name or ":" in raw_name):
        if re.search(r"Label$", raw_name):
            return "label", False
        return raw_name, True
    low = raw_name.lower()
    if low in ALIASES:
        return ALIASES[low], False
    if "-" in low:
        return low, True
    return low, False


def parse(text, ext):
    """Returns (root El, styles [(css text, line)], line_of(offset))."""
    brace = ext in BRACE_EXT
    if ext == ".astro":
        text = re.sub(r"\A---.*?\n---", lambda m: re.sub(r"[^\n]", " ", m[0]), text, count=1, flags=re.S)
    if ext not in BRACE_EXT:
        text = TEMPLATE_RE.sub(lambda m: DYN + "\n" * m[0].count("\n"), text)
    starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    line_of = lambda off: bisect.bisect_right(starts, off)
    icons = icon_names(text) if ext in JS_EXT | {".vue", ".svelte", ".astro"} else set()
    root = El("#root")
    stack = [root]
    styles = []
    n, pos = len(text), 0

    def add_text(s):
        top = stack[-1]
        if top is root and ext in JS_EXT:
            return
        if not brace and DYN not in s:
            if s.strip():
                top.children.append(s)
            return
        buf = []
        for ch in s:
            if ch == "{" and brace:
                top.depth += 1
                top.dyn = True
            elif ch == "}" and brace:
                top.depth = max(top.depth - 1, 0)
            elif ch == DYN:
                top.dyn = True
                buf.append(" ")
            elif top.depth == 0:
                buf.append(ch)
        seg = "".join(buf)
        if seg.strip():
            top.children.append(seg)

    while pos < n:
        i = text.find("<", pos)
        if i < 0:
            add_text(text[pos:])
            break
        if text.startswith("<!--", i):
            add_text(text[pos:i])
            e = text.find("-->", i + 4)
            pos = n if e < 0 else e + 3
            continue
        m = TAG_RE.match(text, i)
        if not m or text.startswith("<!", i):
            if text.startswith("<!", i):
                add_text(text[pos:i])
                e = text.find(">", i)
                pos = n if e < 0 else e + 1
            else:
                add_text(text[pos:i + 1])
                pos = i + 1
            continue
        if ext in JS_EXT and not m[1] and i > 0 and not text[i - 1].isspace() and re.match(r"[\w$)\]]", text[i - 1]):
            add_text(text[pos:i + 1])            # TypeScript generic or comparison, not JSX
            pos = i + 1
            continue
        add_text(text[pos:i])
        closing, raw_name = m[1] == "/", m[2]
        p = m.end()
        if closing:
            e = text.find(">", p)
            pos = n if e < 0 else e + 1
            tag, _ = _comp_info(raw_name, ext)
            for k in range(len(stack) - 1, 0, -1):
                if stack[k].tag == tag or stack[k].tag == raw_name:
                    del stack[k:]
                    break
            continue
        attrs, spread, selfclose = {}, False, False
        while p < n:
            while p < n and text[p].isspace():
                p += 1
            if p >= n:
                break
            if text[p] == ">":
                p += 1
                break
            if text.startswith("/>", p):
                selfclose, p = True, p + 2
                break
            if text[p] == "/":
                p += 1
                continue
            if text[p] == "{":
                e = _skip_braces(text, p)
                inner = text[p + 1:e - 1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", inner):
                    attrs[_norm_attr(inner, ext)[0]] = DYN
                else:
                    spread = True
                p = e
                continue
            nm = NAME_RE.match(text, p)
            if not nm:
                p += 1
                continue
            name, p = nm[0], nm.end()
            q = p
            while q < n and text[q].isspace():
                q += 1
            if name.startswith(DYN) or name == "v-bind" or name == "...":
                spread = True
            if q < n and text[q] == "=":
                q += 1
                while q < n and text[q].isspace():
                    q += 1
                norm, forced = _norm_attr(name, ext)
                val, p = _attr_value(text, q, norm)
                if forced or name.startswith("v-"):
                    val = DYN
                if not name.startswith(DYN) and name != "v-bind":
                    attrs[norm] = val
            else:
                norm, forced = _norm_attr(name, ext)
                if not name.startswith(DYN):
                    attrs[norm] = DYN if forced else ""
        tag, comp = _comp_info(raw_name, ext)
        if tag == "a" and "href" not in attrs and "to" in attrs and raw_name != "a":
            attrs["href"] = attrs["to"]
        el = El(tag, attrs, line_of(i), None, comp, spread, re.sub(r"\s+", " ", text[i:p])[:160])
        el.icon = comp and raw_name in icons
        if "id" in attrs and DYN not in attrs["id"]:
            el.id = attrs["id"].strip() or None
        cls = attrs.get("class")
        if cls is not None:
            if DYN in cls:
                el.style_unknown = True
            else:
                el.classes = set(cls.split())
        if DYN in attrs.get("style", ""):
            el.style_unknown = True
        if tag in AUTOCLOSE and not comp:
            while len(stack) > 1 and stack[-1].tag in AUTOCLOSE[tag]:
                stack.pop()
        el.parent = stack[-1]
        stack[-1].children.append(el)
        if tag in RAW and not comp:
            m2 = re.compile(r"</\s*" + tag + r"\s*>", re.I).search(text, p)
            e = m2.start() if m2 else n
            if tag == "style":
                lang = (attrs.get("lang") or attrs.get("type") or "").lower()
                if lang in ("", "css", "text/css"):
                    styles.append((text[p:e], line_of(p)))
            pos = m2.end() if m2 else n
            continue
        pos = p
        if not selfclose and tag not in VOID:
            stack.append(el)
    return root, styles, line_of
