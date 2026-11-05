"""Multi-line statement joining and lightweight data-flow (taint) tracking.

Regex rules in rules.py see one *logical* line (a statement whose brackets span several physical lines is
joined), and this module adds source-to-sink tracking within a file:

  * Python  : real AST analysis. Request data (flask/django/fastapi style `request.*`, input(), sys.argv) is followed
              through assignments, f-strings, `%`, `+`, `.format()` and string methods into SQL, shell, eval, SSRF,
              path, deserialization, redirect and template sinks. Known sanitizers (int(), shlex.quote, secure_filename,
              os.path.basename, html.escape ...) stop the flow.
  * JS / TS : statement-level tracking with regexes (variables assigned from req.body/query/params, destructuring,
              template literals and concatenation) into the same sink classes.

It is intentionally intra-file and intra-function-ish: it does not follow calls into other modules. Every result is a
candidate that the auditor must still read and confirm.
"""
import ast
import re

CODE_TAGS = {"py", "js", "java", "cs", "go", "php", "rb"}
MAX_JOIN_LINES = 14
MAX_JOIN_CHARS = 4000


# ----------------------------------------------------------------------------- logical lines
def _scan_line(line, state, hash_c, slash_c):
    """Return bracket depth delta for one physical line, updating `state` (open triple-quote / backtick)."""
    delta = 0
    i, n = 0, len(line)
    q = None
    while i < n:
        c = line[i]
        if state["triple"]:
            j = line.find(state["triple"], i)
            if j < 0:
                return delta
            i = j + 3
            state["triple"] = None
            continue
        if state["tick"]:
            if c == "\\":
                i += 2
                continue
            if c == "`":
                state["tick"] = False
            i += 1
            continue
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if hash_c and c == "#":
            break
        if slash_c and c == "/" and line[i:i + 2] == "//":
            break
        if hash_c and line[i:i + 3] in ('"""', "'''"):
            state["triple"] = line[i:i + 3]
            i += 3
            continue
        if c in "\"'":
            q = c
        elif c == "`" and slash_c:
            state["tick"] = True
        elif c in "([{":
            delta += 1
        elif c in ")]}":
            delta -= 1
        i += 1
    return delta


BLOCK_OPEN = re.compile(r"(\)|=>|\b(?:else|try|finally|do))\s*\{\s*(?://.*|/\*.*)?$")   # `) {`, `=> {`, `else {`: a code block, not an object literal


def logical_lines(text, tags):
    """Yield (first_line_number, text) joining physical lines while brackets / template literals stay open."""
    hash_c = bool(tags & {"py", "rb", "php"})
    slash_c = bool(tags & {"js", "java", "cs", "go", "php"})
    state = {"triple": None, "tick": False}
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        first = lines[i]
        if len(first) > 2000:
            yield i + 1, first
            i += 1
            continue
        depth = _scan_line(first, state, hash_c, slash_c)
        buf = [first]
        j = i + 1
        block = slash_c and not state["tick"] and BLOCK_OPEN.search(first.rstrip()) is not None
        if block:
            depth = 0        # a callback/function body starts here: statements inside are separate logical lines
        while (depth > 0 or state["tick"]) and j < n and len(buf) < MAX_JOIN_LINES and len(lines[j]) <= 2000 and sum(map(len, buf)) < MAX_JOIN_CHARS:
            depth += _scan_line(lines[j], state, hash_c, slash_c)
            buf.append(lines[j])
            j += 1
            if slash_c and not state["tick"] and BLOCK_OPEN.search(buf[-1].rstrip()):
                depth = 0
                break
        if len(buf) > 1:
            if depth > 0 or state["tick"]:
                state["tick"] = False
            yield i + 1, " ".join(s.strip() for s in buf)
        else:
            yield i + 1, first
        i = j


# ----------------------------------------------------------------------------- Python (AST)
PY_REQUEST_ATTRS = {"args", "form", "json", "values", "GET", "POST", "data", "cookies", "headers", "files", "view_args",
                    "query_params", "path_params", "body", "get_json", "REQUEST", "META", "FILES"}
PY_SANITIZERS = {"int", "float", "bool", "len", "abs", "round", "quote", "escape", "secure_filename", "basename", "UUID",
                 "uuid4", "isdigit", "isalnum", "fspath_safe", "clean", "sanitize", "html_escape", "urlquote", "quote_plus",
                 "parameterize", "literal_eval", "Decimal"}
PY_PASSTHROUGH_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "title", "replace", "decode", "encode", "format", "join",
                          "get", "getlist", "pop", "split", "splitlines", "casefold", "capitalize", "swapcase", "zfill",
                          "removeprefix", "removesuffix", "items", "values", "keys", "copy", "read", "readline"}
PY_PASSTHROUGH_FUNCS = {"str", "bytes", "bytearray", "repr", "join", "format", "dict", "list", "tuple", "set", "sorted",
                        "unquote", "unquote_plus", "loads", "b64decode", "urlsafe_b64decode", "Path", "PurePath", "PosixPath"}

SQL_SINKS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "read_sql_table", "extra", "RawSQL",
             "mogrify", "execute_sql", "exec_driver_sql"}
CMD_OS = {"system", "popen", "popen2", "popen3", "spawnl", "spawnlp", "spawnv", "startfile"}
CMD_SUBPROCESS = {"call", "run", "Popen", "check_call", "check_output", "getoutput", "getstatusoutput"}
HTTP_FUNCS = {"get", "post", "put", "delete", "patch", "head", "options", "request", "urlopen", "urlretrieve", "stream"}
HTTP_ROOTS = {"requests", "httpx", "urllib", "aiohttp", "urllib3", "session", "client", "http", "urlopen", "s"}
PATH_FUNCS = {"open", "send_file", "send_from_directory", "remove", "unlink", "rmtree", "rename", "listdir", "makedirs", "mkdir",
              "copy", "copyfile", "move", "read_text", "write_text", "read_bytes", "write_bytes", "FileResponse", "static_file"}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) or "")
    return ".".join(reversed(parts))


class _PyTaint:
    def __init__(self, text):
        self.lines = text.split("\n")
        self.hits = []

    def src_of(self, e, env):
        """Return a short description of the untrusted source feeding expression e, or None."""
        if e is None:
            return None
        if isinstance(e, ast.Name):
            return env.get(e.id)
        if isinstance(e, ast.Constant):
            return None
        if isinstance(e, ast.Attribute):
            root = e
            while isinstance(root, (ast.Attribute, ast.Subscript, ast.Call)):
                root = root.value if not isinstance(root, ast.Call) else root.func
            d = _dotted(e)
            if isinstance(root, ast.Name) and root.id == "request" and e.attr in PY_REQUEST_ATTRS:
                return f"request.{e.attr} (line {e.lineno})"
            if d == "sys.argv":
                return f"sys.argv (line {e.lineno})"
            if (isinstance(e.value, ast.Attribute) or isinstance(e.value, ast.Name)) and e.attr in PY_REQUEST_ATTRS:
                inner = self.src_of(e.value, env)
                if inner:
                    return inner
            return self.src_of(e.value, env)
        if isinstance(e, ast.Subscript):
            return self.src_of(e.value, env) or self.src_of(e.slice, env)
        if isinstance(e, ast.JoinedStr):
            for v in e.values:
                s = self.src_of(v.value if isinstance(v, ast.FormattedValue) else v, env)
                if s:
                    return s
            return None
        if isinstance(e, ast.FormattedValue):
            return self.src_of(e.value, env)
        if isinstance(e, ast.BinOp):
            if isinstance(e.op, (ast.Add, ast.Mod)):
                return self.src_of(e.left, env) or self.src_of(e.right, env)
            return None
        if isinstance(e, ast.BoolOp):
            for v in e.values:
                s = self.src_of(v, env)
                if s:
                    return s
            return None
        if isinstance(e, ast.IfExp):
            return self.src_of(e.body, env) or self.src_of(e.orelse, env)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            for v in e.elts:
                s = self.src_of(v, env)
                if s:
                    return s
            return None
        if isinstance(e, ast.Dict):
            for v in e.values:
                s = self.src_of(v, env)
                if s:
                    return s
            return None
        if isinstance(e, ast.Starred):
            return self.src_of(e.value, env)
        if isinstance(e, ast.Call):
            fn = e.func
            name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            if name in PY_SANITIZERS:
                return None
            if name == "input" and isinstance(fn, ast.Name):
                return f"input() (line {e.lineno})"
            if isinstance(fn, ast.Attribute):
                recv = self.src_of(fn.value, env)
                if recv and (name in PY_PASSTHROUGH_METHODS or name in PY_REQUEST_ATTRS):
                    return recv
                if name in PY_PASSTHROUGH_METHODS and name in ("format", "join"):
                    for a in list(e.args) + [k.value for k in e.keywords]:
                        s = self.src_of(a, env)
                        if s:
                            return s
                if name in PY_REQUEST_ATTRS:  # request.get_json(), request.args.get()
                    return self.src_of(fn.value, env)
            if name in PY_PASSTHROUGH_FUNCS:
                for a in list(e.args) + [k.value for k in e.keywords]:
                    s = self.src_of(a, env)
                    if s:
                        return s
            return None
        if isinstance(e, ast.Await):
            return self.src_of(e.value, env)
        return None

    def line(self, n):
        return self.lines[n - 1].strip() if 0 < n <= len(self.lines) else ""

    def hit(self, rule, node, src, sink):
        self.hits.append(dict(rule=rule, line=node.lineno, snippet=self.line(node.lineno),
                              detail=f"Data flow: untrusted input from {src} reaches {sink} (line {node.lineno}) without a recognised sanitizer."))

    def check_call(self, c, env):
        fn = c.func
        name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
        dotted = _dotted(fn)
        root = dotted.split(".")[0]
        args = list(c.args)
        a0 = args[0] if args else None
        kw = {k.arg: k.value for k in c.keywords if k.arg}
        shell_true = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True

        if name in SQL_SINKS and a0 is not None:
            s = self.src_of(a0, env)
            if s:
                self.hit("INJ-SQL-1", c, s, f"a SQL call ({name})")
            return
        if name == "text" and a0 is not None and root in ("sa", "sqlalchemy", "db", "text"):
            s = self.src_of(a0, env)
            if s:
                self.hit("INJ-SQL-1", c, s, "SQLAlchemy text()")
            return
        if (root == "os" and name in CMD_OS) or (root == "subprocess" and name in CMD_SUBPROCESS) or name in ("getoutput", "getstatusoutput"):
            if a0 is not None:
                s = self.src_of(a0, env)
                is_str = not isinstance(a0, (ast.List, ast.Tuple))
                if s and (root == "os" or shell_true or is_str):
                    self.hit("INJ-CMD-1", c, s, f"a shell command ({dotted})")
            return
        if name in ("eval", "exec") and isinstance(fn, ast.Name) and a0 is not None:
            s = self.src_of(a0, env)
            if s:
                self.hit("INJ-EVAL-1", c, s, f"{name}()")
            return
        if name in HTTP_FUNCS and (root in HTTP_ROOTS or root.endswith("session") or name in ("urlopen", "urlretrieve")):
            target = a0 if a0 is not None else kw.get("url")
            if name == "request" and len(args) > 1:
                target = args[1]
            s = self.src_of(target, env)
            if s:
                self.hit("SSRF-1", c, s, f"an outbound HTTP request ({dotted})")
            return
        if name in PATH_FUNCS and (isinstance(fn, ast.Name) or root in ("os", "shutil", "pathlib", "Path", "flask", "web")):
            cand = args[:2] if name in ("send_from_directory", "copy", "copyfile", "move", "rename") else args[:1]
            for a in cand:
                s = self.src_of(a, env)
                if s:
                    self.hit("PATH-1", c, s, f"a file-system call ({name})")
                    break
            return
        if name in ("loads", "load") and root in ("pickle", "cPickle", "marshal", "jsonpickle", "dill", "shelve") and a0 is not None:
            s = self.src_of(a0, env)
            if s:
                self.hit("DESER-1", c, s, f"{dotted}()")
            return
        if name == "load" and root == "yaml" and a0 is not None:
            loader = kw.get("Loader")
            if not (loader is not None and "Safe" in _dotted(loader)):
                s = self.src_of(a0, env)
                if s:
                    self.hit("DESER-2", c, s, "yaml.load()")
            return
        if name == "redirect" and a0 is not None:
            s = self.src_of(a0, env)
            if s:
                self.hit("REDIR-1", c, s, "a redirect")
            return
        if name in ("render_template_string", "Markup", "mark_safe") and a0 is not None:
            s = self.src_of(a0, env)
            if s:
                self.hit("XSS-2", c, s, f"{name}() (unescaped HTML / server-side template)")

    def bind(self, target, src, env):
        if isinstance(target, ast.Name):
            if src:
                env[target.id] = src
            else:
                env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self.bind(t, src, env)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, src, env)

    def stmt_calls(self, stmt, env):
        """Check every call in a statement, without descending into nested statement blocks (handled separately)."""
        stack = [stmt]
        while stack:
            n = stack.pop()
            for ch in ast.iter_child_nodes(n):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(ch, ast.stmt):
                    continue
                if isinstance(ch, ast.Call):
                    self.check_call(ch, env)
                stack.append(ch)

    def block(self, stmts, env):
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = dict(env)
                for a in st.args.args + st.args.kwonlyargs:
                    inner.pop(a.arg, None)
                self.block(st.body, inner)
                continue
            if isinstance(st, ast.ClassDef):
                self.block(st.body, dict(env))
                continue
            self.stmt_calls(st, env)
            if isinstance(st, ast.Assign):
                src = self.src_of(st.value, env)
                for t in st.targets:
                    self.bind(t, src, env)
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                self.bind(st.target, self.src_of(st.value, env), env)
            elif isinstance(st, ast.AugAssign):
                src = self.src_of(st.value, env) or self.src_of(st.target, env)
                if src:
                    self.bind(st.target, src, env)
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                self.bind(st.target, self.src_of(st.iter, env), env)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for it in st.items:
                    if it.optional_vars is not None:
                        self.bind(it.optional_vars, self.src_of(it.context_expr, env), env)
            for field in ("body", "orelse", "finalbody"):
                sub = getattr(st, field, None)
                if sub and isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                    self.block(sub, env)
            for h in getattr(st, "handlers", []) or []:
                self.block(h.body, env)
            for c in getattr(st, "cases", []) or []:
                self.block(c.body, env)


def python_flows(text):
    """-> (hits, parsed_ok). Each hit: dict(rule, line, snippet, detail)."""
    if not re.search(r"request\b|input\(|sys\.argv", text):
        return [], True
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return [], False
    t = _PyTaint(text)
    try:
        t.block(tree.body, {})
    except RecursionError:
        return t.hits, False
    return t.hits, True


# ----------------------------------------------------------------------------- JavaScript / TypeScript
JS_SRC = r"(?:\b(?:req|request|ctx\.request|ctx)\.(?:body|query|params|headers|cookies|files|file)\b|\b(?:location\.(?:search|hash|href)|document\.location|window\.location\.\w+|URLSearchParams\([^)]*\)\.get)\b)"
JS_SRC_RX = re.compile(JS_SRC)
JS_SANITIZE = re.compile(r"\b(parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|escapeHtml|sanitize\w*|DOMPurify\.sanitize|validator\.\w+|"
                         r"mysql\.escape\w*|sqlstring\.escape|path\.basename|shellEscape|shell-quote|quote|Joi\.|z\.\w+|isInt|ObjectId|uuid\w*|toString\(\)\.replace)\s*\(")
JS_ASSIGN = re.compile(r"(?:^|[;{}]\s*|\bexport\s+)(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=(?!=)\s*(.+)$", re.S)
JS_DESTRUCT = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$", re.S)
WORD = lambda v: re.compile(r"(?<![\w$.])" + re.escape(v) + r"(?![\w$])")

# (rule, call regex, extra condition tag)
JS_SINKS = [
    ("INJ-SQL-2", re.compile(r"\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|queryRaw|executeRaw|exec_sql|run|all|get|prepare)\s*\("), "sql"),
    ("INJ-CMD-2", re.compile(r"(?<![\w.])(?:child_process\.)?(?:exec|execSync)\s*\(|(?:spawn|spawnSync|execFile|execFileSync)\s*\("), "cmd"),
    ("INJ-EVAL-1", re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|vm\.run\w*\("), "any"),
    ("SSRF-1", re.compile(r"(?<![\w.])(?:axios|fetch|got|superagent|needle|request|rp)(?:\.\w+)?\s*\(|\b(?:http|https)\.(?:get|request)\s*\("), "any"),
    ("PATH-1", re.compile(r"\b(?:fs|fsp|fs\.promises)\.\w+\s*\(|\b(?:sendFile|createReadStream|createWriteStream|readFile\w*|writeFile\w*|unlink|rmSync|download)\s*\("), "path"),
    ("REDIR-1", re.compile(r"\bres\.redirect\s*\(|\bredirect\s*\("), "any"),
    ("INJ-NOSQL-1", re.compile(r"\.(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments|findOneAndUpdate|findOneAndDelete)\s*\("), "nosql"),
    ("ACC-1", re.compile(r"\.(?:findById|findByPk|findByIdAndUpdate|findByIdAndDelete|findUnique|getById)\s*\("), "any"),
    ("XSS-4", re.compile(r"\bres\.(?:send|write|end)\s*\("), "html"),
]


def _first_arg(s, start):
    """Text of the first argument of the call whose '(' ends at index `start`."""
    depth, i, n, q, buf = 0, start, len(s), None, []
    while i < n:
        c = s[i]
        if q:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            break
        else:
            buf.append(c)
        i += 1
    return "".join(buf)


def _outside_strings(expr):
    """Mask plain string contents (keep template-literal ${...} expressions visible)."""
    out, i, n = [], 0, len(expr)
    while i < n:
        c = expr[i]
        if c in "\"'":
            j = i + 1
            while j < n and expr[j] != c:
                j += 2 if expr[j] == "\\" else 1
            out.append(" ")
            i = j + 1
        elif c == "`":
            j = i + 1
            out.append(" ")
            while j < n and expr[j] != "`":
                if expr[j] == "$" and j + 1 < n and expr[j + 1] == "{":
                    k, d = j + 2, 1
                    while k < n and d:
                        d += (expr[k] == "{") - (expr[k] == "}")
                        k += 1
                    out.append(" " + expr[j + 2:k - 1] + " ")
                    j = k
                else:
                    j += 2 if expr[j] == "\\" else 1
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def javascript_flows(logical):
    """logical: list of (lineno, text) from logical_lines(). -> hits (dict rule/line/snippet/detail)."""
    tainted = {}   # name -> (source text, line)
    hits = []
    if not any(JS_SRC_RX.search(t) for _, t in logical):
        return hits
    for ln, text in logical:
        s = text.strip()
        if s.startswith(("//", "/*", "*")):
            continue
        # --- sinks first (use taint known before this statement)
        for rule, rx, cond in JS_SINKS:
            for m in rx.finditer(s):
                arg = _first_arg(s, m.end())
                visible = _outside_strings(arg)
                src = None
                if JS_SRC_RX.search(visible):
                    mm = JS_SRC_RX.search(visible)
                    src = (mm.group(0), ln)
                else:
                    for v, info in tainted.items():
                        if WORD(v).search(visible):
                            src = info
                            break
                if not src:
                    continue
                if JS_SANITIZE.search(arg):
                    continue
                if cond == "cmd" and m.group(0).startswith(("spawn", "execFile")) and not re.search(r"shell\s*:\s*true", s):
                    continue
                if cond == "sql" and not re.search(r"\+|\$\{|`|\bformat\(|\.concat\(", arg) and not any(WORD(v).fullmatch(arg.strip()) or arg.strip() == v for v in tainted):
                    continue
                if cond == "html" and "<" not in arg:
                    continue
                if cond == "nosql" and not (src[0].startswith(("req.body", "req.query", "request.body", "request.query", "ctx"))):
                    continue
                if rule == "INJ-NOSQL-1" and not re.search(r"\{", arg) and not JS_SRC_RX.search(visible) and not any(WORD(v).fullmatch(arg.strip()) for v in tainted):
                    continue
                if rule == "ACC-1" and not re.search(r"params|query|body", src[0]):
                    continue
                hits.append(dict(rule=rule, line=ln, snippet=s[:220],
                                 detail=f"Data flow: untrusted input from {src[0]} (line {src[1]}) reaches `{m.group(0).strip(' (')}` (line {ln})."))
        # --- then propagate taint through this statement
        d = JS_DESTRUCT.match(s)
        if d and JS_SRC_RX.search(d.group(2)):
            for part in d.group(1).split(","):
                nm = part.strip().split("=")[0].split(":")[-1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", nm):
                    tainted[nm] = (JS_SRC_RX.search(d.group(2)).group(0), ln)
            continue
        a = JS_ASSIGN.search(s)
        if a:
            name, rhs = a.group(1), a.group(2)
            if re.fullmatch(r"(if|for|while|switch|return|const|let|var)", name):
                continue
            visible = _outside_strings(rhs)
            src = None
            mm = JS_SRC_RX.search(visible)
            if mm:
                src = (mm.group(0), ln)
            else:
                for v, info in tainted.items():
                    if WORD(v).search(visible):
                        src = info
                        break
            if src and not JS_SANITIZE.search(rhs):
                tainted[name] = src
            else:
                tainted.pop(name, None)
    return hits
