#!/usr/bin/env python3
"""Render an architecture or sequence diagram to a standalone, accessible SVG from a JSON spec.

Usage: python make_svg.py SPEC.json OUT.svg

Architecture spec (type defaults to "architecture"):
{
  "title": "System architecture", "description": "optional text for screen readers",
  "direction": "LR",                       # LR (groups are columns) or TB (groups are rows)
  "groups": [{"id": "clients", "label": "Clients"}, ...],          # order = left-to-right / top-to-bottom
  "nodes":  [{"id": "api", "label": "API server", "sub": "src/server.js", "group": "services",
              "kind": "service"}],         # kind: client | service | store | external | tool | planned
  "edges":  [{"from": "web", "to": "api", "label": "HTTP :3000", "style": "solid"}]   # style: solid | dashed
}

Sequence spec:
{
  "type": "sequence", "title": "Order flow",
  "participants": [{"id": "U", "label": "Browser"}, {"id": "A", "label": "API"}],
  "messages": [{"from": "U", "to": "A", "label": "POST /orders"}, {"from": "A", "to": "U", "label": "201", "style": "dashed"}]
}
Use Mermaid instead when you need alt/loop/par blocks.
"""
import json
import sys
from xml.sax.saxutils import escape

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
CHAR_W = 7.4          # average glyph width at 13px
STYLE = {              # fill, stroke
    "client": ("#f3e8fd", "#8e4ec6"), "service": ("#e8f0fe", "#3b6fd4"), "store": ("#e6f4ea", "#2f8f4e"),
    "external": ("#fff4e5", "#d9822b"), "tool": ("#eef0f2", "#6b7785"), "planned": ("#f6f6f6", "#8a8a8a"),
}
KIND_NAME = {"client": "Client", "service": "Service", "store": "Data store", "external": "External", "tool": "Tool", "planned": "Planned"}


def tw(s, size=13):
    return len(s) * CHAR_W * size / 13


def defs():
    return ('<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
            '<path d="M0,0 L10,5 L0,10 z" fill="#4b5563"/></marker></defs>')


def wrap(title, desc, body, w, h):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:.0f} {h:.0f}" width="{w:.0f}" height="{h:.0f}" role="img" aria-labelledby="t d" '
            f'font-family="{FONT}" font-size="13">\n<title id="t">{escape(title)}</title>\n<desc id="d">{escape(desc)}</desc>\n'
            f'<rect width="100%" height="100%" fill="#ffffff"/>\n{defs()}\n{body}\n</svg>\n')


def node_svg(n, x, y, w, h):
    fill, stroke = STYLE.get(n.get("kind", "service"), STYLE["service"])
    dash = ' stroke-dasharray="6 4"' if n.get("kind") == "planned" else ""
    label = n["label"] + (" (Planned)" if n.get("kind") == "planned" and "Planned" not in n["label"] else "")
    out = []
    if n.get("kind") == "store":
        ry = 8
        out.append(f'<path d="M{x},{y+ry} a{w/2},{ry} 0 0 1 {w},0 v{h-2*ry} a{w/2},{ry} 0 0 1 {-w},0 z" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        out.append(f'<path d="M{x},{y+ry} a{w/2},{ry} 0 0 0 {w},0" fill="none" stroke="{stroke}" stroke-width="1.5"/>')
    else:
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.5"{dash}/>')
    cy = y + h / 2 + (4 if not n.get("sub") else -2)
    if n.get("kind") == "store":
        cy += 4
    out.append(f'<text x="{x+w/2}" y="{cy}" text-anchor="middle" font-weight="600" fill="#1f2937">{escape(label)}</text>')
    if n.get("sub"):
        out.append(f'<text x="{x+w/2}" y="{cy+16}" text-anchor="middle" font-size="11" fill="#4b5563">{escape(n["sub"])}</text>')
    return "\n".join(out)


def architecture(spec):
    groups = spec["groups"]
    nodes = {n["id"]: n for n in spec["nodes"]}
    for n in nodes.values():
        n.setdefault("group", groups[0]["id"])
    gidx = {g["id"]: i for i, g in enumerate(groups)}
    lr = spec.get("direction", "LR").upper() != "TB"
    edges = spec.get("edges", [])
    gi_of = lambda nid: gidx[nodes[nid]["group"]]
    size = {}
    for i, n in nodes.items():
        lab = n["label"] + (" (Planned)" if n.get("kind") == "planned" and "Planned" not in n["label"] else "")
        w = max(tw(lab) + 28, tw(n.get("sub", ""), 11) + 28, 110)
        size[i] = (round(w), 62 if n.get("sub") else 46)
    order = {g["id"]: [i for i, n in nodes.items() if n["group"] == g["id"]] for g in groups}
    pos = {}
    for gi, g in enumerate(groups):          # barycenter ordering against earlier groups
        m = order[g["id"]]
        if gi > 0:
            def bary(nid):
                nb = [pos[a] for e in edges for a, b in ((e["from"], e["to"]), (e["to"], e["from"])) if b == nid and a in pos and gi_of(a) < gi]
                return sum(nb) / len(nb) if nb else 1e9
            m.sort(key=bary)
        for k, nid in enumerate(m):
            pos[nid] = k
    PAD, HEAD, LANE = 18, 30, 20
    msize = lambda nid: size[nid] if lr else (size[nid][1], size[nid][0])     # (main, cross)
    # gap between neighbouring groups must fit the edge labels that cross it
    gaps = []
    for gi in range(len(groups) - 1):
        lw = max([tw(e.get("label", ""), 11) + 14 for e in edges if {gi_of(e["from"]), gi_of(e["to"])} == {gi, gi + 1}] or [0])
        gaps.append(max(70, lw + 40) if lr else 70)
    gdims, cross_total, ggap = [], [], {}
    for g in groups:
        m = order[g["id"]]
        head_w = tw(g["label"].upper(), 12) * 1.15 + 28
        # room between neighbours inside a group: label height (LR, vertical stack) or label width (TB, side by side)
        inner = [e for e in edges if gi_of(e["from"]) == gi_of(e["to"]) == gidx[g["id"]] and e.get("label")]
        gap = 34 if lr else max(34, max([tw(e["label"], 11) + 40 for e in inner] or [0]))
        ggap[g["id"]] = gap
        mains = [msize(n)[0] for n in m] or [100]
        crosses = [msize(n)[1] for n in m]
        gmain = max(max(mains) + 2 * PAD + (0 if lr else HEAD), head_w if lr else 0)
        gcross = max(sum(crosses) + gap * max(len(m) - 1, 0) + 2 * PAD + (HEAD if lr else 0), 0 if lr else head_w)
        gdims.append((gmain, gcross)); cross_total.append(gcross)
    total_cross = max(cross_total) + 40
    main_pos, placed = 30, {}
    for gi, (g, (gm, gc)) in enumerate(zip(groups, gdims)):
        top = 20 + (total_cross - 40 - gc) / 2
        c = top + PAD + (HEAD if lr else 0)
        hm = 0 if lr else HEAD                      # header sits on the main axis in top-to-bottom layouts
        for nid in order[g["id"]]:
            m_, c_ = msize(nid)
            placed[nid] = {"main": main_pos + hm + (gm - hm - m_) / 2, "cross": c, "ms": m_, "cs": c_}
            c += c_ + ggap[g["id"]]
        g["_main"], g["_cross"], g["_gm"], g["_gc"] = main_pos, top, gm, gc
        main_pos += gm + (gaps[gi] if gi < len(gaps) else 0)
    total_main = main_pos + 30
    # edges that skip a group go through a lane outside the diagram instead of through the nodes in between
    cmin, cmax = ("T", "B") if lr else ("L", "R")
    center = total_cross / 2
    lane_of, nmin, nmax = {}, 0, 0
    longs = sorted([ei for ei, e in enumerate(edges) if abs(gi_of(e["from"]) - gi_of(e["to"])) > 1],
                   key=lambda ei: abs(gi_of(edges[ei]["from"]) - gi_of(edges[ei]["to"])))
    for ei in longs:
        e = edges[ei]
        mid = (placed[e["from"]]["cross"] + placed[e["from"]]["cs"] / 2 + placed[e["to"]]["cross"] + placed[e["to"]]["cs"] / 2) / 2
        if mid < center:
            lane_of[ei] = (cmin, nmin); nmin += 1
        else:
            lane_of[ei] = (cmax, nmax); nmax += 1
    lab_pad = lambda side: max([tw(edges[ei].get("label", ""), 11) / 2 + 8 for ei, (sd, _) in lane_of.items() if sd == side] or [0]) if not lr else 0
    pmin, pmax = lab_pad(cmin), lab_pad(cmax)
    CO = nmin * LANE + pmin
    cross_len = total_cross + (nmin + nmax) * LANE + pmin + pmax
    def box(nid):
        p = placed[nid]; c = p["cross"] + CO
        return (p["main"], c, p["ms"], p["cs"]) if lr else (c, p["main"], p["cs"], p["ms"])      # x, y, w, h
    W, H = (total_main, cross_len) if lr else (cross_len, total_main)
    opposite = {"R": "L", "L": "R", "B": "T", "T": "B"}
    def side_for(ei):
        e = edges[ei]
        if ei in lane_of:
            return lane_of[ei][0], lane_of[ei][0]
        ga, gb = gi_of(e["from"]), gi_of(e["to"])
        if ga != gb:
            s = ("R" if ga < gb else "L") if lr else ("B" if ga < gb else "T")
        else:
            lt = pos[e["from"]] < pos[e["to"]]
            s = ("B" if lt else "T") if lr else ("R" if lt else "L")
        return s, opposite[s]
    sides = {}
    for ei, e in enumerate(edges):
        so, si = side_for(ei)
        sides.setdefault((e["from"], so), []).append((ei, "out"))
        sides.setdefault((e["to"], si), []).append((ei, "in"))
    def anchor(nid, side, ei, role):
        x, y, w, h = box(nid)
        lst = sides[(nid, side)]
        off = (lst.index((ei, role)) - (len(lst) - 1) / 2) * 12
        return {"R": (x + w, y + h / 2 + off), "L": (x, y + h / 2 + off), "B": (x + w / 2 + off, y + h), "T": (x + w / 2 + off, y)}[side]
    body = []
    for g in groups:
        gm, gc, mm, cc = g["_main"], g["_cross"] + CO, g["_gm"], g["_gc"]
        x, y, w, h = (gm, gc, mm, cc) if lr else (gc, gm, cc, mm)
        body.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" rx="12" fill="#f7f8fa" stroke="#d0d7de"/>')
        body.append(f'<text x="{x+14:.0f}" y="{y+22:.0f}" font-size="12" font-weight="700" fill="#57606a" letter-spacing=".04em">{escape(g["label"].upper())}</text>')
    labels = []
    def add_label(text, mx, my):
        lw = tw(text, 11) + 10
        labels.append(f'<rect x="{mx-lw/2:.1f}" y="{my-9:.1f}" width="{lw:.1f}" height="18" rx="4" fill="#ffffff" fill-opacity=".95" stroke="#e5e7eb"/>'
                      f'<text x="{mx:.1f}" y="{my+4:.1f}" text-anchor="middle" font-size="11" fill="#374151">{escape(text)}</text>')
    for ei, e in enumerate(edges):
        so, si = side_for(ei)
        (x1, y1), (x2, y2) = anchor(e["from"], so, ei, "out"), anchor(e["to"], si, ei, "in")
        dash = ' stroke-dasharray="6 4"' if e.get("style") == "dashed" else ""
        if ei in lane_of:
            side, k = lane_of[ei]
            if lr:
                ly = (CO - LANE * (k + 1) + LANE / 2) if side == "T" else (CO + total_cross + LANE * k + LANE / 2)
                pts = f"M{x1:.1f},{y1:.1f} L{x1:.1f},{ly:.1f} L{x2:.1f},{ly:.1f} L{x2:.1f},{y2:.1f}"
                lab = ((x1 + x2) / 2, ly)
            else:
                lx = (CO - LANE * (k + 1) + LANE / 2) if side == "L" else (CO + total_cross + LANE * k + LANE / 2)
                pts = f"M{x1:.1f},{y1:.1f} L{lx:.1f},{y1:.1f} L{lx:.1f},{y2:.1f} L{x2:.1f},{y2:.1f}"
                lab = (lx, (y1 + y2) / 2)
            body.append(f'<path d="{pts}" fill="none" stroke="#4b5563" stroke-width="1.5" stroke-linejoin="round"{dash} marker-end="url(#arr)"/>')
        else:
            horiz = so in "RL"
            d = max(abs(x2 - x1) * 0.5 if horiz else abs(y2 - y1) * 0.5, 24)
            sx, sy = (1 if so == "R" else -1, 0) if horiz else (0, 1 if so == "B" else -1)
            c1, c2 = (x1 + sx * d, y1 + sy * d), (x2 - sx * d, y2 - sy * d)
            body.append(f'<path d="M{x1:.1f},{y1:.1f} C{c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {x2:.1f},{y2:.1f}" fill="none" stroke="#4b5563" stroke-width="1.5"{dash} marker-end="url(#arr)"/>')
            lab = (0.125 * x1 + 0.375 * c1[0] + 0.375 * c2[0] + 0.125 * x2, 0.125 * y1 + 0.375 * c1[1] + 0.375 * c2[1] + 0.125 * y2)
        if e.get("label"):
            add_label(e["label"], *lab)
    for nid, n in nodes.items():
        x, y, w, h = box(nid)
        body.append(node_svg(n, round(x), round(y), w, h))
    body += labels
    kinds = sorted({n.get("kind", "service") for n in nodes.values()})
    if spec.get("legend", True) and kinds:
        lx, ly = 30, H + 8
        for k in kinds:
            fill, stroke = STYLE[k]
            body.append(f'<rect x="{lx}" y="{ly}" width="14" height="14" rx="3" fill="{fill}" stroke="{stroke}"/><text x="{lx+20}" y="{ly+11}" font-size="11" fill="#374151">{KIND_NAME[k]}</text>')
            lx += 20 + tw(KIND_NAME[k], 11) + 22
        H += 34
    desc = spec.get("description") or ("Components: " + "; ".join(n["label"] for n in nodes.values()) + ". Connections: " +
           "; ".join(f'{nodes[e["from"]]["label"]} to {nodes[e["to"]]["label"]}' + (f' ({e["label"]})' if e.get("label") else "") for e in edges) + ".")
    return wrap(spec.get("title", "Architecture diagram"), desc, "\n".join(body), W, H)


def sequence(spec):
    ps, msgs = spec["participants"], spec["messages"]
    ids = {p["id"]: i for i, p in enumerate(ps)}
    widths = [max(tw(p["label"]) + 28, 100) for p in ps]
    # make columns wide enough for the labels between neighbours
    colw = list(widths)
    for m in msgs:
        a, b = sorted((ids[m["from"]], ids[m["to"]]))
        if a != b:
            need = (tw(m.get("label", ""), 12) + 40) / (b - a)
            for k in range(a, b):
                colw[k] = max(colw[k], need)
    xs, x = [], 30
    for i, w in enumerate(widths):
        xs.append(x + w / 2)
        x += max(colw[i], w / 2 + (widths[i + 1] / 2 if i + 1 < len(widths) else 0)) + 30 if i + 1 < len(widths) else 0
    W = xs[-1] + widths[-1] / 2 + 30
    top, step = 20, 38
    H = top + 40 + step * (len(msgs) + 1) + 30
    body = []
    for p, cx, w in zip(ps, xs, widths):
        body.append(f'<line x1="{cx:.0f}" y1="{top+36}" x2="{cx:.0f}" y2="{H-20:.0f}" stroke="#9ca3af" stroke-dasharray="4 4"/>')
        body.append(f'<rect x="{cx-w/2:.0f}" y="{top}" width="{w:.0f}" height="36" rx="8" fill="#e8f0fe" stroke="#3b6fd4" stroke-width="1.5"/>'
                    f'<text x="{cx:.0f}" y="{top+22}" text-anchor="middle" font-weight="600" fill="#1f2937">{escape(p["label"])}</text>')
    for i, m in enumerate(msgs):
        y = top + 36 + step * (i + 1)
        x1, x2 = xs[ids[m["from"]]], xs[ids[m["to"]]]
        dash = ' stroke-dasharray="6 4"' if m.get("style") == "dashed" else ""
        if x1 == x2:
            body.append(f'<path d="M{x1:.0f},{y-8} h34 v16 h-34" fill="none" stroke="#4b5563" stroke-width="1.5"{dash} marker-end="url(#arr)"/>')
            body.append(f'<text x="{x1+40:.0f}" y="{y+4}" font-size="12" fill="#1f2937">{escape(m.get("label", ""))}</text>')
        else:
            body.append(f'<line x1="{x1:.0f}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="#4b5563" stroke-width="1.5"{dash} marker-end="url(#arr)"/>')
            body.append(f'<text x="{(x1+x2)/2:.0f}" y="{y-6}" text-anchor="middle" font-size="12" fill="#1f2937">{escape(m.get("label", ""))}</text>')
    desc = spec.get("description") or ("Participants: " + ", ".join(p["label"] for p in ps) + ". Steps: " +
           "; ".join(f'{i+1}. {ps[ids[m["from"]]]["label"]} to {ps[ids[m["to"]]]["label"]}: {m.get("label", "")}' for i, m in enumerate(msgs)) + ".")
    return wrap(spec.get("title", "Sequence diagram"), desc, "\n".join(body), W, H)


MAX_LABEL = 60


def fail(msg):
    raise SystemExit(f"make_svg: invalid spec: {msg}")


def check_text(where, v, required=True):
    if v is None or v == "":
        if required:
            fail(f"{where} is missing")
        return
    if not isinstance(v, str):
        fail(f"{where} must be text, got {type(v).__name__}")
    if len(v) > MAX_LABEL:
        fail(f"{where} is {len(v)} characters (max {MAX_LABEL}); shorten it and put the detail in the surrounding document")


def validate(spec):
    """Reject specs that would crash or silently draw something wrong, with messages a model can act on."""
    if not isinstance(spec, dict):
        fail("top level must be a JSON object")
    if spec.get("type", "architecture") == "sequence":
        ps = spec.get("participants")
        if not isinstance(ps, list) or not ps:
            fail("'participants' must be a non-empty list of {id, label}")
        ids = set()
        for p in ps:
            if not isinstance(p, dict) or "id" not in p:
                fail("every participant needs an 'id'")
            if p["id"] in ids:
                fail(f"duplicate participant id '{p['id']}'")
            ids.add(p["id"]); check_text(f"participant '{p['id']}' label", p.get("label"))
        for i, m in enumerate(spec.get("messages") or [], 1):
            for k in ("from", "to"):
                if m.get(k) not in ids:
                    fail(f"message {i} {k} '{m.get(k)}' is not a participant id (known: {', '.join(sorted(map(str, ids)))})")
            check_text(f"message {i} label", m.get("label"), required=False)
            if m.get("style", "solid") not in ("solid", "dashed"):
                fail(f"message {i} style must be 'solid' or 'dashed'")
        return
    groups = spec.get("groups")
    if not isinstance(groups, list) or not groups:
        fail("'groups' must be a non-empty list of {id, label}, listed in flow order")
    gids = set()
    for g in groups:
        if not isinstance(g, dict) or "id" not in g:
            fail("every group needs an 'id'")
        if g["id"] in gids:
            fail(f"duplicate group id '{g['id']}'")
        gids.add(g["id"]); check_text(f"group '{g['id']}' label", g.get("label"))
    nodes = spec.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        fail("'nodes' must be a non-empty list")
    nids = set()
    for n in nodes:
        if not isinstance(n, dict) or "id" not in n:
            fail("every node needs an 'id'")
        nid = n["id"]
        if nid in nids:
            fail(f"duplicate node id '{nid}'")
        nids.add(nid)
        check_text(f"node '{nid}' label", n.get("label")); check_text(f"node '{nid}' sub", n.get("sub"), required=False)
        if n.get("group", groups[0]["id"]) not in gids:
            fail(f"node '{nid}' group '{n.get('group')}' is not defined in 'groups' (known: {', '.join(sorted(map(str, gids)))})")
        if n.get("kind", "service") not in STYLE:
            fail(f"node '{nid}' kind '{n.get('kind')}' is not one of: {', '.join(sorted(STYLE))}")
    for i, e in enumerate(spec.get("edges") or [], 1):
        for k in ("from", "to"):
            if e.get(k) not in nids:
                fail(f"edge {i} {k} '{e.get(k)}' is not a node id")
        if e["from"] == e["to"]:
            fail(f"edge {i} connects '{e['from']}' to itself; self-loops are not drawn, describe the retry or loop in text")
        check_text(f"edge {i} label", e.get("label"), required=False)
        if e.get("style", "solid") not in ("solid", "dashed"):
            fail(f"edge {i} style must be 'solid' or 'dashed'")
    if str(spec.get("direction", "LR")).upper() not in ("LR", "TB"):
        fail("direction must be 'LR' or 'TB'")
    if len(nodes) > 30:
        print(f"make_svg: warning: {len(nodes)} nodes; diagrams above about 25 are hard to read, consider splitting by subsystem", file=sys.stderr)


def main():
    if len(sys.argv) != 3:
        print(__doc__); return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            spec = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"make_svg: cannot read spec {sys.argv[1]}: {e}")
    validate(spec)
    svg = sequence(spec) if spec.get("type") == "sequence" else architecture(spec)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"wrote {sys.argv[2]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
