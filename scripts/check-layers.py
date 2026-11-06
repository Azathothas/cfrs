#!/usr/bin/env python3
"""Check that no module of src/ refers to a module of a crate that it may not use.

  python3 -I scripts/check-layers.py [--list] [--plant-empty] [--self-test]

Each top module of src/ belongs to one target crate of the split
(docs/research/podnet/architecture.md, section 4.1; LAYER below). A crate
may use only the crates of USES. Each `crate::MODULE` of a file of src/
(also in a `use crate::{...}` group, also in a doc link) outside the
`#[cfg(test)]` items is one reference. A reference from a module to a module
of a crate that its crate may not use is a fault, except the references of
the allowlist (scripts/layers-allow.txt: `FROM -> TO` on each line). The
allowlist can only shrink: a row whose reference no longer exists is a
fault too. src/main.rs is the binary: it may use each crate.

A top module that LAYER does not name is a fault: give it a crate. A scan
that reads fewer than MIN_FILES files is a fault.

--list prints each reference between crates (allowed or not) as
`FROM -> TO`. --plant-empty scans an empty tree: it must exit 1.
--self-test plants faults in temporary trees.

Exit 0: no fault. Exit 1: a fault, one line for each.
"""

import argparse
import pathlib
import re
import sys
import tempfile

MIN_FILES = 100

LAYER = {
    # core: process, files, network, supervisor
    "exit": "core", "hop": "core", "state": "core", "report": "core",
    "decisions": "core", "metrics": "core", "rlimit": "core", "yaml": "core",
    "race": "core", "util": "core", "qr": "core", "ports": "core",
    "net": "core", "trust": "core", "egress": "core", "resolve": "core",
    "fetch": "core", "udp": "core", "connect": "core", "detach": "core",
    "instances": "core", "autostart": "core",
    "vnet": "vnet",
    "ws_relay": "relay", "relay_pool": "relay", "relay_reverse": "relay",
    "warp": "warp",
    "share": "serve", "gate": "serve", "service": "serve", "ingress": "serve",
    "origin": "serve", "feature": "serve", "transport": "serve",
    "relay": "serve", "ws": "serve",
    "cloudflare": "cloudflare", "tunnel": "cloudflare", "edge_h2": "cloudflare",
    "edge_discovery": "cloudflare", "quicktunnel": "cloudflare",
    "config": "cloudflare", "proxy": "cloudflare",
    "doctor": "podnet", "preflight": "podnet", "agent": "podnet",
    "status": "podnet", "bug_report": "podnet", "manual": "podnet",
    "update": "podnet", "fuzzing": "podnet", "lib": "podnet",
    "test_host": "podnet", "services": "core", "main": "podnet",
}

USES = {
    "core": {"core"},
    "vnet": {"core", "vnet"},
    "relay": {"core", "relay"},
    "warp": {"core", "vnet", "relay", "warp"},
    "serve": {"core", "serve"},
    "cloudflare": {"core", "relay", "warp", "serve", "cloudflare"},
    "podnet": {"core", "vnet", "relay", "warp", "serve", "cloudflare", "podnet"},
}

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def strip_tests(text):
    """Return the text without the items under #[cfg(test)], and the names
    of the test modules that live in their own file (`mod x;`)."""
    out = []
    files = set()
    i = 0
    pat = re.compile(r"#\[cfg\(test\)\]")
    while True:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        j = m.end()
        # Skip the other attributes and the blanks of the item.
        while True:
            while j < len(text) and text[j].isspace():
                j += 1
            if text.startswith("#[", j):
                depth = 0
                while j < len(text):
                    if text[j] == "[":
                        depth += 1
                    elif text[j] == "]":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                continue
            break
        fm = re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text[j:])
        if fm:
            files.add(fm.group(1))
            i = j + fm.end()
            continue
        # The item ends at its first `;` before a `{`, or at the `}` that
        # closes its first `{`.
        k = j
        depth = 0
        while k < len(text):
            c = text[k]
            if c == ";" and depth == 0:
                k += 1
                break
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    k += 1
                    break
            k += 1
        i = k
    return "".join(out), files


def refs_of(text):
    """Yield each top module named after `crate::`."""
    for m in re.finditer(r"\bcrate\s*::\s*", text):
        j = m.end()
        if text.startswith("{", j):
            depth = 0
            k = j
            while k < len(text):
                if text[k] == "{":
                    depth += 1
                elif text[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            body = text[j + 1:k]
            # The top names of the group: the idents at depth 0 that start
            # a path segment.
            depth = 0
            start = True
            for t in re.finditer(r"[{}]|,|::|[A-Za-z_][A-Za-z0-9_]*", body):
                s = t.group(0)
                if s == "{":
                    depth += 1
                elif s == "}":
                    depth -= 1
                elif s == ",":
                    if depth == 0:
                        start = True
                elif s == "::":
                    pass
                else:
                    if depth == 0 and start:
                        yield s
                    start = False
        else:
            im = IDENT.match(text, j)
            if im:
                yield im.group(0)


def top_module(src, path):
    rel = path.relative_to(src)
    return rel.parts[0][:-3] if len(rel.parts) == 1 else rel.parts[0]


def scan(root):
    src = root / "src"
    files = sorted(src.rglob("*.rs")) if src.is_dir() else []
    faults = []
    edges = {}
    skip = set()
    stripped = {}
    for f in files:
        text, tests = strip_tests(f.read_text(encoding="utf-8"))
        base = f.parent if f.name in ("mod.rs", "lib.rs", "main.rs") else f.with_suffix("")
        for t in tests:
            skip.add(base / (t + ".rs"))
            skip.add(base / t / "mod.rs")
        stripped[f] = text
    for f in files:
        if f in skip:
            continue
        frm = top_module(src, f)
        if frm not in LAYER:
            faults.append(f"{f.relative_to(root)}: the module {frm} has no crate in LAYER")
            continue
        for to in refs_of(stripped[f]):
            if to in ("self", "super") or to == frm or to[0].isupper():
                continue
            if to not in LAYER:
                continue
            edges.setdefault((frm, to), f.relative_to(root))
    return files, edges, faults


def read_allow(path):
    rows = {}
    if not path.is_file():
        return rows
    for n, line in enumerate(path.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"(\w+)\s*->\s*(\w+)", line)
        if not m:
            rows[("?", str(n))] = n
            continue
        rows[(m.group(1), m.group(2))] = n
    return rows


def check(root, allow_path, listing=False):
    files, edges, faults = scan(root)
    if len(files) < MIN_FILES:
        faults.append(f"check-layers: {len(files)} files read, fewer than {MIN_FILES}")
    allow = read_allow(allow_path)
    for (a, b), n in allow.items():
        if a == "?":
            faults.append(f"{allow_path.name}:{n}: not a `FROM -> TO` line")
    for (a, b), where in sorted(edges.items()):
        la, lb = LAYER[a], LAYER[b]
        if la == lb:
            continue
        ok = lb in USES[la]
        if listing:
            print(f"{a} -> {b}{'' if ok else '  (up)'}  {where}")
        if not ok and (a, b) not in allow:
            faults.append(f"{where}: {a} ({la}) -> {b} ({lb}): {la} may not use {lb}")
    for (a, b), n in sorted(allow.items(), key=lambda x: x[1]):
        if a == "?":
            continue
        if (a, b) not in edges:
            faults.append(f"{allow_path.name}:{n}: {a} -> {b} no longer exists: remove the row")
        elif a in LAYER and b in LAYER and LAYER[b] in USES[LAYER[a]]:
            faults.append(f"{allow_path.name}:{n}: {a} -> {b} is allowed: remove the row")
    return faults


def self_test():
    ok = True

    def tree(files):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        for i in range(MIN_FILES):
            (d / "src" / f"util{i}.rs").write_text("")
        LAYER.update({f"util{i}": "core" for i in range(MIN_FILES)})
        for name, text in files.items():
            p = d / "src" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return d

    cases = [
        ("control", {"egress.rs": "use crate::util::x;\n"}, "", False),
        ("upward", {"egress.rs": "use crate::tunnel;\n", "tunnel.rs": ""}, "", True),
        ("group", {"egress.rs": "use crate::{util, tunnel::A};\n"}, "", True),
        ("test item", {"egress.rs": "#[cfg(test)]\nmod tests { use crate::tunnel; }\n"}, "", False),
        ("test file", {"egress.rs": "#[cfg(test)]\nmod t;\n", "egress/t.rs": "use crate::tunnel;\n"}, "", False),
        ("allowed", {"egress.rs": "use crate::tunnel;\n"}, "egress -> tunnel\n", False),
        ("stale row", {"egress.rs": ""}, "egress -> tunnel\n", True),
        ("unknown", {"zzz.rs": ""}, "", True),
    ]
    for name, files, allow, want in cases:
        d = tree(files)
        a = d / "allow.txt"
        a.write_text(allow)
        got = bool(check(d, a))
        if got != want:
            print(f"self-test: {name}: fault={got}, want {want}")
            ok = False
    d = pathlib.Path(tempfile.mkdtemp())
    if not check(d, d / "allow.txt"):
        print("self-test: an empty tree passes")
        ok = False
    print("self-test: " + ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--plant-empty", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    root = pathlib.Path(__file__).resolve().parent.parent
    allow = root / "scripts" / "layers-allow.txt"
    if a.plant_empty:
        root = pathlib.Path(tempfile.mkdtemp())
    faults = check(root, allow, a.list)
    for f in faults:
        print(f)
    print(f"check-layers: {len(faults)} faults")
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
