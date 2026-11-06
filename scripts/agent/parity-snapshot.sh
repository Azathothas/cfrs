#!/bin/sh
# Record the parity facts of the tree: the command tree with each flag
# (podnet man --json), the public items of each crate (cargo doc, the page
# all.html) and the name of each test (cargo test --workspace -- --list).
# With BEFORE, compare the new snapshot with it: print each lost item and
# exit 1 when an item is lost. A new item is not a fault.
#
#   sh scripts/agent/parity-snapshot.sh DIR [BEFORE [MAP]]
#
# DIR gets commands.txt, items.txt and tests.txt, each sorted. MAP has one
# "OLD NEW" pair on each line (# starts a comment): each OLD of a line of
# BEFORE becomes NEW before the compare (for example "cfrs podnet").
# PARITY_BIN names the binary (default: target/debug/podnet, built here).
# PARITY_SKIP is a list of parts to skip: commands, items, tests.
set -u
[ $# -ge 1 ] || { echo "usage: $0 DIR [BEFORE [MAP]]" >&2; exit 64; }
here=$(cd "$(dirname "$0")" && pwd)
out=$1
before=${2:-}
map=${3:-}
mkdir -p "$out" || exit 64
out=$(cd "$out" && pwd)
cd "$here/../.." || exit 64
skip=${PARITY_SKIP:-}
on() { case " $skip " in *" $1 "*) return 1 ;; esac; return 0; }

if on commands; then
    bin=${PARITY_BIN:-}
    if [ -z "$bin" ]; then
        cargo build -q -p podnet || exit 2
        bin=target/debug/podnet
    fi
    "$bin" man --json | python3 -I -c '
import json, sys
def walk(c):
    p = " ".join(["podnet"] + c["path"])
    yield p
    for a in c["args"]:
        yield p + " " + (a["synopsis"] if a["positional"] else "--" + a["id"])
    for s in c.get("subcommands", []):
        if isinstance(s, dict):
            yield from walk(s)
d = json.load(sys.stdin)
for line in sorted({x for c in d["commands"] for x in walk(c)}):
    print(line)
' > "$out/commands.txt" || exit 2
fi

if on items; then
    cargo doc -q --workspace --no-deps > /dev/null 2>&1 || exit 2
    python3 -I -c '
import html, pathlib, re, sys
root = pathlib.Path("target/doc")
names = set()
for page in sorted(root.glob("*/all.html")):
    krate = page.parent.name
    for href, text in re.findall(r"<a href=\"([^\"]+)\">([^<]+)</a>", page.read_text()):
        if href.startswith("#"):
            continue
        kind = href.rsplit("/", 1)[-1].split(".", 1)[0]
        names.add(krate + " " + kind + " " + html.unescape(text))
for n in sorted(names):
    print(n)
' > "$out/items.txt" || exit 2
fi

if on tests; then
    cargo test -q --workspace --no-run > /dev/null 2>&1 || exit 2
    cargo test --workspace -- --list 2>&1 | python3 -I -c '
import re, sys
unit = "?"
names = set()
for line in sys.stdin:
    m = re.match(r"\s*Running (.+?) \((.+)\)", line)
    if m:
        bin = re.sub(r"-[0-9a-f]{16}$", "", m.group(2).rsplit("/", 1)[-1])
        unit = m.group(1).split()[-1] + " " + bin
        continue
    m = re.match(r"\s*Doc-tests (\S+)", line)
    if m:
        unit = "doc " + m.group(1)
        continue
    m = re.match(r"(\S.*): (test|bench)$", line.rstrip("\n"))
    if m:
        name = re.sub(r" \(line \d+\)$", "", m.group(1))
        names.add(unit + " " + name)
for n in sorted(names):
    print(n)
' > "$out/tests.txt" || exit 2
fi

[ -n "$before" ] || exit 0
rc=0
for part in commands items tests; do
    on "$part" || continue
    [ -f "$before/$part.txt" ] || { echo "parity: $before/$part.txt is missing" >&2; rc=2; continue; }
    lost=$(python3 -I -c '
import sys
old, new, mp = sys.argv[1], sys.argv[2], sys.argv[3]
pairs = []
if mp:
    for line in open(mp):
        line = line.split("#", 1)[0].split()
        if len(line) == 2:
            pairs.append(line)
def fix(s):
    for a, b in pairs:
        s = s.replace(a, b)
    return s
have = set(open(new).read().splitlines())
for line in open(old).read().splitlines():
    if fix(line) not in have:
        print(line)
' "$before/$part.txt" "$out/$part.txt" "$map")
    if [ -n "$lost" ]; then
        rc=1
        printf '%s\n' "$lost" | sed "s/^/parity: lost $part: /"
    fi
    echo "parity: $part: $(wc -l < "$out/$part.txt") now, $(wc -l < "$before/$part.txt") before"
done
exit "$rc"
