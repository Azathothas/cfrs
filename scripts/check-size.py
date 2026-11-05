#!/usr/bin/env python3
"""Check the size of each Rust file of the repository.

  python3 -I scripts/check-size.py [--update] [--self-test]

No `.rs` file has more than LIMIT lines, except the files of the allowlist
(scripts/size-allow.txt: `LINES PATH` on each line). An allowlisted file can
only become smaller:

* A file over LIMIT that the allowlist does not name is a fault: split it.
* An allowlisted file with more lines than its count is a fault.
* An allowlisted file with fewer lines than its count is a fault: lower the
  count. `--update` lowers each count, and removes each file that has LIMIT
  lines or fewer. It does not raise a count, and it does not add a file.
* An allowlist line of a file that does not exist is a fault.

The scan reads each `.rs` file under the root of the repository, but not in
a directory named `target` or with a name that starts with `.`. A scan that
reads fewer than MIN_FILES files is a fault: a scan of nothing proves
nothing.

--self-test runs the check on temporary trees with planted faults. It exits
0 only when the check finds each fault, and passes the control tree.

Exit 0: no fault. Exit 1: a fault, one line for each. Exit 2: the allowlist
cannot be read.
"""

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW = "scripts/size-allow.txt"
LIMIT = 800
MIN_FILES = 100


class Unreadable(Exception):
    pass


def count_lines(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="replace").splitlines())


def rust_files(root: Path) -> list[str]:
    """Each `.rs` file under `root`, as a path relative to it."""
    out = []
    stack = [root]
    while stack:
        here = stack.pop()
        for entry in here.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                if entry.name != "target" and not entry.name.startswith("."):
                    stack.append(entry)
            elif entry.suffix == ".rs" and entry.is_file():
                out.append(entry.relative_to(root).as_posix())
    return sorted(out)


def read_allow(path: Path) -> dict[str, int]:
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise Unreadable(f"{path}: {e}") from e
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = line.split()
        if len(words) != 2 or not words[0].isdigit():
            raise Unreadable(f"{path}:{n}: not LINES PATH: {line!r}")
        if words[1] in out:
            raise Unreadable(f"{path}:{n}: {words[1]} is listed twice")
        out[words[1]] = int(words[0])
    return out


def check(root: Path, allow: dict[str, int], min_files: int) -> tuple[list[str], dict[str, int]]:
    """The faults, and the allowlist that --update writes."""
    files = rust_files(root)
    faults = []
    if len(files) < min_files:
        faults.append(f"{len(files)} Rust files read, fewer than {min_files}: the scan read too little to pass")
    lowered = {}
    for rel in files:
        lines = count_lines(root / rel)
        listed = allow.get(rel)
        if listed is None:
            if lines > LIMIT:
                faults.append(f"{rel}: {lines} lines, over {LIMIT}: split it")
        elif lines > listed:
            faults.append(f"{rel}: {lines} lines, more than the {listed} of {ALLOW}: make it smaller, do not raise the count")
        elif lines < listed:
            if lines > LIMIT:
                faults.append(f"{rel}: {lines} lines, fewer than the {listed} of {ALLOW}: lower the count to {lines} (--update)")
            else:
                faults.append(f"{rel}: {lines} lines, at or under {LIMIT}: remove it from {ALLOW} (--update)")
        if listed is not None and lines > LIMIT:
            lowered[rel] = min(lines, listed)
    present = set(files)
    for rel in sorted(allow):
        if rel not in present:
            faults.append(f"{ALLOW}: {rel} does not exist: remove its line (--update)")
    return faults, lowered


def write_allow(path: Path, allow: dict[str, int]) -> None:
    """Write the allowlist again with its comment lines and the counts of `allow`."""
    head = [l for l in path.read_text(encoding="utf-8").splitlines() if l.startswith("#") or not l.strip()]
    while head and not head[-1].strip():
        head.pop()
    body = [f"{allow[rel]} {rel}" for rel in sorted(allow)]
    path.write_text("\n".join(head + body) + "\n", encoding="utf-8")


def plant(root: Path, rel: str, lines: int) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"// {i}\n" for i in range(lines)), encoding="utf-8")


def self_test() -> int:
    """Each planted fault must be found, and the control must pass."""
    cases = []

    def case(name, setup, expect):
        cases.append((name, setup, expect))

    def control(root):
        plant(root, "src/big.rs", 900)
        plant(root, "src/small.rs", 10)
        plant(root, "crates/a/src/lib.rs", 800)
        plant(root, "target/debug/build/out.rs", 2000)
        plant(root, ".claude/worktrees/x/src/big.rs", 2000)
        return {"src/big.rs": 900}

    case("control", control, None)

    def new_file(root):
        allow = control(root)
        plant(root, "src/new.rs", 801)
        return allow

    case("a new file over the limit", new_file, "src/new.rs: 801 lines, over 800: split it")

    def grown(root):
        allow = control(root)
        plant(root, "src/big.rs", 901)
        return allow

    case("an allowlisted file that grew", grown, "src/big.rs: 901 lines, more than the 900")

    def shrunk(root):
        allow = control(root)
        plant(root, "src/big.rs", 850)
        return allow

    case("an allowlisted file that shrank", shrunk, "src/big.rs: 850 lines, fewer than the 900")

    def under(root):
        allow = control(root)
        plant(root, "src/big.rs", 700)
        return allow

    case("an allowlisted file at the limit or under", under, "src/big.rs: 700 lines, at or under 800")

    def missing(root):
        allow = control(root)
        allow["src/gone.rs"] = 1000
        return allow

    case("an allowlisted file that does not exist", missing, "src/gone.rs does not exist")

    case("an empty tree", lambda root: {}, "0 Rust files read, fewer than 3")

    failed = 0
    for name, setup, expect in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allow = setup(root)
            faults, _ = check(root, allow, 3)
        if expect is None:
            ok = not faults
        else:
            ok = any(expect in f for f in faults)
        print(f"{'ok  ' if ok else 'FAIL'}  {name}: {faults if faults else 'no fault'}")
        failed += not ok

    # --update lowers a count and removes a file under the limit; it never
    # raises a count or adds a file.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        control(root)
        plant(root, "src/big.rs", 850)
        plant(root, "src/mid.rs", 820)
        plant(root, "src/new.rs", 801)
        plant(root, "crates/a/src/lib.rs", 700)
        _, lowered = check(root, {"src/big.rs": 900, "src/mid.rs": 810, "crates/a/src/lib.rs": 900}, 3)
        ok = lowered == {"src/big.rs": 850, "src/mid.rs": 810}
        print(f"{'ok  ' if ok else 'FAIL'}  --update writes {lowered}")
        failed += not ok
    print(f"check-size: self-test, {failed} failure(s)")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        allow = read_allow(ROOT / ALLOW)
    except Unreadable as e:
        print(f"check-size: {e}", file=sys.stderr)
        return 2
    faults, lowered = check(ROOT, allow, MIN_FILES)
    if args.update:
        write_allow(ROOT / ALLOW, lowered)
        allow = lowered
        faults, _ = check(ROOT, allow, MIN_FILES)
    for fault in faults:
        print(fault)
    files = len(rust_files(ROOT))
    print(f"check-size: {files} Rust files, limit {LIMIT} lines, {len(allow)} allowlisted, {len(faults)} faults")
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
