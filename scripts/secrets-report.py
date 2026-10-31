#!/usr/bin/env python3
"""The findings of TruffleHog, read from its JSON lines, printed with no
secret in them.

  python scripts/secrets-report.py [--allow ALLOW] FOUND.jsonl
  python scripts/secrets-report.py --expect DETECTOR FOUND.jsonl

Each finding prints as its state (verified, unknown or unverified), the
detector, the file and line, and the commit; never its raw value, its
redacted form or its extra data, as the logs of a public repository are
public. Exit 1 when a finding is verified, or could not be verified
(unknown); an unverified finding is a note. ALLOW lists test values that are
not credentials, one per line: the detector, FILE:LINE and the commit that
added it (12 hex digits or more), then `#` and the reason. A listed finding
is a note too, and an entry that matches nothing is named, as it may be
stale. With --expect, exit 0 only when a finding of DETECTOR is there: the
check of a plant. Exit 2 when FOUND or ALLOW cannot be read: a check that
cannot run is not a pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def state(finding: dict) -> str:
    if finding.get("Verified") is True:
        return "verified"
    if finding.get("VerificationError"):
        return "unknown"
    return "unverified"


def place(finding: dict) -> str:
    git = (((finding.get("SourceMetadata") or {}).get("Data") or {}).get("Git")) or {}
    file = str(git.get("file") or "?")
    line = git.get("line")
    commit = str(git.get("commit") or "?")[:12]
    return f"{file}:{line if isinstance(line, int) else '?'} at {commit}"


def where(finding: dict) -> tuple[str, str, str]:
    git = (((finding.get("SourceMetadata") or {}).get("Data") or {}).get("Git")) or {}
    line = git.get("line")
    return (str(finding.get("DetectorName")), f"{git.get('file')}:{line}", str(git.get("commit") or ""))


def allowed(path: Path) -> list[tuple[str, str, str]]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        detector, file_line, commit = line.split()
        if len(commit) < 12:
            raise ValueError(f"{path}: the commit of {file_line} needs 12 hex digits or more")
        entries.append((detector, file_line, commit))
    return entries


def findings(path: Path) -> list[dict]:
    found = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        # A log line of the scanner is JSON too; a finding names a detector.
        if isinstance(item, dict) and item.get("DetectorName"):
            found.append(item)
    return found


def main(argv: list[str]) -> int:
    expect = None
    allow_path = None
    if len(argv) == 3 and argv[0] == "--expect":
        expect, argv = argv[1], argv[2:]
    elif len(argv) == 3 and argv[0] == "--allow":
        allow_path, argv = Path(argv[1]), argv[2:]
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    path = Path(argv[0])
    try:
        found = findings(path)
        allow = allowed(allow_path) if allow_path else []
    except (OSError, ValueError) as e:
        print(f"secrets-report: {getattr(e, 'strerror', None) or e}", file=sys.stderr)
        return 2
    used = set()
    for finding in found:
        detector, file_line, commit = where(finding)
        hit = next((i for i, (d, f, c) in enumerate(allow) if d == detector and f == file_line and commit.startswith(c)), None)
        if hit is not None:
            used.add(hit)
            finding["_allowed"] = True
        label = "allowed" if hit is not None else state(finding)
        print(f"{label:<10} {str(finding.get('DetectorName'))[:40]:<20} {place(finding)}")
    for i, (d, f, c) in enumerate(allow):
        if i not in used:
            print(f"secrets-report: the allowed {d} at {f} in {c} was not found; the entry may be stale")
    if expect is not None:
        hit = any(str(f.get("DetectorName")) == expect for f in found)
        print(f"secrets-report: {'a' if hit else 'no'} finding of {expect}")
        return 0 if hit else 1
    bad = [f for f in found if state(f) != "unverified" and not f.get("_allowed")]
    print(f"secrets-report: {len(found)} findings, {len(bad)} verified or unknown")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
