#!/usr/bin/env python3
"""Compare TODO/github.txt with GitHub.

  python3 -I scripts/check-github-numbers.py [--plant-drop N] [--from FILE] [--repo OWNER/REPO]

TODO/github.txt lists the numbers of the repository (each an issue or a pull
request) with their states: each number from FIRST on, and each open number
before FIRST. A closed number before FIRST is not in the record. `cargo todo
check` holds TODO/issues.md to the list with no network; this script holds
the list to GitHub. An issue that GitHub deleted is `NUMBER issue deleted`
in the list, and agrees with its absence from GitHub.

The script reads the issue list of the GitHub REST API
(`repos/OWNER/REPO/issues?state=all`, which also holds each pull request).
The API is CHECK_GITHUB_API: by default the read-only mirror
https://forge.web.pkgforge.dev/github (CLAUDE.md); CI sets
https://api.github.com and GITHUB_TOKEN. The repository is --repo, else
GITHUB_REPOSITORY, else the remote origin of git.

  --plant-drop N   remove N from the list first: the run must then exit 1
  --from FILE      read the issue list (a JSON array) from FILE, not from the API
  --repo OWNER/REPO

Exit 0 when the list agrees with GitHub, 1 at a difference (one line for
each number), 2 when GitHub or the list cannot be read.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "TODO" / "github.txt"
# The first number that the record holds closed. The record did not import
# the closed numbers before it.
FIRST = 311
API = os.environ.get("CHECK_GITHUB_API", "https://forge.web.pkgforge.dev/github").rstrip("/")


class Unreadable(Exception):
    pass


def listed(drop):
    """The list: {number: (kind, state)}. A line is `NUMBER issue|pull
    open|closed` or `NUMBER issue deleted`; `#` starts a comment."""
    out = {}
    try:
        text = LIST.read_text(encoding="utf-8")
    except OSError as e:
        raise Unreadable(f"{LIST}: {e}") from e
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = line.split()
        ok = len(words) == 3 and words[0].isdigit() and (
            (words[1] in ("issue", "pull") and words[2] in ("open", "closed"))
            or (words[1] == "issue" and words[2] == "deleted")
        )
        if not ok:
            raise Unreadable(f"{LIST}:{n}: not NUMBER issue|pull open|closed, or NUMBER issue deleted: {line!r}")
        number = int(words[0])
        if number in out:
            raise Unreadable(f"{LIST}:{n}: #{number} is listed twice")
        out[number] = (words[1], words[2])
    if drop is not None:
        if drop not in out:
            raise Unreadable(f"--plant-drop {drop}: #{drop} is not in {LIST.name}, so the plant changes nothing")
        del out[drop]
    return out


def repository(given):
    if given:
        return given
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    try:
        url = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        url = ""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
    if not m:
        raise Unreadable("no repository: give --repo OWNER/REPO, or set GITHUB_REPOSITORY")
    return m.group(1)


def get_json(url):
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "check-github-numbers"}
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token and API.startswith("https://api.github.com"):
        request.add_header("Authorization", f"Bearer {token}")
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
    raise Unreadable(f"{url}: {last}")


def issue_list(repo, path):
    """Each item of the issue list of the API, from `path` when it is given."""
    if path:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise Unreadable(f"{path}: {e}") from e
    items = []
    for page in range(1, 1000):
        url = f"{API}/repos/{repo}/issues?state=all&per_page=100&page={page}"
        if "api.github.com" not in API:
            # The mirror keeps answers in a cache: a new query each run.
            url += f"&n={random.randrange(1 << 30)}"
        got = get_json(url)
        if not isinstance(got, list):
            raise Unreadable(f"{url}: not a list: {str(got)[:200]}")
        items += got
        if len(got) < 100:
            return items
    raise Unreadable("more than 999 pages of issues")


def on_github(items):
    out = {}
    for item in items:
        kind = "pull" if "pull_request" in item else "issue"
        out[int(item["number"])] = (kind, "open" if item["state"] == "open" else "closed")
    return out


def differences(mine, theirs):
    found = []
    for number in sorted(set(mine) | set(theirs)):
        here, there = mine.get(number), theirs.get(number)
        if here == there:
            continue
        # The record did not import a closed number before FIRST.
        if number < FIRST and here is None and there[1] != "open":
            continue
        # A deleted issue agrees with its absence from GitHub, and only then.
        if there is None and here[1] == "deleted":
            continue
        if here is None:
            found.append(f"#{number} on GitHub, {there[0]} {there[1]}, has no line in TODO/github.txt")
        elif there is None:
            found.append(f"#{number} is in TODO/github.txt ({here[0]} {here[1]}), and GitHub has no such number")
        else:
            found.append(f"#{number}: TODO/github.txt says {here[0]} {here[1]}, GitHub {there[0]} {there[1]}")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plant-drop", type=int)
    parser.add_argument("--from", dest="source")
    parser.add_argument("--repo")
    args = parser.parse_args()
    try:
        mine = listed(args.plant_drop)
        theirs = on_github(issue_list(repository(args.repo) if not args.source else None, args.source))
    except Unreadable as e:
        print(f"check-github-numbers: {e}", file=sys.stderr)
        return 2
    # A read that gave nothing must not pass as a list with no difference.
    if not theirs:
        print("check-github-numbers: GitHub gave no number", file=sys.stderr)
        return 2
    found = differences(mine, theirs)
    for line in found:
        print(f"FAIL  {line}")
    if found:
        print(
            f"check-github-numbers: {len(found)} difference(s): map each issue (TODO/RULES.md), then change "
            "TODO/github.txt"
        )
        return 1
    held = sum(1 for n in theirs if n >= FIRST or theirs[n][1] == "open")
    print(f"ok    TODO/github.txt holds the {held} numbers of GitHub from #{FIRST} on and the open ones before")
    return 0


if __name__ == "__main__":
    sys.exit(main())
