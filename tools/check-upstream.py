#!/usr/bin/env python3
"""Compare the cloudflared files that cfrs follows with cloudflared.

  python3 -I tools/check-upstream.py [--plant-sum PATH] [PIN]

PIN is src/cloudflare/cloudflared-pin.txt when it is not given. The checks:

1. Each `copy` file of cfrs has the recorded SHA-256, and each `roots` file
   has the certificates of the upstream file.
2. Each upstream file at the pinned tag has the recorded SHA-256.
3. Each upstream file at the newest release has the recorded SHA-256. A
   newer release with the same files is a note: move the pin.
4. The pinned release is at most 9 months old.

--plant-sum PATH changes the recorded sum of PATH (an upstream path or the
path of the copy in cfrs) before the checks: the check of that file must
then fail. Exit 0: all checks pass. Exit 1: a check failed; each line names
the file. Exit 2: a file or the network could not be read.
"""

import base64
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = os.environ.get("CHECK_UPSTREAM_API", "https://forge.web.pkgforge.dev/github")
REPO = "cloudflare/cloudflared"
MAX_AGE_DAYS = 274


class Unreadable(Exception):
    pass


def get_json(path: str):
    url = f"{API}/{path}"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "cfrs-check-upstream"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and API.startswith("https://api.github.com"):
        request.add_header("Authorization", f"Bearer {token}")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise Unreadable(f"{path}: not found") from e
            last = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
    raise Unreadable(f"{url}: {last}")


def upstream(path: str, ref: str) -> bytes:
    data = get_json(f"repos/{REPO}/contents/{path}?ref={ref}")
    if not isinstance(data, dict) or "content" not in data:
        raise Unreadable(f"{path} at {ref}: no content")
    return base64.b64decode(data["content"])


def certificates(text: str) -> list[str]:
    found = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    return [re.sub(r"\s", "", c) for c in found]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main(argv: list[str]) -> int:
    plant = None
    if len(argv) >= 2 and argv[0] == "--plant-sum":
        plant, argv = argv[1], argv[2:]
    pin_path = argv[0] if argv else "src/cloudflare/cloudflared-pin.txt"
    try:
        lines = [l.split() for l in open(pin_path, encoding="utf-8") if l.strip() and not l.startswith("#")]
    except OSError as e:
        print(f"check-upstream: {pin_path}: {e}", file=sys.stderr)
        return 2
    meta = {l[0]: l[1] for l in lines if l[0] in ("tag", "commit", "released")}
    files = [l for l in lines if l[0] in ("copy", "roots", "source")]
    if plant is not None:
        hit = [f for f in files if plant in (f[1], f[3] if len(f) > 3 else None)]
        if not hit:
            print(f"check-upstream: --plant-sum {plant}: no such file in {pin_path}", file=sys.stderr)
            return 2
        hit[0][2] = "0" * 64
    faults = []
    try:
        for kind, path, want, *local in files:
            # 1. The copies of cfrs.
            if kind == "copy":
                got = sha256(open(local[0], "rb").read())
                if got != want:
                    faults.append(f"{local[0]}: the copy of {path} has the SHA-256 {got}, not {want}")
            # 2. Upstream at the pinned tag.
            data = upstream(path, meta["tag"])
            if sha256(data) != want:
                faults.append(f"{path}: at {meta['tag']} it has the SHA-256 {sha256(data)}, not {want}")
            if kind == "roots":
                ours = certificates(open(local[0], encoding="utf-8").read())
                if certificates(data.decode("utf-8", "replace")) != ours:
                    faults.append(f"{local[0]}: its certificates differ from {path} at {meta['tag']}")
        # 3. The newest release.
        latest = get_json(f"repos/{REPO}/releases/latest")
        tag = latest.get("tag_name")
        if not tag:
            raise Unreadable("the newest release has no tag")
        if tag != meta["tag"]:
            moved = []
            for kind, path, want, *local in files:
                if sha256(upstream(path, tag)) != want:
                    moved.append(path)
            if moved:
                for path in moved:
                    faults.append(f"{path}: changed between {meta['tag']} and {tag}; check the code of cfrs that follows it, then move the pin")
            else:
                print(f"check-upstream: {tag} is newer than the pin {meta['tag']}, and the files are the same; move the pin")
    except Unreadable as e:
        print(f"check-upstream: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"check-upstream: {e}", file=sys.stderr)
        return 2
    # 4. The age of the pin.
    released = datetime.date.fromisoformat(meta["released"])
    age = (datetime.date.today() - released).days
    if age > MAX_AGE_DAYS:
        faults.append(f"{pin_path}: the pin {meta['tag']} is {age} days old (limit {MAX_AGE_DAYS})")
    for fault in faults:
        print(fault)
    print(f"check-upstream: cloudflared {meta['tag']}, {len(files)} files, {len(faults)} faults")
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
