"""Read the issue list of the GitHub API (JSON on stdin); append the numbers
that are not in SEEN to it, and with ANNOUNCE=1 print one line for each.
Keep each issue of the list (number, author, title, body, state) in
issues/NUMBER.json beside SEEN: GitHub deletes the issues of a suspended
account, and the copy keeps the text.

    python3 -I scripts/agent/new-issues.py SEEN ANNOUNCE
"""

import json
import os
import sys

seen_path, announce = sys.argv[1], sys.argv[2] == "1"
seen = set(open(seen_path).read().split())
try:
    items = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
issues = [i for i in items if isinstance(i, dict) and "pull_request" not in i]
keep = os.path.join(os.path.dirname(os.path.abspath(seen_path)), "issues")
os.makedirs(keep, exist_ok=True)
for i in issues:
    fields = ("number", "title", "body", "state", "created_at", "updated_at", "closed_at", "html_url")
    copy = {k: i.get(k) for k in fields}
    copy["user"] = (i.get("user") or {}).get("login")
    copy["labels"] = [l.get("name") for l in i.get("labels") or []]
    path = os.path.join(keep, "%d.json" % i["number"])
    with open(path + ".tmp", "w") as f:
        json.dump(copy, f, indent=1)
    os.replace(path + ".tmp", path)
new = [i for i in issues if str(i["number"]) not in seen]
with open(seen_path, "a") as f:
    for i in sorted(new, key=lambda i: i["number"]):
        f.write(str(i["number"]) + "\n")
        if announce:
            print("NEW ISSUE #%d by %s: %s" % (i["number"], i["user"]["login"], i["title"]), flush=True)
