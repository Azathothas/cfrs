"""Read the issue list of the GitHub API (JSON on stdin); append the numbers
that are not in SEEN to it, and with ANNOUNCE=1 print one line for each.

    python3 -I scripts/agent/new-issues.py SEEN ANNOUNCE
"""

import json
import sys

seen_path, announce = sys.argv[1], sys.argv[2] == "1"
seen = set(open(seen_path).read().split())
try:
    items = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
new = [i for i in items if "pull_request" not in i and str(i["number"]) not in seen]
with open(seen_path, "a") as f:
    for i in sorted(new, key=lambda i: i["number"]):
        f.write(str(i["number"]) + "\n")
        if announce:
            print("NEW ISSUE #%d by %s: %s" % (i["number"], i["user"]["login"], i["title"]), flush=True)
