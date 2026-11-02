"""Helpers of watch-runs.sh. With DONE_IDS: read a run list (JSON on stdin)
and print RUN lines for the ended runs that are not in DONE_IDS, then a
STATE line (runs, runs not ended). With --jobs: read a job list and print
the jobs that did not pass, with their failed steps.
"""

import json
import sys

data = json.load(sys.stdin)
if sys.argv[1:] == ["--jobs"]:
    for j in data.get("jobs", []):
        if j["conclusion"] not in ("success", "skipped"):
            steps = [s["name"] for s in j.get("steps", []) if s.get("conclusion") == "failure"]
            print("  job", j["id"], j["name"], j["conclusion"], steps)
    sys.exit(0)
done = set(sys.argv[1].split()) if len(sys.argv) > 1 else set()
runs = data.get("workflow_runs", [])
pending = 0
for r in runs:
    if r["status"] != "completed":
        pending += 1
        continue
    if str(r["id"]) in done:
        continue
    print("RUN", r["id"], r["name"], r["conclusion"], r["html_url"])
print("STATE", len(runs), pending)
