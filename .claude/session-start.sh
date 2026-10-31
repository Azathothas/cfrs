#!/bin/sh
# Set the git identity and the branch for each session.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git config user.name Azathothas
git config user.email ajamx101@gmail.com
git config --global user.name Azathothas
git config --global user.email ajamx101@gmail.com
# Work on main only.
cur=$(git symbolic-ref --short -q HEAD)
if [ "$cur" != "main" ]; then
  git fetch -q origin main 2>/dev/null
  if git rev-parse -q --verify origin/main >/dev/null; then
    git checkout -q -B main origin/main 2>/dev/null || true
  else
    git checkout -q -B main 2>/dev/null || true
  fi
fi
exit 0
