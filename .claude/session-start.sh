#!/bin/sh
# Set the git identity of this repository and put the session on main.
# It changes no global setting (the identity is of this repository only;
# .claude/settings.json gives it to each git command too) and drops no
# commit: an existing main is checked out as it is and only fast-forwarded
# to origin/main; a new main starts at origin/main; a tree with changes
# stays on its branch.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git rev-parse --is-inside-work-tree > /dev/null 2>&1 || exit 0
git config user.name Azathothas
git config user.email ajamx101@gmail.com
git fetch -q origin main 2> /dev/null
cur=$(git symbolic-ref --short -q HEAD)
if [ "$cur" != main ]; then
    if [ -n "$(git status --porcelain 2> /dev/null)" ]; then
        echo "session-start: the tree has changes on ${cur:-a detached HEAD}; it stays there" >&2
        exit 0
    fi
    if git rev-parse -q --verify refs/heads/main > /dev/null; then
        git checkout -q main 2> /dev/null || exit 0
    elif git rev-parse -q --verify refs/remotes/origin/main > /dev/null; then
        git checkout -q -b main --track origin/main 2> /dev/null || exit 0
    else
        exit 0
    fi
fi
# A main that is behind origin/main moves forward; a main with commits of
# its own stays as it is, and the session merges by hand.
if git rev-parse -q --verify refs/remotes/origin/main > /dev/null; then
    git merge -q --ff-only origin/main 2> /dev/null ||
        echo "session-start: main and origin/main differ; nothing was moved" >&2
fi
exit 0
