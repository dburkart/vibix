#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required for autonomous operation}"

GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-vibix auto-engineer}"
GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-noreply@anthropic.com}"
REPO_SLUG="${VIBIX_REPO:-dburkart/vibix}"
WORKDIR="${VIBIX_WORKDIR:-/home/agent/work}"

git config --global user.name  "$GIT_AUTHOR_NAME"
git config --global user.email "$GIT_AUTHOR_EMAIL"
git config --global init.defaultBranch main

# gh reads the token from the env; wire it into git so pushes authenticate.
gh auth setup-git >/dev/null

cd "$WORKDIR"
if [ ! -d .git ]; then
    gh repo clone "$REPO_SLUG" .
fi

# If no args given, fall back to the CMD default (/auto-engineer).
if [ "$#" -eq 0 ]; then
    set -- /auto-engineer
fi

exec claude --dangerously-skip-permissions "$@"
