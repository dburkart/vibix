#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required for autonomous operation}"

# On macOS, auth files are mounted read-only to staging paths (to work around
# Docker Desktop's UID mismatch). Copy them into the agent home so Claude Code
# can read and write them with the correct ownership.
if [ "${CLAUDE_AUTH_STAGE:-0}" = "1" ]; then
    if [ -d /home/agent/.claude-host ]; then
        cp -a /home/agent/.claude-host/. /home/agent/.claude/
    fi
    if [ -f /home/agent/.claude-host.json ]; then
        cp /home/agent/.claude-host.json /home/agent/.claude.json
    fi
fi

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
