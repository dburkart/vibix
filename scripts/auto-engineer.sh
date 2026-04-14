#!/usr/bin/env bash
# Build and run the vibix auto-engineer container.
#
# Usage:
#   scripts/auto-engineer.sh              # build image (if needed) and run /auto-engineer
#   scripts/auto-engineer.sh --build-only # only build the image
#   scripts/auto-engineer.sh -- <prompt>  # pass a custom prompt to claude
#
# Reads .env from the repo root if present (GITHUB_TOKEN, GIT_AUTHOR_NAME,
# GIT_AUTHOR_EMAIL, etc). Mounts ~/.claude so the container reuses your
# host Claude Code login.
set -euo pipefail

IMAGE="${VIBIX_IMAGE:-vibix-auto-engineer}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_only=0
if [ "${1:-}" = "--build-only" ]; then
    build_only=1
    shift
fi
if [ "${1:-}" = "--" ]; then
    shift
fi

if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$REPO_ROOT/.env"
    set +a
fi

docker build -t "$IMAGE" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"

if [ "$build_only" -eq 1 ]; then
    exit 0
fi

if [ ! -d "$HOME/.claude" ] || [ ! -f "$HOME/.claude.json" ]; then
    echo "error: $HOME/.claude or $HOME/.claude.json missing — log in to Claude Code on the host first" >&2
    exit 1
fi

docker_sec_opts=()
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    # Host is SELinux-enforcing (e.g. Fedora). Disable MAC for this container
    # so the mounted ~/.claude auth files are readable. We don't use :z/:Z to
    # avoid relabeling files the host needs.
    docker_sec_opts+=(--security-opt label=disable)
fi

# On macOS, Docker Desktop runs containers in a Linux VM so host UIDs don't
# map into the container. The OAuth token also lives in the macOS Keychain,
# not in .claude.json, so we extract it and pass it via env var.
claude_vol_opts=()
if [ "$(uname -s)" = "Darwin" ]; then
    _keychain_json="$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null || true)"
    CLAUDE_CODE_OAUTH_TOKEN="$(echo "$_keychain_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['claudeAiOauth']['accessToken'])" 2>/dev/null || true)"
    if [ -z "$CLAUDE_CODE_OAUTH_TOKEN" ]; then
        echo "error: could not read Claude OAuth token from Keychain — log in to Claude Code on the host first" >&2
        exit 1
    fi
    claude_vol_opts+=(
        -v "$HOME/.claude:/home/agent/.claude-host:ro"
        -v "$HOME/.claude.json:/home/agent/.claude-host.json:ro"
        -e CLAUDE_AUTH_STAGE=1
        -e "CLAUDE_CODE_OAUTH_TOKEN=$CLAUDE_CODE_OAUTH_TOKEN"
    )
else
    claude_vol_opts+=(
        -v "$HOME/.claude:/home/agent/.claude"
        -v "$HOME/.claude.json:/home/agent/.claude.json"
    )
fi

# If we're inside tmux, disable automatic-rename on the current window so the
# tmux window name auto-engineer chooses isn't immediately overwritten by
# tmux's pane_current_command heuristic. Also start a background poller that
# watches a shared slug file the container writes to, and renames the host
# tmux window accordingly — Claude's Bash tool has no controlling terminal
# inside the container, so OSC 2 via /dev/tty doesn't work; writing to a
# shared file is the reliable cross-boundary signal. Restore on exit.
tmux_pane_vol_opts=()
slug_file=""
poller_pid=""
restore_tmux_rename=""
if [ -n "${TMUX:-}" ] && command -v tmux >/dev/null 2>&1; then
    prev="$(tmux show-window-options -v automatic-rename 2>/dev/null || echo on)"
    tmux set-window-option automatic-rename off >/dev/null 2>&1 || true
    restore_tmux_rename="$prev"

    slug_file="$(mktemp -t vibix-ae-slug.XXXXXX)"
    tmux_pane_vol_opts+=(
        -v "$slug_file:/tmp/vibix-ae-slug"
        -e VIBIX_AE_SLUG_FILE=/tmp/vibix-ae-slug
    )

    (
        last=""
        while [ -e "$slug_file" ]; do
            cur="$(cat "$slug_file" 2>/dev/null || true)"
            if [ -n "$cur" ] && [ "$cur" != "$last" ]; then
                tmux rename-window "AE -> $cur" >/dev/null 2>&1 || true
                last="$cur"
            fi
            sleep 1
        done
    ) &
    poller_pid=$!

    trap '
        [ -n "$poller_pid" ] && kill "$poller_pid" 2>/dev/null || true
        [ -n "$slug_file" ] && rm -f "$slug_file" 2>/dev/null || true
        tmux set-window-option automatic-rename "$restore_tmux_rename" >/dev/null 2>&1 || true
    ' EXIT
fi

docker run --rm -it \
    ${docker_sec_opts[@]+"${docker_sec_opts[@]}"} \
    "${claude_vol_opts[@]}" \
    ${tmux_pane_vol_opts[@]+"${tmux_pane_vol_opts[@]}"} \
    -e GITHUB_TOKEN \
    -e ANTHROPIC_API_KEY \
    -e GIT_AUTHOR_NAME \
    -e GIT_AUTHOR_EMAIL \
    -e VIBIX_REPO \
    "$IMAGE" "$@"
