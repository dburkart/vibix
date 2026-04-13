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

docker run --rm -it \
    ${docker_sec_opts[@]+"${docker_sec_opts[@]}"} \
    -v "$HOME/.claude:/home/agent/.claude" \
    -v "$HOME/.claude.json:/home/agent/.claude.json" \
    -e GITHUB_TOKEN \
    -e ANTHROPIC_API_KEY \
    -e GIT_AUTHOR_NAME \
    -e GIT_AUTHOR_EMAIL \
    -e VIBIX_REPO \
    "$IMAGE" "$@"
