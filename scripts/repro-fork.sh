#!/usr/bin/env bash
# CI-friendly wrapper around `cargo xtask repro-fork` — the deterministic
# reproducer harness for the init fork+exec+wait flake tracked by epic
# #501 / sub-issue #506.
#
# This is a thin shim over the xtask subcommand so CI / smoke
# orchestrators that prefer to invoke a shell script (rather than
# cargo directly) can plug it in without duplicating the boot logic.
# The xtask owns the heartbeat watchdog; this script's job is to:
#
#   1. run one boot of the reproducer ISO,
#   2. forward its serial log verbatim to the caller's stdout,
#   3. exit non-zero on any stall/panic/failure detected by xtask.
#
# Usage:
#   scripts/repro-fork.sh                 # single run
#   scripts/repro-fork.sh --runs N        # N sequential runs; fail on
#                                         # the first non-zero exit
#
# Env:
#   REPRO_FORK_CYCLES=<N>   override the harness cycle count (compile-time)
#
# The --runs option is meant for local soak (#504 / #505 validation):
# run N times, any failure fails the whole invocation.  It is *not* for
# CI gating on its own — wave-3 tightens that up.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

runs=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)
            runs="$2"
            shift 2
            ;;
        --runs=*)
            runs="${1#--runs=}"
            shift
            ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed -e 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "repro-fork.sh: unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

if ! [[ "$runs" =~ ^[0-9]+$ ]] || [[ "$runs" -lt 1 ]]; then
    echo "repro-fork.sh: --runs must be a positive integer (got: $runs)" >&2
    exit 2
fi

fail=0
for ((i = 1; i <= runs; i++)); do
    echo "=== repro-fork run $i/$runs ==="
    if ! cargo xtask repro-fork; then
        echo "=== repro-fork run $i/$runs FAILED ===" >&2
        fail=1
        break
    fi
    echo "=== repro-fork run $i/$runs ok ==="
done

exit "$fail"
