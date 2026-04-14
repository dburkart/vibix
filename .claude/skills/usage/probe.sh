#!/usr/bin/env bash
# Read Claude Code session-quota state by making a 1-token probe to /v1/messages
# and parsing the anthropic-ratelimit-unified-* response headers. This is the
# same data Claude Code's own statusline uses.
#
# Output: single-line JSON on stdout. Exit 0 on success, non-zero on failure.
#
# Cache: ~/.claude/cache/usage-probe.json, 60s TTL. Pass --force to bypass.

set -u
CACHE="${HOME}/.claude/cache/usage-probe.json"
TTL=60
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if [[ $FORCE -eq 0 && -f "$CACHE" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    mtime=$(stat -f %m "$CACHE" 2>/dev/null || echo 0)
  else
    mtime=$(stat -c %Y "$CACHE" 2>/dev/null || echo 0)
  fi
  age=$(( $(date +%s) - mtime ))
  if [[ $age -lt $TTL ]]; then
    cat "$CACHE"; exit 0
  fi
fi

# On macOS, the OAuth token lives in the Keychain; on Linux it's in .credentials.json
if [[ "$(uname -s)" == "Darwin" ]]; then
  _keychain_json="$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null || true)"
  TOK=$(echo "$_keychain_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['claudeAiOauth']['accessToken'])" 2>/dev/null || true)
  [[ -n "$TOK" ]] || { echo '{"error":"no-credentials"}'; exit 2; }
else
  CREDS="${HOME}/.claude/.credentials.json"
  [[ -r "$CREDS" ]] || { echo '{"error":"no-credentials"}'; exit 2; }
  TOK=$(python3 -c "import json,sys;print(json.load(open('$CREDS'))['claudeAiOauth']['accessToken'])" 2>/dev/null) || {
    echo '{"error":"credentials-parse-failed"}'; exit 2;
  }
fi

HDR=$(mktemp); BODY=$(mktemp)
trap 'rm -f "$HDR" "$BODY"' EXIT

http=$(curl -sS -o "$BODY" -D "$HDR" -w '%{http_code}' --max-time 10 \
  -H "Authorization: Bearer $TOK" \
  -H "anthropic-beta: oauth-2025-04-20" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -X POST https://api.anthropic.com/v1/messages \
  -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"."}],"system":"You are Claude Code, Anthropic'"'"'s official CLI for Claude."}')

python3 - "$HDR" "$http" <<'PY' | tee "$CACHE"
import sys, re, json, time
hdr_path, http = sys.argv[1], sys.argv[2]
h = {}
for line in open(hdr_path):
    m = re.match(r'([^:]+):\s*(.*?)\r?$', line)
    if m: h[m.group(1).lower()] = m.group(2)
def g(k):
    return h.get(f'anthropic-ratelimit-unified-{k}')
out = {"http": int(http), "fetched_at": int(time.time())}
for win in ('5h','7d','overage'):
    u, r, s = g(f'{win}-utilization'), g(f'{win}-reset'), g(f'{win}-status')
    if u is None and r is None: continue
    out[win] = {
        "utilization": float(u) if u is not None else None,
        "resets_at": int(r) if r is not None else None,
        "status": s,
    }
if '5h' not in out:
    out["error"] = "no-rate-limit-headers"
print(json.dumps(out))
PY
