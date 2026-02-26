#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://juice-shop.local:3000/}"
POLL_SECONDS="${POLL_SECONDS:-2}"
MAX_POLLS="${MAX_POLLS:-10}"

AGENT_BURP_BIN="${AGENT_BURP_BIN:-./agent-burp}"

if [[ ! -x "$AGENT_BURP_BIN" ]]; then
  echo "error: agent-burp binary not found or not executable at '$AGENT_BURP_BIN'" >&2
  echo "hint: run 'go build -o agent-burp ./cmd/agent-burp' from agent-burp root" >&2
  exit 1
fi

extract_json_field() {
  local field="$1"
  local payload="$2"
  python3 - "$field" "$payload" <<'PY'
import json
import sys

field = sys.argv[1]
raw = sys.argv[2]
obj = json.loads(raw)

cur = obj
for part in field.split('.'):
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break

if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

echo "== Ensuring daemon connection =="
"$AGENT_BURP_BIN" daemon restart --json >/dev/null
"$AGENT_BURP_BIN" open --json >/dev/null

echo "== Starting crawl: $URL =="
start_out="$($AGENT_BURP_BIN crawl start --url "$URL" --json)"
echo "$start_out"

job_id="$(extract_json_field 'data.jobId' "$start_out")"
if [[ -z "$job_id" ]]; then
  echo "error: could not parse crawl job ID" >&2
  exit 1
fi

echo "== Polling status for job: $job_id =="
for ((i=1; i<=MAX_POLLS; i++)); do
  status_out="$($AGENT_BURP_BIN job status --id "$job_id" --json)"
  state="$(extract_json_field 'data.state' "$status_out")"
  req_count="$(extract_json_field 'data.details.requestCount' "$status_out")"
  echo "poll=$i state=${state:-unknown} requestCount=${req_count:-0}"

  if [[ "$state" != "running" && "$state" != "queued" ]]; then
    break
  fi
  sleep "$POLL_SECONDS"
done

echo "== Cancelling crawl =="
cancel_out="$($AGENT_BURP_BIN job cancel --id "$job_id" --json)"
echo "$cancel_out"

echo "== Final status =="
final_out="$($AGENT_BURP_BIN job status --id "$job_id" --json)"
echo "$final_out"

final_state="$(extract_json_field 'data.state' "$final_out")"
if [[ "$final_state" != "cancelled" ]]; then
  echo "warning: final state is '$final_state' (expected 'cancelled')" >&2
  exit 2
fi

echo "ok: crawl start/stop script completed"
