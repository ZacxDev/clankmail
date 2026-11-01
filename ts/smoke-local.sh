#!/usr/bin/env bash
# Builds go/hub, runs it on a free loopback port with a throwaway database,
# runs ts/smoke.ts against it, then stops that hub (by the PID started here)
# and removes the temp dir. Exits with the smoke test's exit code.
set -euo pipefail

NODE=${NODE:-node}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
pid=""

cleanup() {
  if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

(CDPATH= cd -- "$root/go/hub" && go build -o "$tmp/clankmail-hub" ./cmd/clankmail-hub)

# Ask the kernel for a free port; the tiny window before the hub binds it is
# acceptable for a local test.
port=$("$NODE" -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')
base="http://127.0.0.1:$port"

"$tmp/clankmail-hub" -hub hub.example -addr "127.0.0.1:$port" -db "$tmp/hub.db" >"$tmp/hub.log" 2>&1 &
pid=$!

answers() {
  "$NODE" -e 'fetch(process.argv[1]).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))' "$base/v1/channels"
}
for _ in $(seq 1 100); do
  if answers; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "smoke-local: hub exited during startup:" >&2
    cat "$tmp/hub.log" >&2
    exit 1
  fi
  sleep 0.1
done
if ! answers; then
  echo "smoke-local: hub did not answer $base/v1/channels within 10 s" >&2
  cat "$tmp/hub.log" >&2
  exit 1
fi

rc=0
"$NODE" "$root/ts/smoke.ts" "$base" --hub-name hub.example || rc=$?
if [[ $rc -ne 0 ]]; then
  echo "--- hub log ---" >&2
  cat "$tmp/hub.log" >&2
fi
exit "$rc"
