#!/usr/bin/env bash
# Runs the Go, Python and TypeScript snippets from README.md's "Try it in 30
# seconds" section, extracted from the README itself, against a throwaway local
# hub on 127.0.0.1:8080 (the address the snippets use). Each snippet must exit
# 0, print an m_ id, and leave its handle resolvable. The Go snippet builds
# against this checkout (a replace), not the published module.
# Needs Go, Node 24 and Python 3 with `cryptography`.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
NODE=${NODE:-node}
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

# extract LANG OUT: the single ```LANG block in the section; fails unless exactly one.
extract() {
  awk -v lang="$1" '
    /^## / { insec = ($0 == "## Try it in 30 seconds") }
    insec && !inblk && $0 == "```" lang { inblk = 1; n++; next }
    inblk && $0 == "```" { inblk = 0; next }
    inblk { print }
    END { if (n != 1) { print "want exactly one ```" lang " block in the section, found " n > "/dev/stderr"; exit 1 } }
  ' "$root/README.md" > "$2"
}

mkdir -p "$tmp/go" "$tmp/ts"
extract go "$tmp/go/main.go"
extract python "$tmp/demo.py"
extract ts "$tmp/ts/demo.ts"

# The snippets' own setup steps, done against this checkout.
(CDPATH= cd -- "$tmp/go" && go mod init demo >/dev/null 2>&1 \
  && go mod edit -require=github.com/ZacxDev/clankmail@v0.0.0 -replace=github.com/ZacxDev/clankmail="$root")
cp "$root/ts/clankmail.ts" "$tmp/ts/"   # "save as ts/demo.ts" next to the library

(CDPATH= cd -- "$root/go/hub" && go build -o "$tmp/clankmail-hub" ./cmd/clankmail-hub)
"$tmp/clankmail-hub" -hub hub.example -addr 127.0.0.1:8080 -db "$tmp/hub.db" >"$tmp/hub.log" 2>&1 &
pid=$!

up() { curl -fs -o /dev/null http://127.0.0.1:8080/v1/channels; }
for _ in $(seq 1 100); do
  up && break
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "readme-snippets: hub exited during startup (is 127.0.0.1:8080 in use?):" >&2
    cat "$tmp/hub.log" >&2
    exit 1
  fi
  sleep 0.1
done
up || { echo "readme-snippets: hub did not answer within 10 s" >&2; exit 1; }

fails=0
check() { # name handle command...
  local name=$1 handle=$2 out code
  shift 2
  if ! out=$("$@" 2>&1); then
    echo "FAIL $name: exited non-zero:"; echo "$out"; fails=$((fails + 1)); return
  fi
  if [[ $out != *'"id":"m_'* ]]; then
    echo "FAIL $name: no m_ id in output:"; echo "$out"; fails=$((fails + 1)); return
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/v1/handles/$handle")
  if [[ $code != 200 ]]; then
    echo "FAIL $name: GET /v1/handles/$handle -> $code"; fails=$((fails + 1)); return
  fi
  echo "ok $name"
}

check go go-demo go -C "$tmp/go" run .
check python py-demo env PYTHONPATH="$root/python" "$PYTHON" "$tmp/demo.py"
check ts ts-demo "$NODE" --no-warnings "$tmp/ts/demo.ts"

if (( fails )); then
  echo "--- hub log ---" >&2
  cat "$tmp/hub.log" >&2
  exit 1
fi
