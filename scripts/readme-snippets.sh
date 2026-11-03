#!/usr/bin/env bash
# Runs the Go, Python and TypeScript snippets from README.md's "Try it in 30
# seconds" section, extracted from the README itself, against a throwaway local
# hub on 127.0.0.1:8080 (the address the snippets use). Each snippet must exit
# 0, print an m_ id, and leave its handle resolvable. Then the read-a-channel
# snippet (the second ```ts block) runs against a #llm-papers channel that
# scripts/readme-seed.ts fills with 205 posts, and must print exactly the 3
# newest. The Go snippet builds against this checkout (a replace), not the
# published module.
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

# extract LANG WANT IDX OUT: the IDX-th ```LANG block in the section; fails
# unless the section has exactly WANT of them.
extract() {
  awk -v lang="$1" -v want="$2" -v idx="$3" '
    /^## / { insec = ($0 == "## Try it in 30 seconds") }
    insec && !inblk && $0 == "```" lang { inblk = 1; n++; next }
    inblk && $0 == "```" { inblk = 0; next }
    inblk && n == idx { print }
    END { if (n != want) { print "want " want " ```" lang " block(s) in the section, found " n > "/dev/stderr"; exit 1 } }
  ' "$root/README.md" > "$4"
}

mkdir -p "$tmp/go" "$tmp/ts"
extract go 1 1 "$tmp/go/main.go"
extract python 1 1 "$tmp/demo.py"
extract ts 2 1 "$tmp/ts/demo.ts"
extract ts 2 2 "$tmp/ts/read.ts"

# The snippets' own setup steps, done against this checkout.
(CDPATH= cd -- "$tmp/go" && go mod init demo >/dev/null 2>&1 \
  && go mod edit -require=github.com/ZacxDev/clankmail@v0.0.0 -replace=github.com/ZacxDev/clankmail="$root")
cp "$root/ts/clankmail.ts" "$tmp/ts/"   # "save as ts/demo.ts" next to the library

up() { curl -fs --max-time 2 -o /dev/null http://127.0.0.1:8080/v1/channels; }
# Something already answering on 8080 (e.g. the README's own hub) would be
# tested instead of the hub built here, so refuse rather than pass on it.
if up; then
  echo "readme-snippets: 127.0.0.1:8080 is already in use; stop that hub first" >&2
  exit 1
fi

(CDPATH= cd -- "$root/go/hub" && go build -o "$tmp/clankmail-hub" ./cmd/clankmail-hub)
"$tmp/clankmail-hub" -hub hub.example -addr 127.0.0.1:8080 -db "$tmp/hub.db" >"$tmp/hub.log" 2>&1 &
pid=$!

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
kill -0 "$pid" 2>/dev/null || { echo "readme-snippets: the hub built here is not running:" >&2; cat "$tmp/hub.log" >&2; exit 1; }

fails=0
check() { # name handle command...
  local name=$1 handle=$2 out code
  shift 2
  if ! out=$(timeout 120 "$@" 2>&1); then
    echo "FAIL $name: exited non-zero:"; echo "$out"; fails=$((fails + 1)); return
  fi
  if [[ $out != *'"id":"m_'* ]]; then
    echo "FAIL $name: no m_ id in output:"; echo "$out"; fails=$((fails + 1)); return
  fi
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/v1/handles/$handle")
  if [[ $code != 200 ]]; then
    echo "FAIL $name: GET /v1/handles/$handle -> $code"; fails=$((fails + 1)); return
  fi
  echo "ok $name"
}

check go go-demo go -C "$tmp/go" run .
check python py-demo env PYTHONPATH="$root/python" "$PYTHON" "$tmp/demo.py"
check ts ts-demo "$NODE" --no-warnings "$tmp/ts/demo.ts"

# Read-a-channel: seed after the write snippets, then the output must be the 3
# newest posts, oldest of them first, each line "<ISO time> <k_ author> <text>".
if ! seed_out=$(timeout 120 "$NODE" --no-warnings "$root/scripts/readme-seed.ts" http://127.0.0.1:8080 2>&1); then
  echo "FAIL read: seeding failed:"; echo "$seed_out"; fails=$((fails + 1))
elif ! out=$(timeout 120 "$NODE" --no-warnings "$tmp/ts/read.ts" 2>&1); then
  echo "FAIL read: exited non-zero:"; echo "$out"; fails=$((fails + 1))
else
  got=$(sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z k_[a-z2-7]{52} //' <<<"$out")
  want=$'"seed post 203"\n"seed post 204"\n"seed post 205"'
  if [[ $got != "$want" ]]; then
    echo "FAIL read: want the 3 newest posts as \"<time> <k_ author> <text>\" lines, got:"; echo "$out"
    fails=$((fails + 1))
  else
    echo "ok read"
  fi
fi

if (( fails )); then
  echo "--- hub log ---" >&2
  cat "$tmp/hub.log" >&2
  exit 1
fi
