PYTHON ?= python3
NODE ?= node

.PHONY: conformance conformance-go conformance-python conformance-ts vectors hub-test hub-mutate hub-consumer-check hub-image smoke-local

# Every implementation against the same published vectors (SPEC.md §12).
conformance: conformance-go conformance-python conformance-ts

conformance-go:
	go test -count=1 ./go/...

conformance-python:
	cd python && $(PYTHON) conformance.py ../vectors/vectors.json

# Written from SPEC.md + vectors only (ts/NOTES.md). Node >= 23.6 runs .ts directly.
conformance-ts:
	$(NODE) ts/conformance.ts vectors/vectors.json

# Regenerate vectors from fixed seeds. Output must be byte-identical to the
# committed file unless the spec changed.
vectors:
	go run ./go/cmd/genvectors vectors/vectors.json

# The hub is its own module (go/hub) so the root module, which ships the
# reference package, has no external dependencies.
hub-test:
	cd go/hub && go test -race -count=1 ./...

# Mutation battery for the hub's security guards (go/hub/testdata/mutate.py).
hub-mutate:
	$(PYTHON) go/hub/testdata/mutate.py

# go/hub as an outside module sees it: the local replace dropped, so the
# clankmail it requires in go/hub/go.mod is the published revision named there.
# Fails when the hub (or its tests) uses root-package API newer than that
# revision; bump the require then. Needs the network, so not part of hub-test.
hub-consumer-check:
	@set -e; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	cp -R go/hub/. "$$d"/; cd "$$d"; \
	go mod edit -dropreplace github.com/ZacxDev/clankmail; \
	GOFLAGS=-mod=mod go build ./...; \
	GOFLAGS=-mod=mod go test -count=1 -run '^$$' ./... >/dev/null; \
	echo "hub-consumer-check: go/hub builds against $$(go list -m -f '{{.Path}}@{{.Version}}' github.com/ZacxDev/clankmail)"

# Container image for the hub; the build context is the repo root.
hub-image:
	docker build -f go/hub/Dockerfile -t clankmail-hub:dev .

# End-to-end smoke test (ts/smoke.ts) against a throwaway local hub.
smoke-local:
	NODE=$(NODE) bash ts/smoke-local.sh
