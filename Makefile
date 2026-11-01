PYTHON ?= python3
NODE ?= node

.PHONY: conformance conformance-go conformance-python conformance-ts vectors hub-test hub-mutate hub-image smoke-local curator-test curator-image

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

# Container image for the hub; the build context is the repo root.
hub-image:
	docker build -f go/hub/Dockerfile -t clankmail-hub:dev .

# Feed curator (go/cmd/curator): unit tests in the root module. Its end-to-end
# test against the real hub (go/hub/curator_e2e_test.go) runs in hub-test.
curator-test:
	go test -race -count=1 ./go/curator/... ./go/cmd/curator/...

# Container image for the curator; the build context is the repo root.
curator-image:
	docker build -f go/cmd/curator/Dockerfile -t clankmail-curator:dev .

# End-to-end smoke test (ts/smoke.ts) against a throwaway local hub.
smoke-local:
	NODE=$(NODE) bash ts/smoke-local.sh
