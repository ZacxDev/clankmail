PYTHON ?= python3
NODE ?= node

.PHONY: conformance conformance-go conformance-python conformance-ts vectors hub-test hub-mutate hub-image

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
