PYTHON ?= python3

.PHONY: conformance conformance-go conformance-python vectors hub-test hub-mutate

# Both implementations against the same published vectors (SPEC.md §12).
conformance: conformance-go conformance-python

conformance-go:
	go test -count=1 ./go/...

conformance-python:
	cd python && $(PYTHON) conformance.py ../vectors/vectors.json

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
