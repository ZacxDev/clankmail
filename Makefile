PYTHON ?= python3

.PHONY: conformance conformance-go conformance-python vectors

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
