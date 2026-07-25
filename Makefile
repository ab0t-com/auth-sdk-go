# ab0t Auth Service Go SDK

GO ?= go

.PHONY: help
help:
	@echo "test    - run the test suite"
	@echo "vet     - go vet"
	@echo "fmt     - gofmt -l -w"
	@echo "cover   - test with a coverage report"
	@echo "check   - fmt-check + vet + test + stdlib-only assertion (what CI runs)"
	@echo "spec    - fetch the live OpenAPI spec to /tmp/auth-openapi.json"

.PHONY: test
test:
	$(GO) test ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	gofmt -l -w .

.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

# stdlib-only is a hard property of this module, not a preference: it is embedded
# in other people's binaries, so a dependency here becomes a dependency everywhere.
.PHONY: check
check:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting (run make fmt)"; exit 1)
	$(GO) vet ./...
	$(GO) test ./...
	@grep -q '^require' go.mod && (echo "FAIL: go.mod gained a dependency; this module must stay stdlib-only"; exit 1) || echo "OK: stdlib-only"

.PHONY: spec
spec:
	curl -sS https://auth.service.ab0t.com/openapi.json -o /tmp/auth-openapi.json
	@echo "fetched -> /tmp/auth-openapi.json"
	@jq -r '"\(.info.title) \(.info.version) — \(.paths|length) paths"' /tmp/auth-openapi.json
