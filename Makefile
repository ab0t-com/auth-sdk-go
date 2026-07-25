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
	@echo "drift   - check this SDK against the LIVE OpenAPI spec"
	@echo "release - VERSION=x.y.z  bump, tag and push a release (see RELEASING.md)"

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

# The spec is the source of truth and it moves. Twice the SDK has drifted from it
# silently — once on the Zanzibar tuple shape, once on the bulk-check response —
# and both times a human found it by reading files. This makes it one command.
.PHONY: drift
drift:
	python3 scripts/spec-coverage.py

.PHONY: drift-strict
drift-strict:
	python3 scripts/spec-coverage.py --strict

.PHONY: spec
spec:
	curl -sS https://auth.service.ab0t.com/openapi.json -o /tmp/auth-openapi.json
	@echo "fetched -> /tmp/auth-openapi.json"
	@jq -r '"\(.info.title) \(.info.version) — \(.paths|length) paths"' /tmp/auth-openapi.json

# Every change that reaches main gets a version bump. Not "significant" changes -
# every one. v0.1.0 shipped without a fix that was already on main because the fix
# was committed after the tag, and nothing local could tell: the working tree was
# correct, the tests passed, only a clean-room fetch by tag showed the gap.
#
# So the bump is a command with guards, not a thing to remember. See RELEASING.md.
.PHONY: release
release:
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=x.y.z"; exit 1)
	@echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must be x.y.z, got '$(VERSION)'"; exit 1)
	@# A release must be reproducible from its tag alone.
	@test -z "$$(git status --porcelain)" || (echo "FAIL: working tree is dirty - commit or stash first"; git status --short; exit 1)
	@# Write the changelog while you still remember who it breaks.
	@grep -q '^## \[$(VERSION)\]' CHANGELOG.md || (echo "FAIL: CHANGELOG.md has no '## [$(VERSION)]' section - write it first"; exit 1)
	@# Re-tagging silently changes what a consumer already fetched.
	@! git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null || (echo "FAIL: tag v$(VERSION) already exists"; exit 1)
	@sed -i 's/^const Version = ".*"/const Version = "$(VERSION)"/' version.go
	$(MAKE) check
	git add version.go
	git commit -m "release: v$(VERSION)"
	git tag -a "v$(VERSION)" -m "v$(VERSION)"
	git push origin HEAD
	git push origin "v$(VERSION)"
	@echo
	@echo "released v$(VERSION) - now VERIFY FROM OUTSIDE (RELEASING.md):"
	@echo "  cd \$$(mktemp -d) && go mod init t && go get github.com/ab0t-com/auth-sdk-go@v$(VERSION)"
