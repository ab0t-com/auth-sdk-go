# Changelog

All notable changes to the ab0t Auth Service Go SDK.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-07-25

### Added
- **`ab0t-auth` — a command-line client.**

  ```bash
  go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest
  ab0t-auth doctor
  ab0t-auth can user:alice view doc:123 --store my-store
  ```

  Answers from a terminal the questions that otherwise need a Go program: is this
  token valid, who am I, can alice read this document and why not, is the service
  up, and what is wrong with my configuration.

  **Still zero dependencies.** A CLI would normally reach for cobra; that would add
  cobra and pflag to this module and break the stdlib-only guarantee for every
  consumer, none of whom asked for a CLI. Subcommand dispatch is written against
  the stdlib `flag` package instead, so `go install` pulls exactly nothing else.

  **Accessibility is built in, not bolted on**, and each property has a test
  because a regression in any of them is invisible to a sighted developer at an
  interactive terminal:
  - `NO_COLOR` (any non-empty value) means **no ANSI at all**, not less colour;
    a non-TTY, `TERM=dumb` and `--json` each disable colour too.
  - **Colour is never the only signal** — strip every escape sequence and the
    output is byte-identical to the plain rendering. Verified by a test.
  - `--json` on every command, with the same facts as the text output.
  - Data on stdout, diagnostics on stderr, so `cmd --json > out.json` yields a
    parseable file and the human still sees the errors.
  - No spinners, progress bars, cursor movement or box drawing anywhere.
  - Every prompt has a non-interactive equivalent; a prompt that would block in CI
    is skipped rather than hanging.
  - Exit codes: `0` ok/ALLOWED, `1` error, `2` DENIED, `3` no credential — so
    `if ab0t-auth can …; then` works in a script.

  Credential storage follows the house pattern: a JSON file at **0600 inside a
  0700 directory**, written atomically, resolved `--token` → `$AB0T_AUTH_TOKEN` →
  `$AUTH_SERVICE_KEY` → file. No command ever prints a credential in full.

  `doctor` reports every check rather than stopping at the first failure — the
  second failure is often what explains the first.

## [0.5.0] — 2026-07-25

### Added
- **`WithObserver(fn)` — an observability seam.** One `RequestInfo` per completed
  HTTP attempt: method, endpoint, status, duration, attempt number, whether a retry
  follows, error, and the service's request id. **Retries are visible** — a retry
  storm that looks like one slow call is the thing you most need to see.

  Deliberately a callback, not a logger: a logger in a library imposes three
  decisions on the consumer (which package, which format, which level) and would
  add a dependency to a module whose defining property is having none. This feeds
  slog, zap, OTel or a test assertion equally.

  It carries **no headers and no bodies**. This client's job is handling
  credentials, and an observability hook is exactly what ends up in a log
  aggregator; a path and a status cannot leak a token. The endpoint has its query
  string stripped, so it is usable as a metric label.

- **`authclienttest` — exported test doubles.** `Fake` (implements both interfaces,
  records calls) plus ready-made `Allow()`, `Deny()` and **`Unavailable()`**, and
  `Server`, an httptest-backed fake auth service for exercising the *real* client.

  `Unavailable()` is the point. Every consumer writes allow and deny fakes; almost
  nobody tests what their handler does when the auth service is unreachable — the
  one path where a mistake means an outage silently unlocks the write surface. Now
  it is one line. A separate package, so the root's dependency surface is untouched.

- **`authmw` — the HTTP middleware, promoted out of `examples/`.** `Authenticate`
  (attach identity; missing credential stays anonymous, invalid is 401, unreachable
  is 503) and `Require(action, resourceType)` (401 / 403 / 503 / handler), plus
  `RequireFunc` for routers that compose `func(http.Handler) http.Handler`.

  It lived only in an example, which meant every consumer copy-pasted it, inherited
  whatever was wrong with it that day, and got none of the fixes — the wrong
  distribution mechanism for a component whose failure mode is "the write surface
  is silently unlocked". **Fail-closed is the default and cannot be forgotten:**
  `FailOpen` must be set deliberately, and a test asserts the default has not
  drifted.

## [0.4.0] — 2026-07-25

### Added
- **A release SOP that is enforced rather than remembered.** `make release VERSION=x.y.z`
  refuses on a dirty tree, a missing changelog section, an existing tag, or a
  failing `make check`, then bumps `version.go`, commits, tags and pushes.
  `TestVersionMatchesChangelog` fails if `Version` has no changelog section behind
  it. See `RELEASING.md`.

  This exists because v0.1.0 shipped without a fix that was already on `main` — it
  had been committed after the tag. Every local test passed; only a clean-room
  `go get` by tag revealed it. Remembering harder does not fix that; a guard does.

## [0.3.0] — 2026-07-25

### Added
- **`Client.Store(storeID, token)` — the ergonomic Zanzibar surface.** The raw methods
  mirror the HTTP API exactly, which is the right foundation but makes a one-line
  question cost six lines of ceremony and a repeated store id and token on every
  call. `ZanzibarStore` binds them once and exposes the questions people actually
  ask: `Can`, `CanAll`, `CanAny`, `Why`, `WhatCan` ("which docs can alice view" —
  the filtered index page), `WhoCan` ("who can view this" — the sharing dialog,
  groups expanded), `RelationsOn`, `Relate`, `Unrelate`, plus `*ID` variants and a
  `Check(...)` batch builder and `As(token)` for per-request tokens.

  Types are separate arguments (`"user", "alice"`) rather than something the caller
  concatenates, because a mistyped combined id produces a silent DENY, not an error.

  Every boolean fails closed: an error is false, an **empty batch is false**
  ("nothing was asked" is not "everything is permitted"), and a bulk response whose
  length does not match the request is an error rather than a guess. `Relate` and
  `Unrelate` treat `success:false` as an error even on a 200 — a write reported as
  refused is not a write.

  It is a layer over the raw methods, never a replacement: everything the service
  can do stays reachable.

## [0.2.0] — 2026-07-25

### Added
- Zanzibar combined ids are now validated before the request. `ZanzibarCheck` and
  `ZanzibarCheckBulk` return `*ErrUntypedID` when a `subject` or `object` is
  missing its `type:` prefix, instead of sending a request that can only come back
  `allowed:false`. A bare `"alice"` where `"user:alice"` was meant is
  indistinguishable, server-side, from an id it has simply never seen — so the
  caller reads a legitimate DENY and debugs the wrong thing. The bulk form names
  the offending index (`check 2: …`).
- `make drift` / `scripts/spec-coverage.py` — compares this SDK against the live
  OpenAPI spec in both directions and reports MISSING (a capability consumers
  cannot reach) and PHANTOM (a call that would 404). Current: 283/283 operations
  reachable. Stdlib-only; no network unless you ask it to fetch.

### Changed
- The staged CI workflow is **manual-dispatch only** (`workflow_dispatch`, no
  `push`/`pull_request`), so installing it does not start anything running.
  Dropped the CI status badge, which would have advertised a workflow that never
  fires.

## [0.1.0] — 2026-07-25

First public release. Extracted from a private in-repo client, reconciled against
the live ab0t Auth Service OpenAPI 3.1 spec, and published under its own module
path `github.com/ab0t-com/auth-sdk-go`.

### Added
- `DeleteCurrentUser` — `DELETE /users/me`, the GDPR / right-to-erasure
  self-delete flow, guarded by a confirm-email match. Previously the endpoint had
  no representation in the SDK at all, so a consumer offering "delete my account"
  had to hand-roll the call and re-derive the confirmation contract.
- `/mesh/providers` service-discovery surface — `ListMeshProviders`,
  `GetMeshProvider`, `PublishMeshProvider`, with `MeshProvider`,
  `MeshProviderPublishRequest/Response` and the tier types. The whole subsystem
  was previously absent.
- `BulkCheckResults.Allowed(i)` and `.AllAllowed()` helpers. Both fail CLOSED:
  an out-of-range index and an empty result set are `false`, because "nothing was
  checked" is not "everything is permitted".
- `Version`, reported in the `User-Agent` of every request so the service can
  attribute traffic and identify clients running a version with a known-bad
  contract.

### Fixed
- **`ZanzibarCheckBulk` returned an error on every successful call.** The live
  spec defines the `check/bulk` 200 as a bare JSON **array** of
  `CheckPermissionResponse`; the SDK decoded it into a struct with a `results`
  map, so every response failed with `json.UnmarshalTypeError` even when the
  server had answered correctly. This was an honest best-effort guess made while
  the server had no declared response schema — the server has since declared one.
- **The JWKS cache was unbounded.** `OrgJWKS` keyed one entry per organization
  and nothing ever evicted, so a long-lived multi-tenant process grew the map by
  one entry per distinct org ever seen, for the life of the process. It is now
  bounded (512 entries) with stalest-first eviction; eviction only ever costs a
  refetch.

### Changed
- **BREAKING:** module path is `github.com/ab0t-com/auth-sdk-go`.
- **BREAKING:** `ZanzibarCheckBulk` now returns `BulkCheckResults`
  (`[]CheckPermissionResponse`, in request order) instead of `*BulkCheckResponse`.
  The old type is removed; it could not decode a real response.
- `User-Agent` no longer names one particular consumer.

### Known gaps
- Four `authzmodel.go` methods (`ReadAuthorizationModel`,
  `ListAuthorizationModels`, `WriteAuthorizationModel`,
  `WriteAndDeleteRelationships`) target routes the auth service does not expose
  yet. They are shipped as forward-looking stubs, each carrying a `SERVER-GAP`
  doc note, and `TestAuthorizationModel_IsStillAServerGap` records executably
  that they 404 today. When the server ships those routes, that test starts
  failing — which is the signal to remove the warnings.
- Non-idempotent `POST`s are retried on 429/5xx. This is deliberate and tested,
  but it means a create call whose write committed before the response was lost
  can be applied twice on an endpoint with no natural dedup key. Use
  `WithMaxRetries(0)` on calls where once-only semantics matter. See README.

### Note for anyone on v0.1.0
The typed-id guard is a behaviour change: a `ZanzibarCheck` that previously sent a
request with an untyped id now returns `*ErrUntypedID` without sending it. If you
were relying on that request going out, it could only ever have come back
`allowed:false` — the guard turns a silent wrong deny into a clear error.

[0.6.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.6.0
[0.5.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.5.0
[0.4.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.4.0
[0.3.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.3.0
[0.2.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.2.0
[0.1.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.1.0
