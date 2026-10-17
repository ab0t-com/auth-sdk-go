# Migration: auth-sdk-go v0.12.1 → v0.12.2

**Bug fixes. Your code compiles unchanged; every default and exported API is unchanged.**

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.12.2 && go mod tidy
/path/to/auth-sdk-go/migrations/v0.12.1-to-v0.12.2/migrate-check.sh .    # read-only
go build ./... && go vet ./... && go test ./...
```

| # | Rule | Change | Your action |
|---|---|---|---|
| R1 | `TOKENFIXTURE` | `VerifyAccessTokenLocal` decodes each token segment strictly (RFC 7515 §2: no `=` padding, canonical). A padded or non-canonical token string is refused as `malformed` (v0.12.1 accepted it). | Only hand-built test tokens can be affected (the auth service never pads). Regenerate such a fixture with a real encoder (`base64.RawURLEncoding`). |
| — | (no rule) | An `exp` / `nbf` / `iat` beyond 9999-12-31T23:59:59Z is `malformed` (v0.12.1 read a huge `nbf`/`iat` as a date in the distant past and accepted it). | Nothing. |
| — | (no rule) | The validation cache stays within `MaxEntries` under concurrent cold misses (it could grow past it and stay there). | Nothing. `ValidationCacheStats().Entries` now never exceeds `MaxEntries`. |

## R1 — strict token segments
Before: `token+"="`, `token+"=="` and alternate last characters of the signature all verified, so one
signed token had many accepted spellings — anything keyed on the token string (a deny-list, a replay set,
the SDK's validation cache) saw them as different tokens. After: exactly one spelling verifies. JWKS key
fields (`n`, `e`) are still read leniently.

The checker lists JWT-looking string literals containing `=` in your Go files (likely hand-built test
fixtures). Mark a reviewed line with `// authsdk:v0.12.2-reviewed`, or a whole file with
`// authsdk:v0.12.2-reviewed-file`.
