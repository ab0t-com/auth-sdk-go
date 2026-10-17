# auth-sdk-go v0.12.2 — bug fixes, no change required

`go get github.com/ab0t-com/auth-sdk-go@v0.12.2`. Your code compiles unchanged and every default is the same.

- **Local JWT verification is stricter about encoding.** `VerifyAccessTokenLocal` now accepts exactly one
  spelling of a signed token: a token with `=` padding or non-canonical base64url is refused as `malformed`.
  Tokens from the auth service never pad, so real traffic is unaffected; a hand-built test fixture might be.
- **Absurd dates are refused.** An `exp`, `nbf` or `iat` past the year 9999 is `malformed` (a huge `nbf` or
  `iat` used to be read as long ago and accepted).
- **The validation cache stays within its size limit** (`MaxEntries`, 4096 by default) even under a burst of
  concurrent first-time validations.

Check a repository in one step: `./migrate-check.sh /path/to/your/repo` (from the `v0.12.1-to-v0.12.2` kit).
