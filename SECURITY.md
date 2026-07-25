# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's [private vulnerability reporting](https://github.com/ab0t-com/auth-sdk-go/security/advisories/new)
on this repository, or email `security@ab0t.com`.

Please include: what the issue is, how to reproduce it, and what an attacker
gains. We will acknowledge receipt and keep you updated on the fix.

## Scope

This repository is a **client SDK**. It holds credentials in memory and puts them
on the wire; it does not make authorization decisions itself — the ab0t Auth
Service does. Issues in the service itself belong to that service's own process.

In scope here: credential leakage (into logs, errors, URLs, or the User-Agent),
TLS or certificate-validation weaknesses, token-cache or JWKS-cache poisoning,
retry logic that duplicates a security-relevant side effect, and any code path
where an error is silently converted into an "allow".

## Using this SDK safely

- **Never log a credential.** This SDK does not log; if you wrap it, make sure
  your wrapper does not either. `Actor` and the request types can contain tokens.
- **Fail closed.** `Authorize` returns `(false, err)` on a transport or server
  error. Treat an error as *deny* or *unavailable* — never as *allow*. A gate
  that allows on error turns an auth-service blip into an open door.
- **Check the boolean, not just the error.** A `nil` error means the call
  succeeded, not that the answer was yes.
- **Keep service keys (`ab0t_sk_…`) out of source control** and out of client-side
  code. They are service-to-service credentials.
- **Pin a version.** This is pre-1.0; minor releases may change contracts when the
  server's contract changes.
