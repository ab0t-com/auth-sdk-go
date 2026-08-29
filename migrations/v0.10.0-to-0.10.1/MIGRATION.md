# Migration: auth-sdk-go v0.10.0 → v0.10.1

One small breaking change — the delegation-grant request (**G-04**). If you don't call
`GrantDelegation`, nothing changes for you (and it never worked before v0.10.1 anyway — it returned
422). Run the checker: `./migrate-check.sh .`

## The change — `DelegationGrant` (`apikeys.go`)
The server's `POST /delegation/grant` requires `scope` (and `expires_in_hours` on the goauth backend);
it has no `permissions`/`target_user_id`/`expires_at`/`reason`. The grant's target is the
**authenticated caller** (you grant an actor the right to act as *you*), so it isn't in the body.

| Before (v0.10.0) | After (v0.10.1) |
|---|---|
| `DelegationGrant{ActorID, TargetUserID, Permissions, ExpiresAt, Reason}` | `DelegationGrant{ActorID, Scope []string, ExpiresInHours *int}` |

```go
hrs := 24
c.GrantDelegation(ctx, authclient.DelegationGrant{
    ActorID: "svc-agent", Scope: []string{"world.read"}, ExpiresInHours: &hrs,
}, callerToken)
```

*Why:* the old body omitted the required `scope`, so `GrantDelegation` failed with 422 as shipped.
*Migration:* `Permissions` → `Scope`; set `ExpiresInHours`; drop `TargetUserID`/`ExpiresAt`/`Reason`.

## Verify
`go build ./... && go vet ./... && go test ./...` — then the checker reports 0.
