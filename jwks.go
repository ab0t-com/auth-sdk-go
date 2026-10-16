package authclient

import (
	"context"
	"sync"
	"time"
)

// JWK is a single JSON Web Key (RFC 7517). Only the commonly-needed fields are
// modeled; unknown fields are ignored. For RSA keys N and E are base64url; for
// EC keys Crv, X, and Y are populated.
type JWK struct {
	Kty string `json:"kty"`           // key type: "RSA", "EC", "oct"
	Use string `json:"use,omitempty"` // "sig" or "enc"
	Kid string `json:"kid,omitempty"` // key id
	Alg string `json:"alg,omitempty"` // e.g. "RS256", "ES256"

	// RSA.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// X.509 chain (optional).
	X5c []string `json:"x5c,omitempty"`
	X5t string   `json:"x5t,omitempty"`
}

// JWKS is a JSON Web Key Set (GET /.well-known/jwks.json).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Key returns the key with the matching kid, or false if absent.
func (s JWKS) Key(kid string) (JWK, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

// jwksCacheTTL is how long a fetched key set is trusted before a refresh.
const jwksCacheTTL = 10 * time.Minute

// jwksMaxEntries bounds the number of distinct key sets held at once.
//
// Entries are keyed by URL path, and OrgJWKS keys one per organization. In a
// multi-tenant resource server — or any admin tool that iterates organizations —
// an unbounded map grows by one entry per distinct org ever seen and never
// shrinks, for the life of the process. That is a slow leak keyed by tenant,
// which is a well-known failure class, so the cache is bounded.
//
// The bound is generous: a process legitimately serving this many distinct orgs
// concurrently is rare, and eviction only costs a refetch.
const jwksMaxEntries = 512

// jwksCache is a small, concurrency-safe, single-flight TTL cache for key sets.
// It supports both the global JWKS endpoint and per-organization endpoints,
// keyed by URL path. It is BOUNDED at jwksMaxEntries (see above).
type jwksCache struct {
	c   *Client
	ttl time.Duration
	// kidCooldown bounds how often an UNKNOWN kid may force a refetch of one key
	// set (refreshForUnknownKid); 0 means jwksUnknownKidCooldown.
	kidCooldown time.Duration
	// now is time.Now, replaceable in tests.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*jwksEntry
	// maxEntries bounds len(entries); 0 means jwksMaxEntries.
	maxEntries int
}

type jwksEntry struct {
	// Guards a single in-flight fetch for this key.
	once    sync.Mutex
	keys    JWKS
	fetched time.Time
	err     error
	// forcedAt is when an unknown kid last forced a refetch (refreshForUnknownKid).
	forcedAt time.Time
}

// jwksUnknownKidCooldown is the minimum interval between two refetches of one key
// set that were forced by a token naming a kid the cached set does not hold.
//
// A kid comes from the TOKEN, i.e. from whoever sent the request. Without a
// bound, a stream of tokens with random kids turns every request into a JWKS
// fetch — an amplification of attacker traffic onto the auth service. Key
// rotation still works: the first token signed by a new key after the window
// triggers exactly one refetch.
const jwksUnknownKidCooldown = time.Minute

func newJWKSCache(c *Client) *jwksCache {
	return &jwksCache{c: c, ttl: jwksCacheTTL, kidCooldown: jwksUnknownKidCooldown, now: time.Now,
		entries: make(map[string]*jwksEntry), maxEntries: jwksMaxEntries}
}

func (j *jwksCache) clock() time.Time {
	if j.now != nil {
		return j.now()
	}
	return time.Now()
}

func (j *jwksCache) entry(path string) *jwksEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	e := j.entries[path]
	if e == nil {
		j.evictIfFullLocked()
		e = &jwksEntry{}
		j.entries[path] = e
	}
	return e
}

// evictIfFullLocked keeps the cache bounded. Caller must hold j.mu.
//
// Eviction prefers the STALEST entry (oldest successful fetch), so a hot key set
// survives and a long-idle tenant is the one dropped. Entries that never fetched
// successfully sort oldest and go first. Dropping an entry is always safe — the
// only cost is one refetch on the next use.
func (j *jwksCache) evictIfFullLocked() {
	max := j.maxEntries
	if max <= 0 {
		max = jwksMaxEntries
	}
	if len(j.entries) < max {
		return
	}
	var victim string
	var oldest time.Time
	first := true
	for k, e := range j.entries {
		// Never evict an entry with a fetch in flight; TryLock keeps eviction
		// non-blocking and avoids racing a concurrent refresh.
		if !e.once.TryLock() {
			continue
		}
		fetched := e.fetched
		e.once.Unlock()
		if first || fetched.Before(oldest) {
			victim, oldest, first = k, fetched, false
		}
	}
	if !first {
		delete(j.entries, victim)
	}
}

// get returns a cached key set for path, refetching if stale or forced.
func (j *jwksCache) get(ctx context.Context, path string, force bool) (JWKS, error) {
	e := j.entry(path)
	e.once.Lock()
	defer e.once.Unlock()

	if !force && e.err == nil && !e.fetched.IsZero() && j.clock().Sub(e.fetched) < j.ttl {
		return e.keys, nil
	}
	return j.fetchLocked(ctx, path, e)
}

// fetchLocked performs the fetch for e. Caller must hold e.once.
func (j *jwksCache) fetchLocked(ctx context.Context, path string, e *jwksEntry) (JWKS, error) {
	var fresh JWKS
	err := j.c.doGet(ctx, path, &fresh, "")
	if err != nil {
		// Serve a previously-good set on transient failure rather than failing
		// closed; only surface the error when we have nothing cached.
		if !e.fetched.IsZero() && e.err == nil {
			return e.keys, nil
		}
		e.err = err
		return JWKS{}, err
	}
	e.keys = fresh
	e.fetched = j.clock()
	e.err = nil
	return fresh, nil
}

// refreshForUnknownKid refetches path's key set because a token named a kid the
// cached set does not hold — at most once per kidCooldown per path. Inside the
// cooldown it makes no request and returns the cached set with refreshed=false,
// so the caller rejects the token as "unknown kid" without touching the network.
// The cooldown starts at the ATTEMPT, so a failing auth service is not hammered
// either; on a failed fetch a previously-good set keeps being served (keys are
// public; this is the same transient-outage rule as get).
func (j *jwksCache) refreshForUnknownKid(ctx context.Context, path string) (JWKS, bool, error) {
	e := j.entry(path)
	e.once.Lock()
	defer e.once.Unlock()

	cooldown := j.kidCooldown
	if cooldown <= 0 {
		cooldown = jwksUnknownKidCooldown
	}
	now := j.clock()
	if !e.forcedAt.IsZero() && now.Sub(e.forcedAt) < cooldown {
		return e.keys, false, nil
	}
	e.forcedAt = now
	keys, err := j.fetchLocked(ctx, path, e)
	return keys, true, err
}
