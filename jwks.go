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
}

func newJWKSCache(c *Client) *jwksCache {
	return &jwksCache{c: c, ttl: jwksCacheTTL, entries: make(map[string]*jwksEntry), maxEntries: jwksMaxEntries}
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

	if !force && e.err == nil && !e.fetched.IsZero() && time.Since(e.fetched) < j.ttl {
		return e.keys, nil
	}

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
	e.fetched = time.Now()
	e.err = nil
	return fresh, nil
}
