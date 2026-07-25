package authclient

// observe_test.go — the observability seam.
//
// Two things matter here and neither is "the callback fires":
//   1. retries are VISIBLE (one event per attempt), because a retry storm that
//      looks like one slow call is the thing you most need to see;
//   2. no credential ever reaches the callback, because an observability hook is
//      exactly what gets piped to a log aggregator.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestObserver_FiresOncePerAttemptIncludingRetries(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits < 3 {
			http.Error(w, `{"detail":"try later"}`, http.StatusServiceUnavailable) // retryable
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"valid":true}`)
	}))
	defer srv.Close()

	var mu sync.Mutex
	var got []RequestInfo
	c := New(srv.URL,
		WithMaxRetries(3),
		WithBackoff(time.Millisecond, 2*time.Millisecond),
		WithObserver(func(i RequestInfo) { mu.Lock(); got = append(got, i); mu.Unlock() }),
	)

	if _, err := c.ValidateToken(context.Background(), "jwt"); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("observer fired %d times, want 3 (two 503s then a 200) — retries must be visible, not hidden inside one slow call", len(got))
	}
	for i, ri := range got {
		if ri.Attempt != i {
			t.Errorf("event %d has Attempt=%d, want %d", i, ri.Attempt, i)
		}
		if ri.Method != http.MethodPost || ri.Endpoint != "/auth/validate-token" {
			t.Errorf("event %d: %s %s, want POST /auth/validate-token", i, ri.Method, ri.Endpoint)
		}
	}
	if got[0].Status != 503 || !got[0].Retrying {
		t.Errorf("first attempt: status=%d retrying=%v, want 503/true", got[0].Status, got[0].Retrying)
	}
	// Exactly one event per logical call is the terminal one.
	if got[2].Status != 200 || got[2].Retrying {
		t.Errorf("last attempt: status=%d retrying=%v, want 200/false", got[2].Status, got[2].Retrying)
	}
	var terminal int
	for _, ri := range got {
		if !ri.Retrying {
			terminal++
		}
	}
	if terminal != 1 {
		t.Errorf("%d terminal events, want exactly 1", terminal)
	}
}

// TestObserver_CarriesNoCredential is the one that matters for safety. Endpoint and
// status cannot leak a token; a header or a body can — so neither is carried.
func TestObserver_CarriesNoCredential(t *testing.T) {
	const secret = "ab0t_sk_SUPERSECRET_do_not_log"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"valid":true,"user_id":"u1"}`)
	}))
	defer srv.Close()

	var seen []RequestInfo
	c := New(srv.URL, WithAPIKey(secret), WithMaxRetries(0),
		WithObserver(func(i RequestInfo) { seen = append(seen, i) }))

	if _, err := c.ValidateToken(context.Background(), secret); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("observer never fired")
	}
	for _, i := range seen {
		blob := i.Method + "|" + i.Endpoint + "|" + i.RequestID
		if i.Err != nil {
			blob += "|" + i.Err.Error()
		}
		if strings.Contains(blob, secret) || strings.Contains(strings.ToLower(blob), "ab0t_sk_") {
			t.Fatalf("CREDENTIAL LEAK: a token reached the observer: %q", blob)
		}
	}
}

func TestObserver_EndpointHasNoQueryString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"ok"}`)
	}))
	defer srv.Close()

	var seen []RequestInfo
	c := New(srv.URL, WithMaxRetries(0), WithObserver(func(i RequestInfo) { seen = append(seen, i) }))

	// GrantPermission puts user_id/org_id/permission in the query string. Those are
	// unbounded-cardinality values; a metric label built from them would explode.
	if _, err := c.GrantPermission(context.Background(), "u1", "o1", "users.read", "tok"); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("observer never fired")
	}
	if strings.Contains(seen[0].Endpoint, "?") || strings.Contains(seen[0].Endpoint, "u1") {
		t.Errorf("Endpoint = %q — the query string must be stripped so it is usable as a metric label", seen[0].Endpoint)
	}
	if seen[0].Endpoint != "/permissions/grant" {
		t.Errorf("Endpoint = %q, want /permissions/grant", seen[0].Endpoint)
	}
}

func TestObserver_TransportErrorReportsZeroStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close() // nothing is listening now

	var seen []RequestInfo
	c := New(addr, WithMaxRetries(0), WithObserver(func(i RequestInfo) { seen = append(seen, i) }))
	_, _ = c.ValidateToken(context.Background(), "jwt")

	if len(seen) == 0 {
		t.Fatal("observer never fired on a transport error")
	}
	// Status 0 with a non-nil Err is how "never got a response" is distinguished
	// from "got a 500" — they need different alerting.
	if seen[0].Status != 0 || seen[0].Err == nil {
		t.Errorf("status=%d err=%v, want status 0 with a non-nil error", seen[0].Status, seen[0].Err)
	}
}

func TestObserver_UnsetChangesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"valid":true,"user_id":"u1"}`)
	}))
	defer srv.Close()

	a, err := New(srv.URL, WithMaxRetries(0)).ValidateToken(context.Background(), "jwt")
	if err != nil || !a.Valid {
		t.Fatalf("no-observer path changed behaviour: %+v %v", a, err)
	}
	// nil explicitly clears rather than panicking.
	b, err := New(srv.URL, WithMaxRetries(0), WithObserver(nil)).ValidateToken(context.Background(), "jwt")
	if err != nil || !b.Valid {
		t.Fatalf("WithObserver(nil) broke the call: %+v %v", b, err)
	}
}
