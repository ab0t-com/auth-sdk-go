package authclient

// store_test.go — the ergonomic Zanzibar layer.
//
// The point of these tests is not that the helpers compile. It is that they put
// the SAME bytes on the wire as the raw calls they wrap (so the convenience layer
// cannot quietly mean something different) and that every boolean answer FAILS
// CLOSED — an error, an empty batch, or a short response must never read as
// "allowed".

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type storeSpy struct {
	path   string
	body   map[string]any
	bodies []string
	auth   string
	calls  int
}

func storeServe(t *testing.T, spy *storeSpy, status int, reply string) *ZanzibarStore {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		spy.calls++
		spy.path = r.URL.Path
		spy.auth = r.Header.Get("Authorization")
		spy.bodies = append(spy.bodies, string(b))
		spy.body = map[string]any{}
		_ = json.Unmarshal(b, &spy.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, WithMaxRetries(0)).Store("s1", "caller-tok")
}

// TestStore_CanPutsTheSameBytesOnTheWire is the load-bearing test for the whole
// file: the ergonomic call must be indistinguishable, server-side, from the raw one.
func TestStore_CanPutsTheSameBytesOnTheWire(t *testing.T) {
	var viaHelper, viaRaw storeSpy

	st := storeServe(t, &viaHelper, 200, `{"allowed":true}`)
	ok, err := st.Can(context.Background(), "user", "alice", "view", "doc", "123")
	if err != nil || !ok {
		t.Fatalf("Can: ok=%v err=%v", ok, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		viaRaw.path = r.URL.Path
		viaRaw.bodies = append(viaRaw.bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"allowed":true}`)
	}))
	defer srv.Close()
	_, err = New(srv.URL, WithMaxRetries(0)).ZanzibarCheck(context.Background(), "s1", CheckPermissionRequest{
		Subject: Subject("user", "alice"), Permission: "view", Object: Object("doc", "123"),
	}, "caller-tok")
	if err != nil {
		t.Fatalf("raw ZanzibarCheck: %v", err)
	}

	if viaHelper.path != viaRaw.path {
		t.Errorf("paths differ: helper %q vs raw %q", viaHelper.path, viaRaw.path)
	}
	if viaHelper.bodies[0] != viaRaw.bodies[0] {
		t.Errorf("bodies differ:\n  helper: %s\n  raw:    %s", viaHelper.bodies[0], viaRaw.bodies[0])
	}
	if !strings.Contains(viaHelper.auth, "caller-tok") {
		t.Errorf("bound token not forwarded: %q", viaHelper.auth)
	}
}

func TestStore_CanFailsClosed(t *testing.T) {
	t.Run("service error is false", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 500, `{"detail":"boom"}`)
		ok, err := st.Can(context.Background(), "user", "alice", "view", "doc", "1")
		if err == nil {
			t.Fatal("a 500 must surface as an error")
		}
		if ok {
			t.Fatal("FAIL-OPEN: a 500 was read as allowed")
		}
	})
	t.Run("denial is false with no error", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"allowed":false,"reason":"no relation"}`)
		ok, err := st.Can(context.Background(), "user", "alice", "view", "doc", "1")
		if err != nil {
			t.Fatalf("a well-formed denial is not an error: %v", err)
		}
		if ok {
			t.Fatal("denial read as allowed")
		}
	})
}

func TestStore_CanAllAndCanAny(t *testing.T) {
	mk := func(reply string) (*ZanzibarStore, *storeSpy) {
		spy := &storeSpy{}
		return storeServe(t, spy, 200, reply), spy
	}
	checks := []CheckPermissionRequest{
		Check("user", "a", "view", "doc", "1"),
		Check("user", "a", "view", "doc", "2"),
	}

	t.Run("CanAll true only when every result is allowed", func(t *testing.T) {
		st, _ := mk(`[{"allowed":true},{"allowed":true}]`)
		if ok, err := st.CanAll(context.Background(), checks...); err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		st, _ = mk(`[{"allowed":true},{"allowed":false}]`)
		if ok, _ := st.CanAll(context.Background(), checks...); ok {
			t.Fatal("CanAll true despite a denial")
		}
	})

	t.Run("CanAny true when any result is allowed", func(t *testing.T) {
		st, _ := mk(`[{"allowed":false},{"allowed":true}]`)
		if ok, err := st.CanAny(context.Background(), checks...); err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		st, _ = mk(`[{"allowed":false},{"allowed":false}]`)
		if ok, _ := st.CanAny(context.Background(), checks...); ok {
			t.Fatal("CanAny true with no allowed result")
		}
	})

	// "Nothing was asked" is not "everything is permitted". This is the kind of
	// vacuous-truth bug that turns an empty loop into an open door.
	t.Run("empty batch is false and sends nothing", func(t *testing.T) {
		st, spy := mk(`[]`)
		for name, fn := range map[string]func() (bool, error){
			"CanAll": func() (bool, error) { return st.CanAll(context.Background()) },
			"CanAny": func() (bool, error) { return st.CanAny(context.Background()) },
		} {
			ok, err := fn()
			if ok {
				t.Errorf("%s: an EMPTY batch reported true", name)
			}
			if err != nil {
				t.Errorf("%s: empty batch should not error: %v", name, err)
			}
		}
		if spy.calls != 0 {
			t.Errorf("empty batch made %d requests", spy.calls)
		}
	})

	// If the server returns fewer results than checks we cannot tell which result
	// belongs to which check, so the only safe answer is an error.
	t.Run("short response is an error, not a guess", func(t *testing.T) {
		st, _ := mk(`[{"allowed":true}]`) // 1 result for 2 checks
		ok, err := st.CanAll(context.Background(), checks...)
		if err == nil {
			t.Fatal("a short bulk response must be an error")
		}
		if ok {
			t.Fatal("FAIL-OPEN on a short response")
		}
	})
}

func TestStore_RelateAndUnrelate(t *testing.T) {
	t.Run("relate sends the tuple and requires success", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"success":true,"message":"ok"}`)
		if err := st.Relate(context.Background(), "user", "alice", "owner", "doc", "123"); err != nil {
			t.Fatalf("Relate: %v", err)
		}
		if spy.body["subject"] != "user:alice" || spy.body["object"] != "doc:123" || spy.body["relation"] != "owner" {
			t.Errorf("tuple not sent as typed ids: %+v", spy.body)
		}
	})

	// A 200 is not a success — the server reports the outcome in the body. Treating
	// "well-formed answer" as "it worked" is how writes get silently lost.
	t.Run("success=false is an error even on a 200", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"success":false,"message":"unknown relation"}`)
		err := st.Relate(context.Background(), "user", "alice", "bogus", "doc", "123")
		if err == nil {
			t.Fatal("success=false must be an error; otherwise the write is silently lost")
		}
		if !strings.Contains(err.Error(), "unknown relation") {
			t.Errorf("error drops the server's reason: %v", err)
		}
	})

	t.Run("unrelate", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"success":true,"message":"ok"}`)
		if err := st.Unrelate(context.Background(), "user", "alice", "owner", "doc", "123"); err != nil {
			t.Fatalf("Unrelate: %v", err)
		}
		if spy.body["subject"] != "user:alice" {
			t.Errorf("tuple not sent: %+v", spy.body)
		}
	})
}

func TestStore_ListHelpers(t *testing.T) {
	t.Run("WhatCan", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"objects":["doc:1","doc:2"],"subject":"user:alice","permission":"view","object_type":"doc"}`)
		got, err := st.WhatCan(context.Background(), Subject("user", "alice"), "view", "doc")
		if err != nil {
			t.Fatalf("WhatCan: %v", err)
		}
		if len(got) != 2 || got[0] != "doc:1" {
			t.Errorf("objects not decoded: %+v", got)
		}
	})

	t.Run("WhoCan expands groups by default", func(t *testing.T) {
		var spy storeSpy
		st := storeServe(t, &spy, 200, `{"users":["user:alice"],"object":"doc:1","permission":"view"}`)
		if _, err := st.WhoCan(context.Background(), Object("doc", "1"), "view"); err != nil {
			t.Fatalf("WhoCan: %v", err)
		}
		// Without expansion a sharing dialog silently omits everyone who has
		// access through a group, which reads as "nobody else can see this".
		if spy.body["expand_groups"] != true {
			t.Errorf("expand_groups not requested: %+v", spy.body)
		}
	})
}

func TestStore_BindingAndRebinding(t *testing.T) {
	var spy storeSpy
	st := storeServe(t, &spy, 200, `{"allowed":true}`)

	if st.ID() != "s1" {
		t.Errorf("ID() = %q, want s1", st.ID())
	}
	if _, err := st.As("other-token").Can(context.Background(), "user", "a", "view", "doc", "1"); err != nil {
		t.Fatalf("Can via As(): %v", err)
	}
	if !strings.Contains(spy.auth, "other-token") {
		t.Errorf("As() did not rebind the token: %q", spy.auth)
	}
}

// The ergonomic layer must inherit the typed-id guard, not bypass it.
func TestStore_InheritsTypedIDGuard(t *testing.T) {
	var spy storeSpy
	st := storeServe(t, &spy, 200, `{"allowed":true}`)

	_, err := st.CanID(context.Background(), "alice", "view", Object("doc", "1"))
	if err == nil {
		t.Fatal("CanID accepted an untyped subject")
	}
	var e *ErrUntypedID
	if !errors.As(err, &e) {
		t.Errorf("error is %T, want *ErrUntypedID", err)
	}
	if spy.calls != 0 {
		t.Error("request sent despite an untyped id")
	}
}
