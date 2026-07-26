package authclient

// store.go — the ergonomic Zanzibar surface.
//
// WHY THIS FILE EXISTS
//
// The rest of this package is a faithful 1:1 mirror of the auth service's HTTP API.
// That is the right foundation — every operation reachable, every type matching the
// wire — but it is not what using the thing feels like. The raw Zanzibar surface
// asks you to repeat a store id and a caller token on every call, to build a
// request struct for a one-line question, and to remember that ids are combined
// "type:id" strings:
//
//	req := authclient.CheckPermissionRequest{
//	    Subject:    authclient.Subject("user", "alice"),
//	    Permission: "view",
//	    Object:     authclient.Object("doc", "123"),
//	}
//	res, err := c.ZanzibarCheck(ctx, storeID, req, callerToken)
//	if err != nil { return false, err }
//	return res.Allowed, nil
//
// Six lines, two of which are ceremony, to ask one question. With a store bound:
//
//	store := c.Store(storeID, callerToken)
//	ok, err := store.Can(ctx, "user", "alice", "view", "doc", "123")
//
// Same call, same wire bytes, no ceremony. The raw methods stay exactly where they
// were and keep working — this is a layer over them, never a replacement, because
// anything the service can do must remain reachable even if this file never grows
// a helper for it.
//
// DESIGN RULES HERE
//
//  1. Every boolean answer FAILS CLOSED. An error, an empty result, a short
//     response — all false. "I don't know" is never "yes".
//  2. Types are separate arguments, not something the caller concatenates. Passing
//     ("user", "alice") is impossible to get wrong; passing "user:alice" is easy to
//     get wrong, and getting it wrong produces a silent DENY rather than an error.
//     Use the *ID variants when you already hold a combined id.
//  3. No method here hides an error. The convenience is in the shape of the call,
//     not in swallowing what went wrong.

import (
	"context"
	"fmt"
	"time"
)

// ZanzibarStore is a Zanzibar store with its id and caller token already bound.
// Get one from Client.Store. It is safe for concurrent use if the underlying
// Client is; it holds no mutable state of its own.
type ZanzibarStore struct {
	c       *Client
	storeID string
	token   string
}

// Store binds a store id and caller token so you stop repeating them.
//
//	store := client.Store("my-store", userToken)
//	ok, err := store.Can(ctx, "user", "alice", "view", "doc", "123")
//
// callerToken may be "" to use the client's configured service key.
func (c *Client) Store(storeID, callerToken string) *ZanzibarStore {
	return &ZanzibarStore{c: c, storeID: storeID, token: callerToken}
}

// ID returns the bound store id.
func (s *ZanzibarStore) ID() string { return s.storeID }

// As returns a copy of this store bound to a different caller token — for
// per-request user tokens over a long-lived store handle.
func (s *ZanzibarStore) As(callerToken string) *ZanzibarStore {
	return &ZanzibarStore{c: s.c, storeID: s.storeID, token: callerToken}
}

// ---- Asking ----

// Can reports whether subject may perform permission on object. This is the call
// you will make most.
//
//	ok, err := store.Can(ctx, "user", "alice", "view", "doc", "123")
//
// FAILS CLOSED: any error returns false. Check the error — a false with a non-nil
// error means "could not decide", which is not the same as a denial and usually
// deserves a 503 rather than a 403.
func (s *ZanzibarStore) Can(ctx context.Context, subjectType, subjectID, permission, objectType, objectID string) (bool, error) {
	return s.CanID(ctx, Subject(subjectType, subjectID), permission, Object(objectType, objectID))
}

// CanID is Can for callers who already hold combined "type:id" strings.
func (s *ZanzibarStore) CanID(ctx context.Context, subject, permission, object string) (bool, error) {
	res, err := s.c.ZanzibarCheck(ctx, s.storeID, CheckPermissionRequest{
		Subject:    subject,
		Permission: permission,
		Object:     object,
	}, s.token)
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// Why is CanID with the server's explanation attached — the reason and the
// relationship path it followed. Use it when a decision is surprising and you want
// to see how the server got there, rather than guessing from the tuples.
func (s *ZanzibarStore) Why(ctx context.Context, subject, permission, object string) (*CheckPermissionResponse, error) {
	return s.c.ZanzibarCheck(ctx, s.storeID, CheckPermissionRequest{
		Subject:    subject,
		Permission: permission,
		Object:     object,
	}, s.token)
}

// CanAll reports whether EVERY check is allowed, in one round trip.
//
// FAILS CLOSED twice over: an error is false, and so is an empty checks slice —
// "nothing was asked" is not "everything is permitted".
func (s *ZanzibarStore) CanAll(ctx context.Context, checks ...CheckPermissionRequest) (bool, error) {
	if len(checks) == 0 {
		return false, nil
	}
	res, err := s.c.ZanzibarCheckBulk(ctx, s.storeID, BulkCheckRequest{Checks: checks}, s.token)
	if err != nil {
		return false, err
	}
	if len(res) != len(checks) {
		// A short response cannot be interpreted safely: we do not know which
		// check each result belongs to.
		return false, fmt.Errorf("authclient: bulk check returned %d results for %d checks", len(res), len(checks))
	}
	return res.AllAllowed(), nil
}

// CanAny reports whether AT LEAST ONE check is allowed, in one round trip.
// An empty checks slice is false.
func (s *ZanzibarStore) CanAny(ctx context.Context, checks ...CheckPermissionRequest) (bool, error) {
	if len(checks) == 0 {
		return false, nil
	}
	res, err := s.c.ZanzibarCheckBulk(ctx, s.storeID, BulkCheckRequest{Checks: checks}, s.token)
	if err != nil {
		return false, err
	}
	if len(res) != len(checks) {
		return false, fmt.Errorf("authclient: bulk check returned %d results for %d checks", len(res), len(checks))
	}
	for _, r := range res {
		if r.Allowed {
			return true, nil
		}
	}
	return false, nil
}

// Check builds one element of a CanAll/CanAny batch.
//
//	ok, err := store.CanAll(ctx,
//	    authclient.Check("user", "alice", "view", "doc", "1"),
//	    authclient.Check("user", "alice", "view", "doc", "2"),
//	)
func Check(subjectType, subjectID, permission, objectType, objectID string) CheckPermissionRequest {
	return CheckPermissionRequest{
		Subject:    Subject(subjectType, subjectID),
		Permission: permission,
		Object:     Object(objectType, objectID),
	}
}

// ---- Listing ----

// WhatCan answers "which objects of this type may this subject act on?" — the
// query behind every filtered index page ("show me the documents alice can view").
//
// Returns combined ids as the server gives them. A nil error with an empty slice
// means the subject may act on nothing, which is a real answer.
func (s *ZanzibarStore) WhatCan(ctx context.Context, subject, permission, objectType string) ([]string, error) {
	res, err := s.c.ZanzibarListObjects(ctx, s.storeID, ListObjectsRequest{
		Subject:    subject,
		Permission: permission,
		ObjectType: objectType,
	}, s.token)
	if err != nil {
		return nil, err
	}
	return res.Objects, nil
}

// WhoCan answers "who may act on this object?" — the query behind every sharing
// dialog. Group memberships are expanded to their members by default.
func (s *ZanzibarStore) WhoCan(ctx context.Context, object, permission string) ([]string, error) {
	expand := true
	res, err := s.c.ZanzibarListUsers(ctx, s.storeID, ListUsersRequest{
		Object:       object,
		Permission:   permission,
		ExpandGroups: &expand,
	}, s.token)
	if err != nil {
		return nil, err
	}
	return res.Users, nil
}

// RelationsOn lists the stored relationship tuples on one object — what is
// actually written down, as opposed to what the check engine derives from it.
// Pass relation "" for all relations.
func (s *ZanzibarStore) RelationsOn(ctx context.Context, objectType, objectID, relation string) ([]RelationshipEntry, error) {
	res, err := s.c.ListRelationships(ctx, s.storeID, objectType, objectID, relation, s.token)
	if err != nil {
		return nil, err
	}
	return res.Relationships, nil
}

// ---- Writing ----

// Relate writes one relationship tuple: subject #relation@ object.
//
//	err := store.Relate(ctx, "user", "alice", "owner", "doc", "123")
//
// Idempotent server-side: writing a tuple that already exists is not an error.
func (s *ZanzibarStore) Relate(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error {
	return s.RelateID(ctx, Subject(subjectType, subjectID), relation, Object(objectType, objectID))
}

// RelateID is Relate for callers holding combined "type:id" strings.
func (s *ZanzibarStore) RelateID(ctx context.Context, subject, relation, object string) error {
	res, err := s.c.WriteRelationships(ctx, s.storeID, RelationshipRequest{
		Object:   object,
		Relation: relation,
		Subject:  subject,
	}, s.token)
	if err != nil {
		return err
	}
	// A 200 is not a success: the server reports the outcome in the body, and
	// treating "well-formed answer" as "it worked" is how writes get silently lost.
	if !res.Success {
		return fmt.Errorf("authclient: relationship write refused: %s", res.Message)
	}
	return nil
}

// Unrelate removes one relationship tuple. Removing an absent tuple is not an error.
func (s *ZanzibarStore) Unrelate(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error {
	return s.UnrelateID(ctx, Subject(subjectType, subjectID), relation, Object(objectType, objectID))
}

// UnrelateID is Unrelate for callers holding combined "type:id" strings.
func (s *ZanzibarStore) UnrelateID(ctx context.Context, subject, relation, object string) error {
	res, err := s.c.DeleteRelationships(ctx, s.storeID, RelationshipRequest{
		Object:   object,
		Relation: relation,
		Subject:  subject,
	}, s.token)
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("authclient: relationship delete refused: %s", res.Message)
	}
	return nil
}

// RelateUntil writes a relationship that expires.
//
// Time-boxing exists on the wire and had no ergonomic path, so callers granted
// permanent access for temporary needs — a permissions leak created by the SDK's
// own surface rather than by anything the customer did wrong.
func (s *ZanzibarStore) RelateUntil(ctx context.Context, subject, relation, object string, expires time.Time) error {
	res, err := s.c.WriteRelationships(ctx, s.storeID, RelationshipRequest{
		Object:    object,
		Relation:  relation,
		Subject:   subject,
		ExpiresAt: &expires,
	}, s.token)
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("authclient: relationship write refused: %s", res.Message)
	}
	return nil
}
