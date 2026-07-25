package authclient

import (
	"context"
	"net/url"
)

// This file extends the SDK with the Users domain (contract section 8):
// self-service profile management and admin user lifecycle. The core
// GetUser / GetMyOrganizations / Me operations live in operations.go; the
// remaining 9 user operations are added here.

// ---- Models ----

// MessageResponse is the generic {"message": ...} envelope returned by many
// mutating endpoints across the auth service.
type MessageResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// MessageDetailResponse adds a structured detail/status to a message
// (used by user activate/deactivate).
type MessageDetailResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	Status  string `json:"status,omitempty"`
	UserID  string `json:"user_id,omitempty"`
}

// UserUpdate is the body for PUT /users/me and PUT /users/{user_id}.
// Only non-nil fields are sent, giving partial-update (PATCH-like) semantics.
type UserUpdate struct {
	Name      *string         `json:"name,omitempty"`
	Phone     *string         `json:"phone,omitempty"`
	AvatarURL *string         `json:"avatar_url,omitempty"`
	Timezone  *string         `json:"timezone,omitempty"`
	Language  *string         `json:"language,omitempty"`
	Metadata  *map[string]any `json:"metadata,omitempty"`
}

// ChangePassword is the body for POST /users/me/change-password.
type ChangePassword struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// PasswordReset is the body for POST /users/request-password-reset,
// POST /auth/password-reset, and POST /auth/check-permission's reset flows.
type PasswordReset struct {
	Email string `json:"email"`
	OrgID string `json:"org_id,omitempty"`
}

// PasswordResetResponse is the result of requesting a password reset.
type PasswordResetResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// PasswordResetConfirm is the body for POST /users/reset-password and
// POST /auth/password-reset/confirm.
type PasswordResetConfirm struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// PasswordResetConfirmResponse is the result of confirming a password reset.
type PasswordResetConfirmResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// ---- Self-service ----

// GetMyProfile returns the caller's full profile. GET /users/me.
func (c *Client) GetMyProfile(ctx context.Context, token string) (*User, error) {
	var out User
	if err := c.doGet(ctx, "/users/me", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateMyProfile applies a partial update to the caller's profile.
// PUT /users/me.
func (c *Client) UpdateMyProfile(ctx context.Context, token string, upd UserUpdate) (*User, error) {
	var out User
	if err := c.doJSON(ctx, "PUT", "/users/me", upd, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChangeMyPassword changes the caller's password.
// POST /users/me/change-password.
func (c *Client) ChangeMyPassword(ctx context.Context, token string, req ChangePassword) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", "/users/me/change-password", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Admin user management (users.read / users.write) ----

// UpdateUser updates a user by id (requires users.write).
// PUT /users/{user_id}.
func (c *Client) UpdateUser(ctx context.Context, userID string, upd UserUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/users/"+url.PathEscape(userID), upd, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyUserEmail force-marks a user's email verified (requires users.write).
// POST /users/{user_id}/verify-email.
func (c *Client) VerifyUserEmail(ctx context.Context, userID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", "/users/"+url.PathEscape(userID)+"/verify-email", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeactivateUser deactivates a user (requires users.write).
// POST /users/{user_id}/deactivate.
func (c *Client) DeactivateUser(ctx context.Context, userID, callerToken string) (*MessageDetailResponse, error) {
	var out MessageDetailResponse
	if err := c.doJSON(ctx, "POST", "/users/"+url.PathEscape(userID)+"/deactivate", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActivateUser reactivates a user (requires users.write).
// POST /users/{user_id}/activate.
func (c *Client) ActivateUser(ctx context.Context, userID, callerToken string) (*MessageDetailResponse, error) {
	var out MessageDetailResponse
	if err := c.doJSON(ctx, "POST", "/users/"+url.PathEscape(userID)+"/activate", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Public password reset (self-service, no auth) ----

// RequestPasswordReset starts a password-reset flow (sends an email).
// POST /users/request-password-reset. PUBLIC.
func (c *Client) RequestPasswordReset(ctx context.Context, req PasswordReset) (*PasswordResetResponse, error) {
	var out PasswordResetResponse
	if err := c.doJSON(ctx, "POST", "/users/request-password-reset", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResetPassword completes a password-reset flow with a token.
// POST /users/reset-password. PUBLIC.
func (c *Client) ResetPassword(ctx context.Context, req PasswordResetConfirm) (*PasswordResetConfirmResponse, error) {
	var out PasswordResetConfirmResponse
	if err := c.doJSON(ctx, "POST", "/users/reset-password", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Self-service account deletion (GDPR / right to erasure) ----

// SelfDeleteRequest is the confirmation body for DELETE /users/me.
// Matches OpenAPI schema SelfDeleteRequest (required: confirm_email).
//
// ConfirmEmail MUST exactly match the authenticated caller's own account email.
// It is the irreversible-action guard — the same "type your address to confirm"
// pattern a UI would use. A mismatch is rejected and NO state changes.
type SelfDeleteRequest struct {
	ConfirmEmail string `json:"confirm_email"`
}

// SelfDeleteResponse is the result of DELETE /users/me.
//
// The server's response body is not tightly specified, so the useful fields are
// modelled optimistically and Raw retains anything else. Treat a nil error as
// the authoritative signal that the deletion was accepted.
type SelfDeleteResponse struct {
	Success bool   `json:"success,omitempty"`
	Message string `json:"message,omitempty"`
	UserID  string `json:"user_id,omitempty"`
}

// DeleteCurrentUser IRREVERSIBLY deletes the authenticated caller's own account.
// DELETE /users/me. Requires the caller's own bearer token; there is no
// admin/impersonation form of this call — a user may only delete themselves.
//
// ⚠️  THIS IS NOT UNDOABLE. Per the endpoint's own contract the server will:
// soft-delete the account and anonymize its PII, invalidate every session,
// hard-delete every API key, remove permissions, delegations and Zanzibar
// relationship tuples, drop organization and team memberships (flagging any
// organization left without an owner), clean up enterprise records, and emit an
// audit event.
//
// confirmEmail must equal the caller's own account email exactly; a mismatch is
// rejected with no state change. Callers should obtain it from a deliberate user
// action (typing it), never auto-fill it from the session — auto-filling defeats
// the entire purpose of the guard.
func (c *Client) DeleteCurrentUser(ctx context.Context, confirmEmail, callerToken string) (*SelfDeleteResponse, error) {
	var out SelfDeleteResponse
	req := SelfDeleteRequest{ConfirmEmail: confirmEmail}
	if err := c.doJSON(ctx, "DELETE", "/users/me", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
