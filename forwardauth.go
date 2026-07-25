package authclient

import (
	"context"
	"net/http"
)

// This file covers the forward-auth domain (contract section 22): edge /
// reverse-proxy auth decision endpoints. These serve the resource-server
// archetype at the proxy edge. Each endpoint returns a 2xx (allow) or non-2xx
// (deny) decision; GET/POST/HEAD verbs are all accepted on the live, root,
// pass and fail paths. A 2xx is surfaced as a true decision and a 403/401 as
// false; other non-2xx still return an *APIError.

// ForwardAuthDecision reports a proxy auth decision plus echoed headers.
type ForwardAuthDecision struct {
	// Allowed is true when the forward-auth endpoint returned a 2xx.
	Allowed bool
	// StatusCode is the HTTP status the auth service returned.
	StatusCode int
	// Body is the raw response body (may carry identity headers/JSON).
	Body string
}

// forwardAuthDecide issues a forward-auth request and maps the outcome to a
// decision. token, when non-empty, is forwarded as the bearer to validate; the
// proxy edge typically copies the inbound Authorization header here.
func (c *Client) forwardAuthDecide(ctx context.Context, method, path, token string) (*ForwardAuthDecision, error) {
	body, err := c.doRaw(ctx, method, path, "", nil, token)
	if err == nil {
		return &ForwardAuthDecision{Allowed: true, StatusCode: 200, Body: body}, nil
	}
	if ae, ok := err.(*APIError); ok {
		if ae.StatusCode == http.StatusUnauthorized || ae.StatusCode == http.StatusForbidden {
			return &ForwardAuthDecision{Allowed: false, StatusCode: ae.StatusCode, Body: ae.Body}, nil
		}
	}
	return nil, err
}

// ForwardAuthLive is the liveness decision endpoint. method may be GET, POST or
// HEAD. /forward-auth/live.
func (c *Client) ForwardAuthLive(ctx context.Context, method, token string) (*ForwardAuthDecision, error) {
	return c.forwardAuthDecide(ctx, normalizeFAMethod(method), "/forward-auth/live", token)
}

// ForwardAuth is the primary forward-auth decision endpoint. method may be GET,
// POST or HEAD. /forward-auth/.
func (c *Client) ForwardAuth(ctx context.Context, method, token string) (*ForwardAuthDecision, error) {
	return c.forwardAuthDecide(ctx, normalizeFAMethod(method), "/forward-auth/", token)
}

// ForwardAuthPass is the explicit-pass decision endpoint. method may be GET,
// POST or HEAD. /forward-auth/pass.
func (c *Client) ForwardAuthPass(ctx context.Context, method, token string) (*ForwardAuthDecision, error) {
	return c.forwardAuthDecide(ctx, normalizeFAMethod(method), "/forward-auth/pass", token)
}

// ForwardAuthFail is the explicit-fail decision endpoint. method may be GET,
// POST or HEAD. /forward-auth/fail.
func (c *Client) ForwardAuthFail(ctx context.Context, method, token string) (*ForwardAuthDecision, error) {
	return c.forwardAuthDecide(ctx, normalizeFAMethod(method), "/forward-auth/fail", token)
}

func normalizeFAMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodHead:
		return method
	case "":
		return http.MethodGet
	default:
		return method
	}
}
