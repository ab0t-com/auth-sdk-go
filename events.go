package authclient

import (
	"context"
	"net/url"
)

// This file covers the events / webhook-subscription domain (contract section
// 20): event-type discovery and subscription lifecycle (create/list/get/
// update/delete/test/toggle/stats). These serve the service/machine and admin
// archetypes via events.* scopes.

// ---- Models ----

// EventTypeInfo describes one emittable event type.
type EventTypeInfo struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

// EventTypesResponse lists available event types.
type EventTypesResponse struct {
	EventTypes []EventTypeInfo `json:"event_types"`
}

// EventSubscriptionCreate is the body for POST /events/subscriptions.
type EventSubscriptionCreate struct {
	URL         string            `json:"url"`
	EventTypes  []string          `json:"event_types"`
	Secret      string            `json:"secret,omitempty"`
	Active      bool              `json:"active,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description,omitempty"`
}

// EventSubscriptionUpdate is the body for PATCH /events/subscriptions/{id}.
type EventSubscriptionUpdate struct {
	URL         *string            `json:"url,omitempty"`
	EventTypes  *[]string          `json:"event_types,omitempty"`
	Secret      *string            `json:"secret,omitempty"`
	Active      *bool              `json:"active,omitempty"`
	Headers     *map[string]string `json:"headers,omitempty"`
	Description *string            `json:"description,omitempty"`
}

// EventSubscription is a webhook subscription.
type EventSubscription struct {
	ID          string            `json:"id"`
	URL         string            `json:"url,omitempty"`
	EventTypes  []string          `json:"event_types,omitempty"`
	Active      bool              `json:"active,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
}

// EventSubscriptionListResponse lists webhook subscriptions.
type EventSubscriptionListResponse struct {
	Subscriptions []EventSubscription `json:"subscriptions"`
	Total         int                 `json:"total,omitempty"`
}

// EventSubscriptionTestResponse is the result of a test delivery.
type EventSubscriptionTestResponse struct {
	Success      bool   `json:"success,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	ResponseBody string `json:"response_body,omitempty"`
	Message      string `json:"message,omitempty"`
}

// EventSubscriptionStatsResponse reports delivery statistics.
type EventSubscriptionStatsResponse struct {
	Delivered int            `json:"delivered,omitempty"`
	Failed    int            `json:"failed,omitempty"`
	Pending   int            `json:"pending,omitempty"`
	Stats     map[string]any `json:"stats,omitempty"`
}

// ---- Operations ----

// EventTypes lists the available event types. GET /events/types (public).
func (c *Client) EventTypes(ctx context.Context) (*EventTypesResponse, error) {
	var out EventTypesResponse
	if err := c.doGet(ctx, "/events/types", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateEventSubscription creates a webhook subscription.
// POST /events/subscriptions. Requires events.subscribe.
func (c *Client) CreateEventSubscription(ctx context.Context, req EventSubscriptionCreate, token string) (*EventSubscription, error) {
	var out EventSubscription
	if err := c.doJSON(ctx, "POST", "/events/subscriptions", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListEventSubscriptions lists webhook subscriptions.
// GET /events/subscriptions. Requires events.read.
func (c *Client) ListEventSubscriptions(ctx context.Context, token string) (*EventSubscriptionListResponse, error) {
	var out EventSubscriptionListResponse
	if err := c.doGet(ctx, "/events/subscriptions", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetEventSubscription fetches a webhook subscription.
// GET /events/subscriptions/{subscription_id}. Requires events.read.
func (c *Client) GetEventSubscription(ctx context.Context, subscriptionID, token string) (*EventSubscription, error) {
	var out EventSubscription
	if err := c.doGet(ctx, "/events/subscriptions/"+url.PathEscape(subscriptionID), &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateEventSubscription partially updates a webhook subscription.
// PATCH /events/subscriptions/{subscription_id}. Requires events.update.
func (c *Client) UpdateEventSubscription(ctx context.Context, subscriptionID string, req EventSubscriptionUpdate, token string) (*EventSubscription, error) {
	var out EventSubscription
	if err := c.doJSON(ctx, "PATCH", "/events/subscriptions/"+url.PathEscape(subscriptionID), req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteEventSubscription deletes a webhook subscription.
// DELETE /events/subscriptions/{subscription_id}. Requires events.delete.
func (c *Client) DeleteEventSubscription(ctx context.Context, subscriptionID, token string) error {
	return c.doJSON(ctx, "DELETE", "/events/subscriptions/"+url.PathEscape(subscriptionID), nil, nil, token)
}

// TestEventSubscription triggers a test delivery for a subscription.
// POST /events/subscriptions/{subscription_id}/test. Requires events.test.
func (c *Client) TestEventSubscription(ctx context.Context, subscriptionID, token string) (*EventSubscriptionTestResponse, error) {
	var out EventSubscriptionTestResponse
	if err := c.doJSON(ctx, "POST", "/events/subscriptions/"+url.PathEscape(subscriptionID)+"/test", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ToggleEventSubscription enables/disables a subscription.
// POST /events/subscriptions/{subscription_id}/toggle. Requires events.update.
func (c *Client) ToggleEventSubscription(ctx context.Context, subscriptionID, token string) (*EventSubscription, error) {
	var out EventSubscription
	if err := c.doJSON(ctx, "POST", "/events/subscriptions/"+url.PathEscape(subscriptionID)+"/toggle", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// EventSubscriptionStats returns delivery statistics for a subscription.
// GET /events/subscriptions/{subscription_id}/stats. Requires events.read.
func (c *Client) EventSubscriptionStats(ctx context.Context, subscriptionID, token string) (*EventSubscriptionStatsResponse, error) {
	var out EventSubscriptionStatsResponse
	if err := c.doGet(ctx, "/events/subscriptions/"+url.PathEscape(subscriptionID)+"/stats", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}
