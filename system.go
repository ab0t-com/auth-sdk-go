package authclient

import (
	"context"
	"encoding/json"
)

// This file covers the metrics/health/discovery surface (contract section 25):
// JWKS metrics, recent alerts, health/status probes, JWKS health + recovery,
// enterprise license/help, the metrics endpoint and the service-discovery root.
// These serve the resource-server (health/discovery) and admin (metrics)
// archetypes.

// ---- Models ----

// JwksMetricsResponse reports JWKS operational metrics.
type JwksMetricsResponse struct {
	ActiveKeys      int             `json:"active_keys,omitempty"`
	RevokedKeys     int             `json:"revoked_keys,omitempty"`
	LastRotation    string          `json:"last_rotation,omitempty"`
	NextRotation    string          `json:"next_rotation,omitempty"`
	Metrics         map[string]any  `json:"metrics,omitempty"`
	Configuration   json.RawMessage `json:"configuration,omitempty"`
	KeyMetrics      json.RawMessage `json:"key_metrics,omitempty"`
	RotationHealth  json.RawMessage `json:"rotation_health,omitempty"`
	RotationMetrics json.RawMessage `json:"rotation_metrics,omitempty"`
}

// AlertEntry is one recent operational alert.
type AlertEntry struct {
	Level     string `json:"level,omitempty"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Source    string `json:"source,omitempty"`
}

// RecentAlertsResponse lists recent alerts.
type RecentAlertsResponse struct {
	Alerts          []AlertEntry    `json:"alerts"`
	TimeRange       json.RawMessage `json:"time_range,omitempty"`
	TotalCount      int64           `json:"total_count,omitempty"`
	UnresolvedCount int64           `json:"unresolved_count,omitempty"`
}

// HealthCheckResponse is the result of GET /health. Fields are the union across
// auth backends; nested objects are left as raw JSON so callers can decode the
// parts they need without this type tracking every backend's internal shape.
type HealthCheckResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	// Timestamp is a Unix epoch (seconds, fractional). Both backends return it as
	// a JSON NUMBER — modeling it as a string made encoding/json fail the whole
	// /health decode.
	Timestamp         float64         `json:"timestamp,omitempty"`
	Dependencies      json.RawMessage `json:"dependencies,omitempty"`
	CircuitBreakers   json.RawMessage `json:"circuit_breakers,omitempty"`
	Metrics           json.RawMessage `json:"metrics,omitempty"`
	Enterprise        json.RawMessage `json:"enterprise,omitempty"`
	OAuth21           json.RawMessage `json:"oauth21,omitempty"`
	ZanzibarMigration json.RawMessage `json:"zanzibar_migration,omitempty"`
	// goauth-only fields.
	Checks         json.RawMessage `json:"checks,omitempty"`
	Runtime        json.RawMessage `json:"runtime,omitempty"`
	Service        string          `json:"service,omitempty"`
	UptimeSec      float64         `json:"uptime_sec,omitempty"`
	PasswordPolicy json.RawMessage `json:"password_policy,omitempty"`
}

// ServiceStatusResponse is the result of GET /status.
type ServiceStatusResponse struct {
	Status            string            `json:"status"`
	Uptime            string            `json:"uptime,omitempty"`
	Details           map[string]any    `json:"details,omitempty"`
	Checks            map[string]string `json:"checks,omitempty"`
	CircuitBreakers   json.RawMessage   `json:"circuit_breakers,omitempty"`
	Configuration     json.RawMessage   `json:"configuration,omitempty"`
	Dependencies      map[string]string `json:"dependencies,omitempty"`
	Enterprise        json.RawMessage   `json:"enterprise,omitempty"`
	Features          json.RawMessage   `json:"features,omitempty"`
	Metrics           json.RawMessage   `json:"metrics,omitempty"`
	Oauth21           json.RawMessage   `json:"oauth21,omitempty"`
	PasswordPolicy    json.RawMessage   `json:"password_policy,omitempty"`
	Runtime           string            `json:"runtime,omitempty"`
	Service           string            `json:"service,omitempty"`
	Timestamp         float64           `json:"timestamp,omitempty"`
	UptimeSec         int64             `json:"uptime_sec,omitempty"`
	Version           string            `json:"version,omitempty"`
	ZanzibarMigration json.RawMessage   `json:"zanzibar_migration,omitempty"`
}

// JwksHealthResponse is the result of GET /health/jwks.
type JwksHealthResponse struct {
	Healthy          bool   `json:"healthy"`
	ActiveKeys       int    `json:"active_keys,omitempty"`
	Message          string `json:"message,omitempty"`
	ActiveKeyCreated string `json:"active_key_created,omitempty"`
	ActiveKeyID      string `json:"active_key_id,omitempty"`
	Algorithm        string `json:"algorithm,omitempty"`
	Error            string `json:"error,omitempty"`
	Status           string `json:"status,omitempty"`
	TotalKeys        int64  `json:"total_keys,omitempty"`
}

// JwksRecoverResponse is the result of POST /health/jwks/recover.
type JwksRecoverResponse struct {
	Recovered   bool   `json:"recovered,omitempty"`
	Message     string `json:"message,omitempty"`
	ActiveKeyID string `json:"active_key_id,omitempty"`
	Status      string `json:"status,omitempty"`
	TotalKeys   int64  `json:"total_keys,omitempty"`
}

// ServiceDiscoveryResponse is the result of GET / (root discovery). Nested
// objects are raw JSON so callers can decode the parts they need.
type ServiceDiscoveryResponse struct {
	Service          string          `json:"service,omitempty"`
	Version          string          `json:"version,omitempty"`
	Status           string          `json:"status,omitempty"`
	Description      string          `json:"description,omitempty"`
	DiscoveryVersion string          `json:"discovery_version,omitempty"`
	Discovery        json.RawMessage `json:"discovery,omitempty"`
	APIGroups        json.RawMessage `json:"api_groups,omitempty"`
	AuthMethods      json.RawMessage `json:"auth_methods,omitempty"`
	Capabilities     json.RawMessage `json:"capabilities,omitempty"`
	MeshNetwork      json.RawMessage `json:"mesh_network,omitempty"`
	Resources        json.RawMessage `json:"resources,omitempty"`
	StartHere        json.RawMessage `json:"start_here,omitempty"`
}

// ---- Operations ----

// JWKSMetrics returns JWKS operational metrics.
// GET /metrics/jwks. Requires admin.jwks.read / jwks.read.
func (c *Client) JWKSMetrics(ctx context.Context, callerToken string) (*JwksMetricsResponse, error) {
	var out JwksMetricsResponse
	if err := c.doGet(ctx, "/metrics/jwks", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecentAlerts returns recent operational alerts.
// GET /metrics/alerts/recent. Requires admin.jwks.read / jwks.read.
func (c *Client) RecentAlerts(ctx context.Context, callerToken string) (*RecentAlertsResponse, error) {
	var out RecentAlertsResponse
	if err := c.doGet(ctx, "/metrics/alerts/recent", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// Health returns the service health check. GET /health (public).
func (c *Client) Health(ctx context.Context) (*HealthCheckResponse, error) {
	var out HealthCheckResponse
	if err := c.doGet(ctx, "/health", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status returns service status. GET /status (public).
func (c *Client) Status(ctx context.Context) (*ServiceStatusResponse, error) {
	var out ServiceStatusResponse
	if err := c.doGet(ctx, "/status", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKSHealthDetail returns JWKS health detail. GET /health/jwks (public).
func (c *Client) JWKSHealthDetail(ctx context.Context) (*JwksHealthResponse, error) {
	var out JwksHealthResponse
	if err := c.doGet(ctx, "/health/jwks", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecoverJWKS triggers JWKS recovery. POST /health/jwks/recover (public).
func (c *Client) RecoverJWKS(ctx context.Context) (*JwksRecoverResponse, error) {
	var out JwksRecoverResponse
	if err := c.doJSON(ctx, "POST", "/health/jwks/recover", struct{}{}, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnterpriseLicense fetches the enterprise license payload.
// GET /enterprise/license (public).
func (c *Client) EnterpriseLicense(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/enterprise/license", &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// Help fetches the API help payload. GET /help (public).
func (c *Client) Help(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/help", &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// EnterpriseHelp fetches the enterprise help payload. GET /help/enterprise (public).
func (c *Client) EnterpriseHelp(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/help/enterprise", &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// Metrics fetches the service metrics payload.
// GET /metrics. Requires admin.metrics.read / metrics.read.
func (c *Client) Metrics(ctx context.Context, callerToken string) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/metrics", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// Discover fetches the service-discovery root. GET / (public).
func (c *Client) Discover(ctx context.Context) (*ServiceDiscoveryResponse, error) {
	var out ServiceDiscoveryResponse
	if err := c.doGet(ctx, "/", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}
