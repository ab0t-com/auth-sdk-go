package authclient

import "context"

// This file covers the metrics/health/discovery surface (contract section 25):
// JWKS metrics, recent alerts, health/status probes, JWKS health + recovery,
// enterprise license/help, the metrics endpoint and the service-discovery root.
// These serve the resource-server (health/discovery) and admin (metrics)
// archetypes.

// ---- Models ----

// JwksMetricsResponse reports JWKS operational metrics.
type JwksMetricsResponse struct {
	ActiveKeys   int            `json:"active_keys,omitempty"`
	RevokedKeys  int            `json:"revoked_keys,omitempty"`
	LastRotation string         `json:"last_rotation,omitempty"`
	NextRotation string         `json:"next_rotation,omitempty"`
	Metrics      map[string]any `json:"metrics,omitempty"`
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
	Alerts []AlertEntry `json:"alerts"`
}

// HealthCheckResponse is the result of GET /health.
type HealthCheckResponse struct {
	Status     string            `json:"status"`
	Version    string            `json:"version,omitempty"`
	Components map[string]string `json:"components,omitempty"`
}

// ServiceStatusResponse is the result of GET /status.
type ServiceStatusResponse struct {
	Status  string         `json:"status"`
	Uptime  string         `json:"uptime,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// JwksHealthResponse is the result of GET /health/jwks.
type JwksHealthResponse struct {
	Healthy    bool   `json:"healthy"`
	ActiveKeys int    `json:"active_keys,omitempty"`
	Message    string `json:"message,omitempty"`
}

// JwksRecoverResponse is the result of POST /health/jwks/recover.
type JwksRecoverResponse struct {
	Recovered bool   `json:"recovered,omitempty"`
	Message   string `json:"message,omitempty"`
}

// ServiceDiscoveryResponse is the result of GET / (root discovery).
type ServiceDiscoveryResponse struct {
	Service   string            `json:"service,omitempty"`
	Version   string            `json:"version,omitempty"`
	Endpoints map[string]string `json:"endpoints,omitempty"`
	Links     map[string]string `json:"links,omitempty"`
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
