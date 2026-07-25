package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxBodyBytes caps how much of a response body we read (for both decode and
// error capture), guarding against unbounded responses.
const maxBodyBytes = 4 << 20 // 4 MiB

// doJSON sends an optional JSON body and decodes a JSON response into out.
// bearer, if non-empty, sets Authorization: Bearer <bearer>.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any, bearer string) error {
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		raw = b
	}
	return c.do(ctx, method, path, "application/json", raw, out, bearer)
}

// doForm posts application/x-www-form-urlencoded (used by /token/introspect).
func (c *Client) doForm(ctx context.Context, path string, form url.Values, out any, bearer string) error {
	return c.do(ctx, http.MethodPost, path, "application/x-www-form-urlencoded",
		[]byte(form.Encode()), out, bearer)
}

// doGet performs a GET and decodes JSON into out.
func (c *Client) doGet(ctx context.Context, path string, out any, bearer string) error {
	return c.do(ctx, http.MethodGet, path, "", nil, out, bearer)
}

// getString performs a GET and returns the raw response body (for endpoints
// that return XML/HTML/text such as SAML metadata).
func (c *Client) getString(ctx context.Context, path, bearer string) (string, error) {
	return c.doRaw(ctx, http.MethodGet, path, "", nil, bearer)
}

// postFormString posts a form and returns the raw response body.
func (c *Client) postFormString(ctx context.Context, path string, form url.Values) (string, error) {
	return c.doRaw(ctx, http.MethodPost, path, "application/x-www-form-urlencoded", []byte(form.Encode()), "")
}

// doRaw performs the request with retry/backoff and returns the raw response
// body as a string. It shares the error/retry model with do, but does not
// attempt JSON decoding.
func (c *Client) doRaw(ctx context.Context, method, path, contentType string, body []byte, bearer string) (string, error) {
	endpoint := stripQuery(path)

	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
		if err != nil {
			return "", err
		}
		if contentType != "" && body != nil {
			req.Header.Set("Content-Type", contentType)
		}
		c.applyCommon(req, bearer)

		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return "", err
			}
			if attempt < c.maxRetries && isIdempotent(method) {
				if werr := c.wait(ctx, attempt, 0); werr != nil {
					return "", werr
				}
				continue
			}
			return "", err
		}

		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return string(data), nil
		}

		apiErr := parseAPIError(resp.StatusCode, method, endpoint, requestID(resp.Header), string(data))
		if attempt < c.maxRetries && IsRetryable(apiErr) {
			if werr := c.wait(ctx, attempt, retryAfter(resp.Header)); werr != nil {
				return "", werr
			}
			continue
		}
		return "", apiErr
	}
}

// do performs the request with retry/backoff and decodes the response.
//
// Retries apply to:
//   - transport errors on idempotent methods (GET), and
//   - any 429 or 5xx response (these are safe to retry because the body is
//     buffered and replayable, and a 5xx implies the request was not durably
//     applied or the caller has opted into at-least-once semantics).
//
// On 429/503 the Retry-After header is honored when present.
func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte, out any, bearer string) error {
	endpoint := stripQuery(path)

	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
		if err != nil {
			return err
		}
		if contentType != "" && body != nil {
			req.Header.Set("Content-Type", contentType)
		}
		c.applyCommon(req, bearer)

		resp, err := c.http.Do(req)
		if err != nil {
			// Context cancellation/deadline is terminal.
			if ctx.Err() != nil {
				return err
			}

			if attempt < c.maxRetries && isIdempotent(method) {
				if werr := c.wait(ctx, attempt, 0); werr != nil {
					return werr
				}
				continue
			}
			return err
		}

		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil || len(data) == 0 {
				return nil
			}
			return json.Unmarshal(data, out)
		}

		apiErr := parseAPIError(resp.StatusCode, method, endpoint, requestID(resp.Header), string(data))

		if attempt < c.maxRetries && IsRetryable(apiErr) {
			if werr := c.wait(ctx, attempt, retryAfter(resp.Header)); werr != nil {
				return werr
			}
			continue
		}
		return apiErr
	}
}

// applyCommon sets shared headers. If bearer is empty, falls back to the
// configured service API key (so service-to-service calls authenticate).
func (c *Client) applyCommon(req *http.Request, bearer string) {
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if bearer == "" {
		bearer = c.apiKey
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
}

// wait sleeps for the backoff appropriate to attempt (0-indexed), honoring a
// server-supplied Retry-After when non-zero, and aborts on context cancellation.
func (c *Client) wait(ctx context.Context, attempt int, serverHint time.Duration) error {
	d := serverHint
	if d <= 0 {
		d = c.backoff(attempt)
	}
	if d > c.backoffMax {
		d = c.backoffMax
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// backoff returns base * 2^attempt with full jitter, capped at backoffMax.
func (c *Client) backoff(attempt int) time.Duration {
	d := c.backoffBase << attempt
	if d <= 0 || d > c.backoffMax {
		d = c.backoffMax
	}
	// Full jitter in [0, d].
	return time.Duration(rand.Int63n(int64(d) + 1))
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

// retryAfter parses the Retry-After header (seconds or HTTP-date) into a delay.
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func requestID(h http.Header) string {
	for _, k := range []string{"X-Request-ID", "X-Request-Id", "X-Correlation-ID", "X-Trace-ID"} {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func stripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}
