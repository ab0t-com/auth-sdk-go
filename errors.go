package authclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is returned for non-2xx responses from the auth service. It captures
// the HTTP status, the endpoint that produced it, a best-effort machine-readable
// error code parsed from the response body, and the raw body for diagnostics.
//
// Callers should generally branch on the Is* helpers (IsUnauthorized, etc.)
// rather than comparing StatusCode directly.
type APIError struct {
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Method is the HTTP method of the originating request.
	Method string
	// Endpoint is the request path (no query string) that produced the error.
	Endpoint string
	// Code is a machine-readable error code parsed from the body, if any
	// (e.g. "invalid_grant", "token_expired"). Empty when not present.
	Code string
	// Message is a human-readable message parsed from the body, if any.
	Message string
	// RequestID echoes any X-Request-ID / request correlation id returned.
	RequestID string
	// Body is the raw (possibly truncated) response body.
	Body string
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("authclient: ")
	if e.Method != "" {
		b.WriteString(e.Method)
		b.WriteByte(' ')
	}
	b.WriteString(e.Endpoint)
	b.WriteString(": ")
	fmt.Fprintf(&b, "status %d %s", e.StatusCode, http.StatusText(e.StatusCode))
	if e.Code != "" {
		b.WriteString(" [")
		b.WriteString(e.Code)
		b.WriteByte(']')
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	} else if e.Body != "" {
		b.WriteString(": ")
		b.WriteString(truncate(e.Body, 256))
	}
	if e.RequestID != "" {
		b.WriteString(" (request_id=")
		b.WriteString(e.RequestID)
		b.WriteByte(')')
	}
	return b.String()
}

// parseAPIError builds an APIError, extracting code/message from common
// JSON error envelopes used by the auth service. It is tolerant of FastAPI's
// {"detail": ...} as well as RFC-style {"error", "error_description"} and
// {"code", "message"} shapes.
func parseAPIError(status int, method, endpoint, requestID, body string) *APIError {
	e := &APIError{
		StatusCode: status,
		Method:     method,
		Endpoint:   endpoint,
		RequestID:  requestID,
		Body:       body,
	}
	e.Code, e.Message = extractCodeMessage(body)
	return e
}

func extractCodeMessage(body string) (code, msg string) {
	body = strings.TrimSpace(body)
	if body == "" || body[0] != '{' {
		return "", ""
	}
	var env struct {
		Error            json.RawMessage `json:"error"`
		ErrorDescription string          `json:"error_description"`
		Code             string          `json:"code"`
		Message          string          `json:"message"`
		Detail           json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return "", ""
	}

	// RFC 6749/7662 style: {"error": "invalid_grant", "error_description": "..."}.
	if len(env.Error) > 0 {
		var s string
		if json.Unmarshal(env.Error, &s) == nil {
			code = s
		} else {
			// {"error": {"code": ..., "message": ...}}
			var obj struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if json.Unmarshal(env.Error, &obj) == nil {
				code = obj.Code
				msg = obj.Message
			}
		}
	}
	if env.ErrorDescription != "" {
		msg = env.ErrorDescription
	}
	if env.Code != "" {
		code = env.Code
	}
	if env.Message != "" {
		msg = env.Message
	}

	// FastAPI style: {"detail": "..."} or {"detail": [{"msg": ...}]}.
	if msg == "" && len(env.Detail) > 0 {
		var ds string
		if json.Unmarshal(env.Detail, &ds) == nil {
			msg = ds
		} else {
			var items []struct {
				Msg  string `json:"msg"`
				Type string `json:"type"`
			}
			if json.Unmarshal(env.Detail, &items) == nil && len(items) > 0 {
				msg = items[0].Msg
				if code == "" {
					code = items[0].Type
				}
			}
		}
	}
	return code, msg
}

// AsAPIError returns the underlying *APIError if err wraps one.
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// StatusCode returns the HTTP status code carried by err, or 0 if err is not
// an APIError.
func StatusCode(err error) int {
	if ae, ok := AsAPIError(err); ok {
		return ae.StatusCode
	}
	return 0
}

// IsUnauthorized reports whether err is an APIError with a 401 status
// (authentication failed / token missing, expired, or invalid).
func IsUnauthorized(err error) bool { return StatusCode(err) == http.StatusUnauthorized }

// IsForbidden reports whether err is an APIError with a 403 status
// (authenticated but lacking the required permission/role).
func IsForbidden(err error) bool { return StatusCode(err) == http.StatusForbidden }

// IsNotFound reports whether err is an APIError with a 404 status.
func IsNotFound(err error) bool { return StatusCode(err) == http.StatusNotFound }

// IsConflict reports whether err is an APIError with a 409 status.
func IsConflict(err error) bool { return StatusCode(err) == http.StatusConflict }

// IsBadRequest reports whether err is an APIError with a 400 status.
func IsBadRequest(err error) bool { return StatusCode(err) == http.StatusBadRequest }

// IsValidationError reports whether err is an APIError with a 422 status
// (request body failed server-side validation).
func IsValidationError(err error) bool { return StatusCode(err) == http.StatusUnprocessableEntity }

// IsRateLimited reports whether err is an APIError with a 429 status.
func IsRateLimited(err error) bool { return StatusCode(err) == http.StatusTooManyRequests }

// IsServerError reports whether err is an APIError with a 5xx status.
func IsServerError(err error) bool {
	s := StatusCode(err)
	return s >= 500 && s <= 599
}

// IsRetryable reports whether err represents a transient condition that the
// transport considers safe to retry (429 or 5xx).
func IsRetryable(err error) bool {
	s := StatusCode(err)
	return s == http.StatusTooManyRequests || (s >= 500 && s <= 599)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
