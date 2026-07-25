package authclient

// observe.go — the observability seam.
//
// A service that embeds this client needs to see what it did: which calls it made,
// how long they took, what came back, how often it retried. Without a seam the
// only options are wrapping every call site (nobody does this consistently) or
// swapping in a custom http.Client and re-deriving the endpoint from the URL.
//
// WHY A CALLBACK AND NOT A LOGGER
//
// A logger in a library is three decisions imposed on the consumer: which logging
// package, which format, which level. Ship a *log.Logger and zap users bridge it;
// ship slog and pre-1.21 consumers cannot use it; ship an interface and everyone
// writes an adapter. A single callback carries the facts and lets the consumer
// decide — it feeds slog, zap, an OTel span, a Prometheus histogram, or a test
// assertion equally well, and adds no dependency to a module whose defining
// property is having none.
//
// WHAT IT DELIBERATELY DOES NOT CARRY
//
// No headers, no request body, no response body. This client's whole job is
// handling credentials, and an observability hook is exactly the kind of thing
// that ends up piped to a log aggregator. A path and a status cannot leak a
// token; an Authorization header can. If you need bodies, wrap the http.Client
// with WithHTTPClient — that is an explicit act with visible consequences.

import "time"

// RequestInfo describes one completed HTTP attempt. A call that is retried
// produces one RequestInfo per attempt, so retry behaviour is visible rather than
// hidden inside a single "slow call".
type RequestInfo struct {
	// Method is the HTTP method, e.g. "POST".
	Method string
	// Endpoint is the request path with any query string stripped — a stable,
	// low-cardinality label suitable as a metric dimension. Path parameters are
	// NOT templated, so ids do appear here; aggregate accordingly.
	Endpoint string
	// Status is the HTTP status code, or 0 when the request never got a response
	// (connection failure, timeout, cancelled context — Err says which).
	Status int
	// Duration is how long this attempt took.
	Duration time.Duration
	// Attempt is 0 for the first try, 1 for the first retry, and so on.
	Attempt int
	// Retrying reports whether the client is about to retry after this attempt.
	// Exactly one RequestInfo per logical call has Retrying == false.
	Retrying bool
	// Err is the transport error, if any. A non-2xx response is NOT an error
	// here — check Status. This field means the request did not complete.
	Err error
	// RequestID is the service's correlation id from the response, when present.
	// Quote it in a bug report; it is how the service finds your call in its logs.
	RequestID string
}

// Observer is called once per completed HTTP attempt.
//
// It runs on the calling goroutine, inside the request path, so it must be fast
// and must not block — a slow observer slows every request. It must also be safe
// for concurrent use if the client is shared, which it is designed to be.
//
// A panic in an Observer is NOT recovered. That is deliberate: swallowing it would
// hide a bug in consumer code at the exact place a consumer is least likely to
// look, and a panic in an observability hook should be as loud as any other.
type Observer func(RequestInfo)

// WithObserver installs a callback invoked once per completed HTTP attempt.
//
//	client := authclient.New("", authclient.WithObserver(func(i authclient.RequestInfo) {
//	    slog.Info("auth call",
//	        "method", i.Method, "endpoint", i.Endpoint, "status", i.Status,
//	        "ms", i.Duration.Milliseconds(), "attempt", i.Attempt, "err", i.Err)
//	}))
//
// Passing nil clears any previously set observer. With none set the client behaves
// exactly as before — the hook is not consulted at all.
func WithObserver(fn Observer) Option {
	return func(c *Client) { c.observer = fn }
}

// observe fires the callback if one is installed. Kept tiny and nil-guarded so the
// no-observer path stays a single branch.
func (c *Client) observe(i RequestInfo) {
	if c.observer != nil {
		c.observer(i)
	}
}
