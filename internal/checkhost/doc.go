// Package checkhost is a minimal client for the public check-host.net HTTP
// check API. It powers the hub's mirror-health monitor (P2) by asking
// distributed vantage points whether a mirror domain is reachable from each
// region, used to detect per-region blocks and decide which mirrors doors
// are allowed to redirect to.
//
// The public API offers two endpoints:
//
//   POST /check-http?host=<mirror>&max_nodes=N
//        returns {request_id, nodes, permanent_node_names}
//
//   GET  /check-result/<request_id>
//        returns map[node_id] [[code, time, error]] (or null per node while
//        results are still in flight)
//
// Client wraps these with:
//
//   - Context-aware HTTP calls with an injected *http.Client for tests.
//   - A golang.org/x/time/rate limiter so workers do not exceed the ~1 req/5s
//     budget check-host.net publishes.
//   - Typed ErrRateLimited{RetryAfter} on HTTP 429 so callers can honour the
//     Retry-After header instead of guessing.
//   - Tuple-to-struct decoding for per-node results and a pending signal when
//     the service returns null for a node that has not reported yet.
//   - CheckNow convenience that performs StartHTTPCheck, polls GetResult
//     until ready (or maxWait elapses), and returns the snapshot.
//
// The package has no dependencies outside the standard library and
// golang.org/x/time/rate.
package checkhost
