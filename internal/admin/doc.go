// Package admin implements the admin-path routing carve-out described in the
// P1 core gateway design.
//
// P1 only reserves the shape of the carve-out: a three-segment path prefix
// (/slug/token1/token2/) is matched in constant time and, on match, returns
// 501 Not Implemented. On mismatch, or when the gate is disabled, the response
// is byte-identical to any other 404: empty body, Content-Length: 0, no
// distinguishing headers. The real handler arrives in P3.
//
// The timing properties must already be correct in P1 so that the P3 handler
// cannot reintroduce a side channel by accident. All three segment compares
// run unconditionally, on length-padded byte slices, using
// crypto/subtle.ConstantTimeCompare, and their results are combined with a
// bitwise AND checked once at the end. The disabled-gate path follows the
// exact same code path with dummy byte slices so that the "admin disabled"
// state is not observable by wall-clock timing.
//
// The package logs nothing. The slug and tokens are configuration secrets and
// must never appear in log output regardless of request outcome.
package admin
