// Package metrics provides OPSEC-safe helpers for labelling Prometheus
// series without exposing raw tenant identifiers.
//
// The central type is Labeler, which, when configured with
// HashTenantLabels=true, rewrites tenant hostnames into short, salted
// SHA-256 digests. Client IP addresses are always hashed (truncated), so
// scraped metrics never carry raw endpoint identifiers even if tenant
// hashing is disabled.
//
// The salt is loaded from a file. If the file does not exist it is
// created with 32 crypto/rand bytes and mode 0600. If it exists with
// looser permissions than 0600 the constructor refuses to run — a
// leaked salt invalidates the hash guarantee.
//
// This package intentionally depends only on the Go standard library.
package metrics
