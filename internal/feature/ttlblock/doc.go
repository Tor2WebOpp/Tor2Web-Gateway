// Package ttlblock implements the "ttl_blocklist" feature: a persistent
// IP blocklist with automatic time-based expiry, backed by BoltDB.
//
// Entries live in an on-disk key/value store. Each entry carries a
// BlockedUntil timestamp, a reason string, and the owning tenant. A
// background sweeper goroutine periodically removes expired rows so the
// database does not grow without bound.
//
// Parameters (from the feature snapshot):
//
//   - db_path       string         path to the BoltDB file.
//   - default_ttl   string         Go duration (e.g. "24h") used when
//                                  Add receives a zero duration.
//   - action        string         one of drop|404|429|timeout.
//   - salted_hashes bool           if true, keys are sha256(ip||salt);
//                                  plaintext IPs never hit disk.
//   - salt_file     string         where the per-install salt is persisted
//                                  when salted_hashes is true.
//   - max_entries   int            LRU-style cap. When exceeded, the
//                                  oldest (by BlockedUntil) rows for the
//                                  affected tenant are trimmed on Add.
//   - trust_xff     bool           use the leftmost X-Forwarded-For entry
//                                  when present. Off by default to avoid
//                                  header spoofing.
//
// Key format: fmt.Sprintf("%s\x00%s", tenant, ip-or-hash) — the NUL byte
// avoids ambiguity between tenant boundaries and IPv4/IPv6 separators.
//
// Hot path: Contains takes a single BoltDB read transaction, decodes one
// JSON value and checks the timestamp. The middleware branches on a
// cached atomic bool before doing any allocation when the feature is
// globally disabled.
package ttlblock
