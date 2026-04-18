# OPSEC linter

A small, stdlib-only Go program that scans the repository tree and any
compiled binaries for a configurable list of banned substrings. It is
intended to catch accidental leaks of internal project codenames,
personal identifiers, or analytics endpoints before they reach a public
commit or release artifact.

The linter enforces the first and sixth points of the P1 OPSEC
principles (see
`docs/superpowers/specs/2026-04-18-P1-core-multitenant-remote-hub-design.md`,
"OPSEC principles"):

1. No identifying strings in code, binaries, help text, or error
   messages. Ship a neutral project name.
2. No outbound calls from edge to anything other than the hub and the
   user's backends. (The linter flags analytics/telemetry domains if
   they are added to the banned list.)

## What it does

- Walks the repo, skipping `.git/`, `node_modules/`, `vendor/`, binary
  media (`.png`, `.jpg`, `.pdf`, fonts, archives, ...), the banned-list
  file itself, and files larger than 20 MB.
- For every remaining text file, searches case-insensitively for each
  banned substring and reports `file:line:col` hits.
- For every binary passed via `--binaries`, extracts printable ASCII
  runs of >= 4 bytes (a `strings`-equivalent) and searches those for the
  banned terms.
- Optionally (`--scan-git`) scans `git log` commit messages.
- Reads `go.mod` and surfaces any `replace` directives as non-fatal
  warnings -- they usually indicate a local dev setup and should not be
  shipped.

## Exit codes

| code | meaning                             |
|------|-------------------------------------|
| 0    | clean                               |
| 1    | violations found (fatal in CI)      |
| 2    | IO or configuration error           |

## Running locally

From the `gateway/` directory:

```sh
# fast repo-only scan
go run ./tests/opsec --repo=. --banned=./tests/opsec/banned_strings.txt

# include compiled binaries
go build -o /tmp/gateway-proxy   ./cmd/gateway-proxy
go build -o /tmp/gateway-torpool ./cmd/gateway-torpool
go build -o /tmp/gateway-hub     ./cmd/gateway-hub
go run ./tests/opsec \
  --repo=. \
  --binaries=/tmp/gateway-proxy,/tmp/gateway-torpool,/tmp/gateway-hub \
  --banned=./tests/opsec/banned_strings.txt

# machine-readable output
go run ./tests/opsec --json --repo=. --banned=./tests/opsec/banned_strings.txt
```

On a typical laptop this completes in under a second on this repo.

## Adding a banned string

Edit `tests/opsec/banned_strings.txt`. Rules:

- one substring per line
- blank lines and lines starting with `#` are ignored
- matching is case-insensitive, so add the term in any case
- keep a short comment above each entry explaining *why* it is banned
  (project codename, contributor handle, analytics host, ...)

Example:

```
# Internal codename of the staging host -- do not ship.
crimson-otter

# Personal handle of a contributor, per their request.
@somehandle
```

## Adding an exception

Sometimes a banned substring legitimately appears inside a file (for
instance, a test fixture that asserts the linter *catches* the word).
Today the linter has two kinds of built-in exceptions:

- the banned-list file itself is always skipped
- files under `.git/`, `node_modules/`, `vendor/`, and common media
  extensions are skipped

If you need a narrower carve-out, the current recommendation is to move
the legitimate occurrence inside a skipped directory (for example,
`tests/opsec/testdata/`), or to rename the token so the substring no
longer appears. A first-class per-path allowlist can be added later as
a `# allow: <path>` directive in the banned-list file; until then,
please coordinate any exception through code review.

## Pre-commit hook (optional)

To run the linter before every commit, drop this into
`.git/hooks/pre-commit` (and `chmod +x` it):

```sh
#!/bin/sh
set -e
cd "$(git rev-parse --show-toplevel)/gateway"
go run ./tests/opsec --repo=. --banned=./tests/opsec/banned_strings.txt
```

CI already runs the same command in `.github/workflows/opsec.yml`, so
the hook is redundant for remote enforcement -- it just saves a round
trip when the check would otherwise fail.

## Testing

```sh
go test ./tests/opsec/... -race -count=1
```

The test suite covers: comment/blank-line handling in the banned list,
repo scanning, case-insensitive matching, skip-list behaviour, binary
scanning (builds a tiny Go program with a literal and confirms the
linter finds it), exit codes, JSON output, and the `go.mod replace`
warning path.
