package admin

import "embed"

// UIFS is the embedded admin UI filesystem. P3 ships only a minimal
// "admin ready" index.html so the mount point is exercised in tests
// and the binary's import surface is fixed; P4 populates the full UI.
//
// Callers that need a sub-FS rooted at "ui" can do `fs.Sub(UIFS, "ui")`.
//
//go:embed ui
var UIFS embed.FS
