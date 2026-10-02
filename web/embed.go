// Package web embeds the built frontend (web/dist). Build it with
// `npm run build` inside web/; the Go binary serves it at / with an SPA
// fallback. If dist contains only the .gitkeep placeholder (a fresh clone
// without a frontend build), the binary serves the API only.
package web

import "embed"

// Dist is the built single-page application.
//
//go:embed dist
var Dist embed.FS
