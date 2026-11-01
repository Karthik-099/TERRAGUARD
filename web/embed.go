// Package web embeds the site; run make web first so the WASM is included.
package web

import "embed"

//go:embed all:*
var FS embed.FS
