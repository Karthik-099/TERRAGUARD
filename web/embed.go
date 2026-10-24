// Package web embeds the static site so `terraguard serve` is a single
// self-hosted binary. Run `make web` first so terraguard.wasm is included.
package web

import "embed"

//go:embed all:*
var FS embed.FS
