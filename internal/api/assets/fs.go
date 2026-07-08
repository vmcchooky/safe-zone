package assets

import (
	"embed"
	"strings"

	"safe-zone/internal/buildinfo"
)

const RevisionPlaceholder = "__SAFE_ZONE_ASSET_REV__"

// FS exposes the browser-facing CSS, JS, and font assets served by core-api.
//
//go:embed *.css *.js *.woff2
var FS embed.FS

func Revision() string {
	rev := strings.TrimSpace(buildinfo.GitCommit)
	if rev == "" || rev == "unknown" {
		rev = strings.TrimSpace(buildinfo.Version)
	}
	if rev == "" {
		rev = "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev
}

func ReplaceRevisionPlaceholders(content string) string {
	return strings.ReplaceAll(content, RevisionPlaceholder, Revision())
}
