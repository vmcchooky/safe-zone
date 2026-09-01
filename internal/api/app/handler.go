package app

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const (
	MountPath            = "/app"
	legacyDashboardPath  = "/dashboard"
	legacyBackgroundPath = "/app-background.avif"
)

// RedirectPublicRoot sends browser requests for the service root to the
// primary React UI. The API status document remains available at /v1/status.
func RedirectPublicRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := MountPath + "/"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// #nosec G710 -- target always starts with the fixed relative /app/ path; the query cannot change its origin.
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

// RedirectRoot canonicalizes the mount root so relative asset resolution stays stable.
func RedirectRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != MountPath {
		http.NotFound(w, r)
		return
	}

	target := MountPath + "/"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// #nosec G710 -- target always starts with the fixed relative /app/ path; the query cannot change its origin.
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

// RedirectLegacyDashboard keeps existing dashboard bookmarks on the React UI.
func RedirectLegacyDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != legacyDashboardPath && !strings.HasPrefix(r.URL.Path, legacyDashboardPath+"/") {
		http.NotFound(w, r)
		return
	}

	target := MountPath + "/"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// #nosec G710 -- target always starts with the fixed relative /app/ path; the query cannot change its origin.
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

// RedirectLegacyBackground keeps clients from an older UI build working after
// the application moved its public assets under /app/.
func RedirectLegacyBackground(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != legacyBackgroundPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := MountPath + legacyBackgroundPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// #nosec G710 -- target always starts with the fixed relative /app/ path; the query cannot change its origin.
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func RedirectFavicon(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/favicon.ico" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.Redirect(w, r, MountPath+"/favicon.svg", http.StatusPermanentRedirect)
}

func Robots(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/robots.txt" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// NewHandler serves the embedded SPA bundle and falls back to index.html for client-side routes.
func NewHandler(staticFS fs.FS) http.Handler {
	if staticFS == nil {
		return http.NotFoundHandler()
	}

	fileServer := http.FileServer(http.FS(staticFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		resolvedPath := resolvePath(r.URL.Path)
		if resolvedPath == "" {
			serveIndex(staticFS, w, r)
			return
		}

		if isEmbeddedFile(staticFS, resolvedPath) {
			serveFile(fileServer, w, r, resolvedPath)
			return
		}

		if isStaticAssetRequest(resolvedPath) {
			http.NotFound(w, r)
			return
		}

		serveIndex(staticFS, w, r)
	})
}

func resolvePath(requestPath string) string {
	trimmed := strings.TrimPrefix(requestPath, MountPath)
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return ""
	}

	cleaned := path.Clean("/" + trimmed)
	if cleaned == "/" || cleaned == "." {
		return ""
	}
	return strings.TrimPrefix(cleaned, "/")
}

func isEmbeddedFile(staticFS fs.FS, name string) bool {
	info, err := fs.Stat(staticFS, name)
	return err == nil && !info.IsDir()
}

func isStaticAssetRequest(name string) bool {
	return name == "assets" || strings.HasPrefix(name, "assets/") || path.Ext(name) != ""
}

func serveIndex(staticFS fs.FS, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	http.ServeFileFS(w, r, staticFS, "index.html")
}

func serveFile(fileServer http.Handler, w http.ResponseWriter, r *http.Request, name string) {
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	cloned := r.Clone(r.Context())
	clonedURL := *r.URL
	cloned.URL = &clonedURL
	cloned.URL.Path = "/" + strings.TrimPrefix(name, "/")
	fileServer.ServeHTTP(w, cloned)
}
