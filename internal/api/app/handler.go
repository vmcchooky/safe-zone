package app

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const MountPath = "/app"

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
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
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
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, staticFS, "index.html")
}

func serveFile(fileServer http.Handler, w http.ResponseWriter, r *http.Request, name string) {
	cloned := r.Clone(r.Context())
	clonedURL := *r.URL
	cloned.URL = &clonedURL
	cloned.URL.Path = "/" + strings.TrimPrefix(name, "/")
	fileServer.ServeHTTP(w, cloned)
}
