package serve

import "net/http"

// DotLottie uses a locally generated Blob worker and compiles the bundled WASM
// renderer. The policy allows only that same-origin asset flow; it does not
// grant remote scripts, inline scripts, or unsafe eval.
//
// style-src carries 'unsafe-inline' because the operator UI sets element
// styles through React style attributes and one inline <style> block. That
// exception is scoped to styles only: script-src stays 'self' without
// 'unsafe-inline' and 'unsafe-eval', so a style injection cannot execute
// code. The alternative — moving every inline style into a class — was
// rejected because it touches five large UI files and the end-to-end suite
// runs against the Vite dev server, which does not apply the policy, so the
// regression would not have been caught before release.
const contentSecurityPolicy = "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'"

// SecurityHeaders applies a baseline set of browser security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		headers.Set("Content-Security-Policy", contentSecurityPolicy)
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}
