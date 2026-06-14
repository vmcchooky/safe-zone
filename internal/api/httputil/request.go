package httputil

import (
	"net/http"
	"strings"

	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
)

func ExtractClientInfo(r *http.Request) risk.ClientInfo {
	ip := ratelimit.ClientIP(r)

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		path := r.URL.Path
		path = strings.Trim(path, "/")
		parts := strings.Split(path, "/")
		if len(parts) >= 2 && parts[0] == "dns-query" {
			clientID = parts[1]
		} else if len(parts) == 1 && parts[0] != "" && parts[0] != "dns-query" {
			clientID = parts[0]
		}
	}

	return risk.ClientInfo{
		IP:       ip,
		ClientID: clientID,
	}
}

func SanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
