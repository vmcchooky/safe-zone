// Package doh implements the DNS-over-HTTPS protocol defined in RFC 8484.
//
// It is split into three independent concerns:
//
//   - server.go: the RFC 8484 HTTP endpoint (GET with the "dns" query
//     parameter and POST with "application/dns-message"), including the
//     HTTP status code mapping and Cache-Control freshness lifetime rules
//     of section 5.1.
//   - client.go: the upstream DoH client used to forward DNS messages to
//     a recursive resolver.
//   - upstream.go: the health-checked upstream endpoint pool with failover.
//   - cache.go: the Cache-Control freshness lifetime rules of RFC 8484
//     section 5.1 combined with RFC 2308 negative caching.
//
// The package is transport-only: it never decides DNS policy itself. Query
// policy (block lists, CNAME uncloaking) is delegated to the QueryBackend
// implemented by internal/dns/resolver, which keeps DoH interchangeable
// with other encrypted-DNS transports such as DoT.
package doh

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"safe-zone/internal/logjson"
	"safe-zone/internal/ratelimit"
)

const (
	// ContentTypeDNSMessage is the only media type defined by RFC 8484.
	ContentTypeDNSMessage = "application/dns-message"

	// MaxDNSMessageSize is the maximum DNS message size allowed by
	// RFC 8484 section 6.
	MaxDNSMessageSize = 65535
)

// ClientInfo carries the transport-derived caller identity used for
// per-client policy decisions. It is populated by the DoH endpoint from
// proxy headers and the /dns-query/{client_id} path convention.
type ClientInfo struct {
	IP       string
	ClientID string
}

// QueryBackend resolves a decoded DNS query into a complete DNS response.
// Implementations (the resolver policy engine) own the block decision,
// upstream forwarding and CNAME uncloaking; returning a non-nil error
// makes the DoH endpoint answer with a SERVFAIL DNS message inside HTTP 200
// as required by RFC 8484 section 4.2.1.
type QueryBackend interface {
	ResolveQuery(ctx context.Context, query *dns.Msg, client ClientInfo) (*dns.Msg, error)
}

// Handler is the RFC 8484 HTTP endpoint. It satisfies http.Handler and can
// be mounted on both /dns-query and /dns-query/ (client_id subpaths).
type Handler struct {
	backend QueryBackend
}

// NewHandler builds a DoH endpoint on top of the given query backend.
func NewHandler(backend QueryBackend) *Handler {
	return &Handler{backend: backend}
}

// ServeHTTP implements the DoH server protocol for one HTTP exchange.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	wire, err := readRequestMessage(w, req)
	if err != nil {
		writeProtoError(w, err)
		return
	}

	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		writeProtoError(w, protoError{http.StatusBadRequest, "invalid DNS message"})
		return
	}
	if len(query.Question) == 0 {
		writeProtoError(w, protoError{http.StatusBadRequest, "DNS message has no question"})
		return
	}

	response, err := h.backend.ResolveQuery(req.Context(), query, extractClientInfo(req))
	if err != nil {
		servfail := new(dns.Msg)
		servfail.SetRcode(query, dns.RcodeServerFailure)
		servfail.RecursionAvailable = true
		writeDNSResponse(w, servfail)
		return
	}

	writeDNSResponse(w, response)
}

// requestError couples an HTTP status code with a plain-text reason for
// non-2xx responses, which per RFC 8484 section 4.2.1 never carry a DNS
// reply to the original question.
type protoError struct {
	status int
	reason string
}

func (e protoError) Error() string { return e.reason }

func writeProtoError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	reason := err.Error()
	var perr protoError
	if errors.As(err, &perr) {
		status = perr.status
		reason = perr.reason
	}
	if status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", "GET, POST")
	}
	http.Error(w, reason, status)
}

// readRequestMessage extracts the raw DNS wire message from an RFC 8484
// HTTP request: GET with the base64url "dns" parameter (no padding
// characters allowed) or POST with an "application/dns-message" body.
func readRequestMessage(w http.ResponseWriter, req *http.Request) ([]byte, error) {
	switch req.Method {
	case http.MethodGet:
		encoded := req.URL.Query().Get("dns")
		if encoded == "" {
			return nil, protoError{http.StatusBadRequest, "missing dns query parameter"}
		}
		wire, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, protoError{http.StatusBadRequest, "malformed base64url dns parameter"}
		}
		if len(wire) == 0 || len(wire) > MaxDNSMessageSize {
			return nil, protoError{http.StatusBadRequest, "dns message out of size bounds"}
		}
		return wire, nil
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || mediaType != ContentTypeDNSMessage {
			return nil, protoError{http.StatusUnsupportedMediaType, "Content-Type must be application/dns-message"}
		}
		wire, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxDNSMessageSize))
		if err != nil {
			var maxBytes *http.MaxBytesError
			if errors.As(err, &maxBytes) {
				return nil, protoError{http.StatusRequestEntityTooLarge, "DNS message exceeds 65535 bytes"}
			}
			return nil, protoError{http.StatusBadRequest, "could not read request body"}
		}
		if len(wire) == 0 {
			return nil, protoError{http.StatusBadRequest, "empty request body"}
		}
		return wire, nil
	default:
		return nil, protoError{http.StatusMethodNotAllowed, "method not allowed"}
	}
}

// extractClientInfo derives caller identity for the policy engine: the
// client IP (proxy-aware via internal/ratelimit) plus the optional
// client_id taken from the query string or the /dns-query/{client_id} path.
func extractClientInfo(req *http.Request) ClientInfo {
	clientID := req.URL.Query().Get("client_id")
	if clientID == "" {
		segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(segments) >= 2 && segments[0] == "dns-query" {
			clientID = segments[1]
		}
	}
	return ClientInfo{IP: ratelimit.ClientIP(req), ClientID: clientID}
}

// writeDNSResponse packs and sends a valid DNS response inside HTTP 200.
// Per RFC 8484 section 5.1 the response carries an explicit freshness
// lifetime capped by the smallest TTL in the Answer section (or the SOA
// minimum for negative answers), and is marked private because block
// decisions are customized per client identity.
func writeDNSResponse(w http.ResponseWriter, response *dns.Msg) {
	wire, err := response.Pack()
	if err != nil {
		http.Error(w, "could not pack DNS response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentTypeDNSMessage)
	w.Header().Set("Cache-Control", "private, max-age="+strconv.FormatUint(uint64(CacheFreshnessLifetime(response)), 10))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wire); err != nil { // #nosec G705 -- DNS wire format binary, not HTML
		logjson.Warn("write DNS response failed", map[string]any{
			"service": "dns-resolver",
			"error":   err.Error(),
		})
	}
}
