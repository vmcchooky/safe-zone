package resolver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"safe-zone/internal/api/httputil"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/risk"
)

func (r *Resolver) DoHHandler(w http.ResponseWriter, req *http.Request) {
	wire, err := readDNSMessage(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}
	if len(query.Question) == 0 {
		http.Error(w, "DNS message has no question", http.StatusBadRequest)
		return
	}

	questionDomain := strings.TrimSuffix(query.Question[0].Name, ".")
	clientInfo := httputil.ExtractClientInfo(req)
	policy := r.Risk.Policy(req.Context(), questionDomain, clientInfo)
	if policy.Policy == "block" {
		response, err := r.BlockedDNSMessage(query)
		if err != nil {
			http.Error(w, "could not build blocked DNS response", http.StatusInternalServerError)
			return
		}
		wire, _ = response.Pack()
		writeDNSMessage(w, wire)
		return
	}

	response, err := r.ForwardDoH(req.Context(), wire)
	if err != nil {
		if r.Metrics != nil {
			r.Metrics.IncCounter("upstream_doh_failures_total")
		}
		logjson.Warn("upstream DoH failed", correlation.Fields(req.Context(), map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
			"mode":    "doh",
		}))
		servfail, packErr := ServfailDNSResponse(query)
		if packErr != nil {
			http.Error(w, "upstream DoH failed", http.StatusBadGateway)
			return
		}
		writeDNSMessage(w, servfail)
		return
	}

	writeDNSMessage(w, response)
}

func readDNSMessage(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, errors.New("missing dns query parameter")
		}
		return base64.RawURLEncoding.DecodeString(encoded)
	case http.MethodPost:
		defer r.Body.Close()
		return io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
	default:
		return nil, errors.New("method not allowed")
	}
}

func writeDNSMessage(w http.ResponseWriter, wire []byte) {
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wire); err != nil { // #nosec G705 -- DNS wire format binary, not HTML
		logjson.Warn("write DNS response failed", map[string]any{
			"service": "dns-resolver",
			"error":   err.Error(),
		})
	}
}

// DoTHandler xử lý các truy vấn DNS-over-TLS bảo mật trực tiếp trên giao thức TCP TLS
func (r *Resolver) DoTHandler(w dns.ResponseWriter, req *dns.Msg) {
	ctx := correlation.WithRunID(context.Background(), correlation.NewID("dot"))

	// Panic Recovery để bảo vệ máy chủ khỏi bị sập
	defer func() {
		if rec := recover(); rec != nil {
			logjson.Error("panic recovered in DoT handler", correlation.Fields(ctx, map[string]any{
				"service": "dns-resolver",
				"panic":   fmt.Sprint(rec),
				"mode":    "dot",
			}))
			SendServfail(w, req)
		}
	}()

	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		clientIP = w.RemoteAddr().String()
	}
	clientIP = strings.Trim(clientIP, "[]") // Chuẩn hóa IPv6

	// Rate Limiting Check
	if r.DotLimiter != nil && !r.DotLimiter.Allow(clientIP) {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(resp)
		return
	}

	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	questionDomain := strings.TrimSuffix(req.Question[0].Name, ".")
	clientInfo := risk.ClientInfo{IP: clientIP}

	// Tạo context có giới hạn thời gian (Timeout) để ngăn chặn rò rỉ goroutine
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	policy := r.Risk.Policy(requestCtx, questionDomain, clientInfo)

	if policy.Policy == "block" {
		responseMsg, err := r.BlockedDNSMessage(req)
		if err == nil {
			_ = w.WriteMsg(responseMsg)
			return
		}
	}

	// Forward allowed query to upstream via DoH
	wire, err := req.Pack()
	if err != nil {
		SendServfail(w, req)
		return
	}

	responseWire, err := r.ForwardDoH(requestCtx, wire)
	if err != nil {
		if r.Metrics != nil {
			r.Metrics.IncCounter("upstream_doh_failures_total")
		}
		logjson.Warn("upstream DoH failed", correlation.Fields(requestCtx, map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
			"mode":    "dot",
		}))
		SendServfail(w, req)
		return
	}

	responseMsg := new(dns.Msg)
	if err := responseMsg.Unpack(responseWire); err != nil {
		SendServfail(w, req)
		return
	}

	_ = w.WriteMsg(responseMsg)
}
