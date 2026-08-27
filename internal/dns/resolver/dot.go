package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"safe-zone/internal/correlation"
	"safe-zone/internal/dns/doh"
	"safe-zone/internal/logjson"
)

// DoTHandler xử lý các truy vấn DNS-over-TLS (RFC 7858) bảo mật trực tiếp
// trên giao thức TCP TLS. Policy, chặn và forward đều được ủy quyền cho
// pipeline ResolveQuery dùng chung với transport DoH.
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

	// Tạo context có giới hạn thời gian (Timeout) để ngăn chặn rò rỉ goroutine
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	responseMsg, err := r.ResolveQuery(requestCtx, req, doh.ClientInfo{IP: clientIP})
	if err != nil {
		SendServfail(w, req)
		return
	}

	_ = w.WriteMsg(responseMsg)
}
