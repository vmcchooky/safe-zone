package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
)

type policyResponse struct {
	Service string `json:"service"`
	risk.Policy
	Meta map[string]string `json:"meta,omitempty"`
}

type app struct {
	risk           *risk.Service
	metrics        *observability.Registry
	deploymentTier string
	upstreamDoHURL string
	upstreamClient *http.Client
	blockPageIP    string
	blockStrategy  string
	dnsTTL         uint32
	dotLimiter     *ratelimit.Limiter
}

const (
	blockStrategySinkhole = "sinkhole"
	blockStrategyNXDomain = "nxdomain"
	blockStrategyRefused  = "refused"
	blockStrategyNullIP   = "nullip"
)

func main() {
	addr := config.String("SAFE_ZONE_DNS_RESOLVER_ADDR", ":8081")
	shutdownTimeout := config.DurationMillis("SAFE_ZONE_SHUTDOWN_TIMEOUT_MS", 10*time.Second)

	ttlVal := config.Int("SAFE_ZONE_DNS_BLOCK_TTL_SECONDS", 60)
	if ttlVal < 0 || ttlVal > 86400 {
		logjson.Error("SAFE_ZONE_DNS_BLOCK_TTL_SECONDS out of valid range", map[string]any{
			"service": "dns-resolver",
			"value":   ttlVal,
		})
		os.Exit(1)
	}

	blockStrategy := strings.ToLower(strings.TrimSpace(config.String("SAFE_ZONE_DNS_BLOCK_STRATEGY", blockStrategySinkhole)))
	if !validBlockStrategy(blockStrategy) {
		logjson.Error("invalid SAFE_ZONE_DNS_BLOCK_STRATEGY", map[string]any{
			"service": "dns-resolver",
			"value":   blockStrategy,
			"allowed": []string{blockStrategySinkhole, blockStrategyNXDomain, blockStrategyRefused, blockStrategyNullIP},
		})
		os.Exit(1)
	}

	resolver := &app{
		risk:           risk.NewServiceFromEnv(),
		metrics:        observability.NewRegistry(),
		deploymentTier: config.String("SAFE_ZONE_DEPLOYMENT_TIER", "budget-vps"),
		upstreamDoHURL: config.String("SAFE_ZONE_UPSTREAM_DOH_URL", "https://cloudflare-dns.com/dns-query"),
		upstreamClient: &http.Client{Timeout: config.DurationMillis("SAFE_ZONE_UPSTREAM_DOH_TIMEOUT_MS", 3*time.Second)},
		blockPageIP:    config.String("SAFE_ZONE_BLOCK_PAGE_IP", "127.0.0.1"),
		blockStrategy:  blockStrategy,
		dnsTTL:         uint32(ttlVal), // #nosec G115 -- bounds validated above
	}
	defer func() {
		if err := resolver.risk.Close(); err != nil {
			logjson.Warn("risk service close failed", map[string]any{
				"service": "dns-resolver",
				"error":   err.Error(),
			})
		}
	}()
	logCacheStatus("dns-resolver", resolver.risk)

	// --- Rate limiting ---
	rlEnabled := config.Bool("SAFE_ZONE_RATELIMIT_ENABLED", true)
	var tiered *ratelimit.TieredMiddleware
	if rlEnabled {
		dohLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DOH_RPM", 100), config.Int("SAFE_ZONE_RATELIMIT_DOH_BURST", 20))
		defaultLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", 15))
		dotLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DOT_RPM", 100), config.Int("SAFE_ZONE_RATELIMIT_DOT_BURST", 20))

		defer dohLimiter.Close()
		defer defaultLimiter.Close()
		defer dotLimiter.Close()

		resolver.dotLimiter = dotLimiter

		tiered = ratelimit.NewTieredMiddleware(
			defaultLimiter,
			ratelimit.Tier{PathPrefix: "/dns-query", Limiter: dohLimiter},
		)
		logjson.Info("rate limiting enabled", map[string]any{
			"service":     "dns-resolver",
			"doh_rpm":     config.Float64("SAFE_ZONE_RATELIMIT_DOH_RPM", 100),
			"dot_rpm":     config.Float64("SAFE_ZONE_RATELIMIT_DOT_RPM", 100),
			"default_rpm": config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60),
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", resolver.statusHandler)
	mux.HandleFunc("/healthz", healthHandler("dns-resolver"))
	mux.HandleFunc("/metrics", resolver.metricsHandler)
	mux.HandleFunc("/v1/policy", resolver.policyHandler)
	mux.HandleFunc("/dns-query", resolver.dohHandler)
	mux.HandleFunc("/dns-query/", resolver.dohHandler)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, resolver.metrics)
	requestIDHandler := serve.WithRequestID(logRequests("dns-resolver", recoveryHandler, resolver.metrics))

	server := &http.Server{
		Addr:              addr,
		Handler:           requestIDHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// --- DNS-over-TLS (DoT) Server ---
	dotEnabled := config.Bool("SAFE_ZONE_DNS_DOT_ENABLED", true)
	var dotServer *dns.Server

	if dotEnabled {
		dotAddr := config.String("SAFE_ZONE_DNS_DOT_ADDR", ":8533")
		certFile := config.String("SAFE_ZONE_DNS_DOT_CERT_FILE", "")
		keyFile := config.String("SAFE_ZONE_DNS_DOT_KEY_FILE", "")

		var cert tls.Certificate
		var certErr error
		if certFile != "" || keyFile != "" {
			cert, certErr = tls.LoadX509KeyPair(certFile, keyFile)
			if certErr != nil {
				logjson.Error("failed to load configured TLS keys", map[string]any{
					"service":   "dns-resolver",
					"cert_file": certFile,
					"key_file":  keyFile,
					"error":     certErr.Error(),
				})
				os.Exit(1)
			}
		} else {
			logjson.Warn("TLS key files not configured; generating temporary self-signed cert", map[string]any{
				"service": "dns-resolver",
			})
			cert, certErr = generateSelfSignedCert()
			if certErr != nil {
				logjson.Error("failed to generate self-signed cert", map[string]any{
					"service": "dns-resolver",
					"error":   certErr.Error(),
				})
				os.Exit(1)
			}
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		dotServer = &dns.Server{
			Addr:         dotAddr,
			Net:          "tcp-tls",
			TLSConfig:    tlsConfig,
			Handler:      dns.HandlerFunc(resolver.dotHandler),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
	}

	// Channel to catch server run errors and OS signals
	errCh := make(chan error, 2)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Run HTTP DoH Server
	go func() {
		logjson.Info("service listening", map[string]any{
			"service": "dns-resolver",
			"mode":    "doh",
			"addr":    addr,
		})
		if err := serve.RunHTTPServer(server, shutdownTimeout); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("DoH server error: %w", err)
		} else {
			errCh <- nil
		}
	}()

	// Run DoT Server
	if dotServer != nil {
		go func() {
			logjson.Info("service listening", map[string]any{
				"service": "dns-resolver",
				"mode":    "dot",
				"addr":    dotServer.Addr,
			})
			if err := dotServer.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
				errCh <- fmt.Errorf("DoT server error: %w", err)
			} else {
				errCh <- nil
			}
		}()
	}

	// Wait for OS signals or server errors
	select {
	case sig := <-sigCh:
		logjson.Info("shutdown requested", map[string]any{
			"service": "dns-resolver",
			"signal":  sig.String(),
		})
	case err := <-errCh:
		if err != nil {
			logjson.Error("server error", map[string]any{
				"service": "dns-resolver",
				"error":   err.Error(),
			})
		}
	}

	// Graceful Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	logjson.Info("stopping HTTP (DoH) server", map[string]any{"service": "dns-resolver"})
	if err := server.Shutdown(ctx); err != nil {
		logjson.Warn("HTTP server shutdown error", map[string]any{
			"service": "dns-resolver",
			"error":   err.Error(),
		})
	}

	if dotServer != nil {
		logjson.Info("stopping DNS-over-TLS (DoT) server", map[string]any{"service": "dns-resolver"})
		if err := dotServer.ShutdownContext(ctx); err != nil {
			logjson.Warn("DoT server shutdown error", map[string]any{
				"service": "dns-resolver",
				"error":   err.Error(),
			})
		}
	}

	logjson.Info("all services stopped gracefully", map[string]any{"service": "dns-resolver"})
}

func healthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"status":  "ok",
			"time":    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func validBlockStrategy(strategy string) bool {
	switch strategy {
	case blockStrategySinkhole, blockStrategyNXDomain, blockStrategyRefused, blockStrategyNullIP:
		return true
	default:
		return false
	}
}

func (a *app) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":         "dns-resolver",
		"status":          "ok",
		"mode":            "doh",
		"deployment_tier": a.deploymentTier,
		"upstream_doh":    a.upstreamDoHURL,
		"redis":           a.risk.CacheStatus(r.Context()),
		"endpoints": []string{
			"/",
			"/healthz",
			"/v1/policy?domain=example.com",
			"/dns-query",
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": "dns-resolver",
		"status":  "ok",
		"metrics": a.metrics.Snapshot(),
		"upstream_doh": map[string]any{
			"failures_total": dohFailureCount(a.metrics),
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) policyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	domain := r.URL.Query().Get("domain")
	clientInfo := extractClientInfo(r)
	policy := a.risk.Policy(r.Context(), domain, clientInfo)

	writeJSON(w, http.StatusOK, policyResponse{
		Service: "dns-resolver",
		Policy:  policy,
		Meta: map[string]string{
			"mode":         "doh",
			"upstream_doh": a.upstreamDoHURL,
		},
	})
}

func (a *app) dohHandler(w http.ResponseWriter, r *http.Request) {
	wire, err := readDNSMessage(w, r)
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
	clientInfo := extractClientInfo(r)
	policy := a.risk.Policy(r.Context(), questionDomain, clientInfo)
	if policy.Policy == "block" {
		response, err := a.blockedDNSResponse(query)
		if err != nil {
			http.Error(w, "could not build blocked DNS response", http.StatusInternalServerError)
			return
		}
		writeDNSMessage(w, response)
		return
	}

	response, err := a.forwardDoH(r.Context(), wire)
	if err != nil {
		if a.metrics != nil {
			a.metrics.IncCounter("upstream_doh_failures_total")
		}
		logjson.Warn("upstream DoH failed", correlation.Fields(r.Context(), map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
			"mode":    "doh",
		}))
		servfail, packErr := servfailDNSResponse(query)
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

func (a *app) forwardDoH(ctx context.Context, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.upstreamDoHURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := a.upstreamClient.Do(req) // #nosec G704 -- URL is from trusted server config (SAFE_ZONE_UPSTREAM_DOH_URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (a *app) blockedDNSResponse(query *dns.Msg) ([]byte, error) {
	response, err := a.blockedDNSMessage(query)
	if err != nil {
		return nil, err
	}
	return response.Pack()
}

func servfailDNSResponse(query *dns.Msg) ([]byte, error) {
	response := new(dns.Msg)
	response.SetRcode(query, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	return response.Pack()
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

func logCacheStatus(service string, riskService *risk.Service) {
	status := riskService.CacheStatus(context.Background())
	if !status.Configured {
		return
	}
	if status.Status == "ok" {
		logjson.Info("redis cache connected", map[string]any{"service": service})
		return
	}
	logjson.Warn("redis cache unavailable at startup", map[string]any{
		"service": service,
		"error":   status.Error,
	})
}

func logRequests(service string, next http.Handler, metrics *observability.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panicObserved := false
		ctx := context.WithValue(r.Context(), serve.ObservedPanicKey, &panicObserved)
		r = r.WithContext(ctx)
		started := time.Now()
		recorder := &statusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if metrics != nil {
			if p, ok := r.Context().Value(serve.ObservedPanicKey).(*bool); !ok || !*p {
				metrics.Observe(r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started))
			}
		}
		clientInfo := extractClientInfo(r)
		logjson.Info("http request", map[string]any{
			"service":     service,
			"request_id":  serve.RequestID(r.Context()),
			"method":      sanitizeLog(r.Method),
			"path":        sanitizeLog(r.URL.Path),
			"status":      recorder.statusCode,
			"bytes":       recorder.bytesWritten,
			"duration_ms": time.Since(started).Milliseconds(),
			"client_ip":   clientInfo.IP,
			"client_id":   clientInfo.ClientID,
		})
	})
}

type statusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *statusLoggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusLoggingResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logjson.Error("write response failed", map[string]any{
			"service": "dns-resolver",
			"error":   err.Error(),
		})
	}
}

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func extractClientInfo(r *http.Request) risk.ClientInfo {
	ip := ""
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}
	if ip == "" {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ip = strings.TrimSpace(xri)
		}
	}
	if ip == "" {
		remoteAddr := r.RemoteAddr
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			ip = remoteAddr[:idx]
		} else {
			ip = remoteAddr
		}
		ip = strings.Trim(ip, "[]")
	}

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

// generateSelfSignedCert sinh chứng chỉ SSL tự ký 2048-bit RSA trực tiếp trên RAM làm fallback
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Safe Zone Security"},
			CommonName:   "safezone.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// dotHandler xử lý các truy vấn DNS-over-TLS bảo mật trực tiếp trên giao thức TCP TLS
func (a *app) dotHandler(w dns.ResponseWriter, r *dns.Msg) {
	ctx := correlation.WithRunID(context.Background(), correlation.NewID("dot"))

	// Panic Recovery để bảo vệ máy chủ khỏi bị sập
	defer func() {
		if rec := recover(); rec != nil {
			logjson.Error("panic recovered in DoT handler", correlation.Fields(ctx, map[string]any{
				"service": "dns-resolver",
				"panic":   fmt.Sprint(rec),
				"mode":    "dot",
			}))
			sendServfail(w, r)
		}
	}()

	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		clientIP = w.RemoteAddr().String()
	}
	clientIP = strings.Trim(clientIP, "[]") // Chuẩn hóa IPv6

	// Rate Limiting Check
	if a.dotLimiter != nil && !a.dotLimiter.Allow(clientIP) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(resp)
		return
	}

	if len(r.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	questionDomain := strings.TrimSuffix(r.Question[0].Name, ".")
	clientInfo := risk.ClientInfo{IP: clientIP}

	// Tạo context có giới hạn thời gian (Timeout) để ngăn chặn rò rỉ goroutine
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	policy := a.risk.Policy(requestCtx, questionDomain, clientInfo)

	if policy.Policy == "block" {
		responseMsg, err := a.blockedDNSMessage(r)
		if err == nil {
			_ = w.WriteMsg(responseMsg)
			return
		}
	}

	// Forward allowed query to upstream via DoH
	wire, err := r.Pack()
	if err != nil {
		sendServfail(w, r)
		return
	}

	responseWire, err := a.forwardDoH(requestCtx, wire)
	if err != nil {
		if a.metrics != nil {
			a.metrics.IncCounter("upstream_doh_failures_total")
		}
		logjson.Warn("upstream DoH failed", correlation.Fields(requestCtx, map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
			"mode":    "dot",
		}))
		sendServfail(w, r)
		return
	}

	responseMsg := new(dns.Msg)
	if err := responseMsg.Unpack(responseWire); err != nil {
		sendServfail(w, r)
		return
	}

	_ = w.WriteMsg(responseMsg)
}

// blockedDNSMessage tạo message block cụ thể cho DoT trả về theo strategy đã cấu hình.
func (a *app) blockedDNSMessage(query *dns.Msg) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true

	switch a.effectiveBlockStrategy() {
	case blockStrategyNXDomain:
		response.Rcode = dns.RcodeNameError
		return response, nil
	case blockStrategyRefused:
		response.Rcode = dns.RcodeRefused
		return response, nil
	}

	for _, question := range query.Question {
		switch question.Qtype {
		case dns.TypeA:
			ip := a.blockIPv4()
			if ip == nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: a.dnsTTL},
				A:   ip,
			})
		case dns.TypeAAAA:
			ip := a.blockIPv6()
			if ip == nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: question.Qclass, Ttl: a.dnsTTL},
				AAAA: ip,
			})
		}
	}

	return response, nil
}

func (a *app) effectiveBlockStrategy() string {
	if a.blockStrategy == "" {
		return blockStrategySinkhole
	}
	return a.blockStrategy
}

func (a *app) blockIPv4() net.IP {
	if a.effectiveBlockStrategy() == blockStrategyNullIP {
		return net.IPv4(0, 0, 0, 0)
	}
	return net.ParseIP(a.blockPageIP).To4()
}

func (a *app) blockIPv6() net.IP {
	if a.effectiveBlockStrategy() == blockStrategyNullIP {
		return net.IPv6zero
	}
	return net.ParseIP(a.blockPageIP).To16()
}

// sendServfail gửi phản hồi lỗi DNS ServFail (Server Failure) an toàn cho DoT client
func sendServfail(w dns.ResponseWriter, r *dns.Msg) {
	response := new(dns.Msg)
	response.SetRcode(r, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	_ = w.WriteMsg(response)
}

func dohFailureCount(metrics *observability.Registry) int64 {
	if metrics == nil {
		return 0
	}
	return metrics.Snapshot().Counters["upstream_doh_failures_total"]
}
