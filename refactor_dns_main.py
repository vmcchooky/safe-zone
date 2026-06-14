import os
import re

main_path = "cmd/dns-resolver/main.go"
with open(main_path, "r", encoding="utf-8") as f:
    content = f.read()

# We need to replace everything from `type policyResponse struct {` up to `func main() {`
# And then replace inside `func main() {` to initialize the resolver correctly.

new_content = """package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/config"
	"safe-zone/internal/dns/resolver"
	"safe-zone/internal/dns/server"
	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
	"safe-zone/internal/serve"
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

	blockStrategy := strings.ToLower(strings.TrimSpace(config.String("SAFE_ZONE_DNS_BLOCK_STRATEGY", resolver.BlockStrategySinkhole)))
	if blockStrategy != resolver.BlockStrategySinkhole && blockStrategy != resolver.BlockStrategyNXDomain && blockStrategy != resolver.BlockStrategyRefused && blockStrategy != resolver.BlockStrategyNullIP {
		logjson.Error("invalid SAFE_ZONE_DNS_BLOCK_STRATEGY", map[string]any{
			"service": "dns-resolver",
			"value":   blockStrategy,
			"allowed": []string{resolver.BlockStrategySinkhole, resolver.BlockStrategyNXDomain, resolver.BlockStrategyRefused, resolver.BlockStrategyNullIP},
		})
		os.Exit(1)
	}

	upstreamClient := &http.Client{
		Timeout: config.DurationMillis("SAFE_ZONE_UPSTREAM_DOH_TIMEOUT_MS", 3*time.Second),
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
	upstreamURLs := config.String("SAFE_ZONE_UPSTREAM_DOH_URLS",
		config.String("SAFE_ZONE_UPSTREAM_DOH_URL", "https://cloudflare-dns.com/dns-query"))
	upstreams := resolver.NewUpstreamResolver(upstreamURLs, upstreamClient)
	probeInterval := config.DurationMillis("SAFE_ZONE_UPSTREAM_DOH_PROBE_INTERVAL_MS", 30*time.Second)
	probeCtx, stopProbes := context.WithCancel(context.Background())
	defer stopProbes()
	if probeInterval > 0 {
		go upstreams.ProbeLoop(probeCtx, probeInterval)
	}

	riskService := risk.NewServiceFromEnvForRole("dns-resolver")
	defer func() {
		if err := riskService.Close(); err != nil {
			logjson.Warn("risk service close failed", map[string]any{
				"service": "dns-resolver",
				"error":   err.Error(),
			})
		}
	}()

	metrics := observability.NewRegistry()

	// --- Rate limiting ---
	rlEnabled := config.Bool("SAFE_ZONE_RATELIMIT_ENABLED", true)
	var tiered *ratelimit.TieredMiddleware
	var dotLimiter *ratelimit.Limiter
	if rlEnabled {
		dohLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DOH_RPM", 100), config.Int("SAFE_ZONE_RATELIMIT_DOH_BURST", 20))
		defaultLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", 15))
		dotLimiter = ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DOT_RPM", 100), config.Int("SAFE_ZONE_RATELIMIT_DOT_BURST", 20))

		defer dohLimiter.Close()
		defer defaultLimiter.Close()
		defer dotLimiter.Close()

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

	res := resolver.New(riskService, metrics, upstreams, resolver.Config{
		BlockPageIP:    config.String("SAFE_ZONE_BLOCK_PAGE_IP", "127.0.0.1"),
		BlockStrategy:  blockStrategy,
		DNSTTL:         uint32(ttlVal), // #nosec G115 -- bounds validated above
		DeploymentTier: config.String("SAFE_ZONE_DEPLOYMENT_TIER", "budget-vps"),
	}, dotLimiter)

	mux := server.NewRouter(res, tiered)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, metrics)
	requestIDHandler := serve.WithRequestID(httputil.LogRequests("dns-resolver", metrics)(recoveryHandler))

	httpServer := &http.Server{
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
			Handler:      dns.HandlerFunc(res.DoTHandler),
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
		if err := serve.RunHTTPServer(httpServer, shutdownTimeout); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	if err := httpServer.Shutdown(ctx); err != nil {
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
"""

with open(main_path, "w", encoding="utf-8") as f:
    f.write(new_content)
