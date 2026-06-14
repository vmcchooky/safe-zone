package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func DoDoH(ctx context.Context, client *http.Client, upstreamURL string, wire []byte) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// #nosec G107 G704 -- URL is from trusted server configuration.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

type UpstreamResolver struct {
	mu        sync.RWMutex
	endpoints []UpstreamEndpoint
	client    *http.Client
}

type UpstreamEndpoint struct {
	URL       string        `json:"url"`
	Healthy   bool          `json:"healthy"`
	LatencyMS int64         `json:"latency_ms"`
	Failures  int           `json:"failures"`
	LastError string        `json:"last_error,omitempty"`
	latency   time.Duration `json:"-"`
}

func NewUpstreamResolver(raw string, client *http.Client) *UpstreamResolver {
	urls := parseUpstreamURLs(raw)
	if len(urls) == 0 {
		urls = []string{"https://cloudflare-dns.com/dns-query"}
	}
	endpoints := make([]UpstreamEndpoint, 0, len(urls))
	for _, endpointURL := range urls {
		endpoints = append(endpoints, UpstreamEndpoint{URL: endpointURL, Healthy: true})
	}
	return &UpstreamResolver{endpoints: endpoints, client: client}
}

func parseUpstreamURLs(raw string) []string {
	seen := map[string]struct{}{}
	var urls []string
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		urls = append(urls, value)
	}
	return urls
}

func (u *UpstreamResolver) PrimaryURL() string {
	status := u.Status()
	if active, _ := status["active"].(string); active != "" {
		return active
	}
	return "https://cloudflare-dns.com/dns-query"
}

func (u *UpstreamResolver) Status() map[string]any {
	if u == nil {
		return map[string]any{}
	}
	endpoints := u.orderedEndpoints()
	active := ""
	if len(endpoints) > 0 {
		active = endpoints[0].URL
	}
	for i := range endpoints {
		endpoints[i].LatencyMS = endpoints[i].latency.Milliseconds()
	}
	return map[string]any{
		"active":    active,
		"endpoints": endpoints,
	}
}

func (u *UpstreamResolver) orderedEndpoints() []UpstreamEndpoint {
	u.mu.RLock()
	defer u.mu.RUnlock()
	endpoints := append([]UpstreamEndpoint(nil), u.endpoints...)
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Healthy != endpoints[j].Healthy {
			return endpoints[i].Healthy
		}
		if endpoints[i].latency == 0 {
			return false
		}
		if endpoints[j].latency == 0 {
			return true
		}
		return endpoints[i].latency < endpoints[j].latency
	})
	return endpoints
}

func (u *UpstreamResolver) Forward(ctx context.Context, wire []byte) ([]byte, string, error) {
	var lastErr error
	for _, endpoint := range u.orderedEndpoints() {
		started := time.Now()
		response, err := DoDoH(ctx, u.client, endpoint.URL, wire)
		if err == nil {
			u.markSuccess(endpoint.URL, time.Since(started))
			return response, endpoint.URL, nil
		}
		lastErr = err
		u.markFailure(endpoint.URL, err)
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream DoH resolvers configured")
	}
	return nil, "", lastErr
}

func (u *UpstreamResolver) markSuccess(endpointURL string, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.endpoints {
		if u.endpoints[i].URL == endpointURL {
			u.endpoints[i].Healthy = true
			u.endpoints[i].LatencyMS = latency.Milliseconds()
			u.endpoints[i].latency = latency
			u.endpoints[i].Failures = 0
			u.endpoints[i].LastError = ""
			return
		}
	}
}

func (u *UpstreamResolver) markFailure(endpointURL string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.endpoints {
		if u.endpoints[i].URL == endpointURL {
			u.endpoints[i].Healthy = false
			u.endpoints[i].Failures++
			if err != nil {
				u.endpoints[i].LastError = err.Error()
			}
			return
		}
	}
}

func (u *UpstreamResolver) ProbeLoop(ctx context.Context, interval time.Duration) {
	u.probeAll(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.probeAll(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (u *UpstreamResolver) probeAll(ctx context.Context) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		return
	}
	for _, endpoint := range u.orderedEndpoints() {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		started := time.Now()
		_, err := DoDoH(probeCtx, u.client, endpoint.URL, wire)
		cancel()
		if err != nil {
			u.markFailure(endpoint.URL, err)
			continue
		}
		u.markSuccess(endpoint.URL, time.Since(started))
	}
}
