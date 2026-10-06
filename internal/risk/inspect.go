package risk

import (
	"context"
	"net"
	"sync"
	"time"

	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// RawInspection holds the full DNS/TLS/WHOIS inspection data for a domain.
type RawInspection struct {
	Domain    string            `json:"domain"`
	DNS       RawDNS            `json:"dns"`
	TLS       tlsinspect.Result `json:"tls"`
	WHOIS     whois.Result      `json:"whois"`
	InspectAt string            `json:"inspect_at"`
}

// RawDNS contains the DNS resolution result for a domain.
type RawDNS struct {
	Resolved    bool     `json:"resolved"`
	Nameservers []string `json:"nameservers,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// InspectRawData performs on-demand DNS, TLS, and WHOIS lookups concurrently
// and returns the full enrichment data for the given domain.
func (s *Service) InspectRawData(ctx context.Context, domain string) RawInspection {
	var (
		dnsResult   RawDNS
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)

	apex := whois.RegisteredDomain(domain)
	if apex == "" {
		apex = domain
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		nsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		records, err := net.DefaultResolver.LookupNS(nsCtx, apex)
		if err != nil {
			dnsResult = RawDNS{Resolved: false, Error: err.Error()}
			return
		}
		dnsResult.Resolved = true
		for _, ns := range records {
			dnsResult.Nameservers = append(dnsResult.Nameservers, ns.Host)
		}
	}()
	go func() {
		defer wg.Done()
		tlsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		tlsResult = tlsinspect.Inspect(tlsCtx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		whoisResult = whois.LookupWithCache(whoisCtx, domain, s.store, s.whoisCacheTTL)
	}()
	wg.Wait()

	return RawInspection{
		Domain:    domain,
		DNS:       dnsResult,
		TLS:       tlsResult,
		WHOIS:     whoisResult,
		InspectAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}
