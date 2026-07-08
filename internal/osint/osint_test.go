package osint

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
)

type stubResolver struct {
	records map[string][]net.IP
	err     error
}

func (r *stubResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if r.err != nil {
		return nil, r.err
	}
	ips := r.records[host]
	return append([]net.IP(nil), ips...), nil
}

func TestLookupOfficialWarningEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>Cảnh báo giả mạo</title><body>dichvucong-vn.com là website giả mạo, lừa đảo.</body></html>`))
	}))
	defer server.Close()

	service := NewService(Options{
		Enabled:             true,
		Timeout:             time.Second,
		CacheTTL:            time.Hour,
		Sources:             []string{server.URL},
		TrustedDomains:      []string{strings.TrimPrefix(server.URL, "http://")},
		AllowPrivateSources: true,
	})

	report, err := service.Lookup(context.Background(), "dichvucong-vn.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ShouldBlock {
		t.Fatalf("expected strong warning to block, got %#v", report)
	}
	if len(report.Evidence) != 1 {
		t.Fatalf("expected one evidence item, got %d", len(report.Evidence))
	}
	if report.Evidence[0].SourceType != TypeTrustedNewsWarning {
		t.Fatalf("expected trusted news warning for test host, got %s", report.Evidence[0].SourceType)
	}
}

func TestApplyStrongEvidenceEscalatesToMalicious(t *testing.T) {
	service := NewService(Options{Enabled: true})
	result := analysis.Result{
		Domain:     "baohiem-online.com",
		Verdict:    analysis.VerdictSafe,
		Score:      0,
		Confidence: 0.45,
		Category:   "uncategorized",
	}

	updated := service.Apply(result, Report{
		Domain:      "baohiem-online.com",
		ShouldBlock: true,
		Evidence: []Evidence{{
			SourceType: TypeOfficialWarning,
			Confidence: 0.95,
		}},
	})

	if updated.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", updated.Verdict)
	}
	if updated.Category != "phishing" {
		t.Fatalf("expected phishing category, got %s", updated.Category)
	}
	if updated.Score < 90 {
		t.Fatalf("expected score >= 90, got %d", updated.Score)
	}
}

func TestUntrustedSourceRejected(t *testing.T) {
	service := NewService(Options{
		Enabled:             true,
		Sources:             []string{"https://untrusted.example/warning"},
		TrustedDomains:      []string{"gov.vn"},
		AllowPrivateSources: true,
	})

	_, err := service.fetchSource(context.Background(), "dichvucong-vn.com", "https://untrusted.example/warning")
	if err == nil {
		t.Fatal("expected untrusted source to be rejected")
	}
}

func TestValidateSourceRejectsPrivateResolvedIP(t *testing.T) {
	service := NewService(Options{
		Enabled:        true,
		TrustedDomains: []string{"trusted.example"},
		Resolver: &stubResolver{
			records: map[string][]net.IP{
				"trusted.example": {net.ParseIP("127.0.0.1")},
			},
		},
	})

	parsed, err := url.Parse("https://trusted.example/warning")
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.validateSource(context.Background(), parsed)
	if err == nil || !strings.Contains(err.Error(), "blocked private source address") {
		t.Fatalf("expected blocked private source address, got %v", err)
	}
}

func TestFetchSourcePinsValidatedIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>Cảnh báo giả mạo</title><body>evil.example là website giả mạo, lừa đảo.</body></html>`))
	}))
	defer server.Close()

	var dialedAddr string
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}

	service := NewService(Options{
		Enabled:        true,
		Timeout:        time.Second,
		HTTPClient:     &http.Client{Timeout: time.Second, Transport: baseTransport},
		TrustedDomains: []string{"trusted.example"},
		Resolver: &stubResolver{
			records: map[string][]net.IP{
				"trusted.example": {net.ParseIP("93.184.216.34")},
			},
		},
	})

	evidence, err := service.fetchSource(context.Background(), "evil.example", "http://trusted.example/warning")
	if err != nil {
		t.Fatalf("fetch source: %v", err)
	}
	if evidence.SourceURL == "" {
		t.Fatalf("expected evidence to be returned, got %#v", evidence)
	}
	if dialedAddr == "" {
		t.Fatal("expected dialed address to be captured")
	}
	host, port, err := net.SplitHostPort(dialedAddr)
	if err != nil {
		t.Fatalf("split dialed address: %v", err)
	}
	if host != "93.184.216.34" || port != "80" {
		t.Fatalf("expected pinned dial to 93.184.216.34:80, got %s", dialedAddr)
	}
}

func TestOfficialGovDomainDoesNotNeedKeywordLookup(t *testing.T) {
	result := analysis.Analyze("dichvucong.gov.vn")
	if ShouldLookup("dichvucong.gov.vn", result) {
		t.Fatal("official gov.vn domain should not trigger protected keyword OSINT lookup")
	}
	if ShouldLookup("dichvucong.hanoi.gov.vn", analysis.Analyze("dichvucong.hanoi.gov.vn")) {
		t.Fatal("official gov.vn subdomain should not trigger protected keyword OSINT lookup")
	}
}
