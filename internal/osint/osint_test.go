package osint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/analysis"
)

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

func TestPrivateSourceRejectedWhenNotAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	service := NewService(Options{
		Enabled:        true,
		Sources:        []string{server.URL},
		TrustedDomains: []string{strings.TrimPrefix(server.URL, "http://")},
	})

	_, err := service.fetchSource(context.Background(), "dichvucong-vn.com", server.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked private or local address") {
		t.Fatalf("expected private source rejection, got %v", err)
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
