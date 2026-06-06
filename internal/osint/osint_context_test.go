package osint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stubRoleClassifier struct {
	enabled bool
	role    string
	err     error
	calls   int
}

func (s *stubRoleClassifier) Enabled() bool {
	return s != nil && s.enabled
}

func (s *stubRoleClassifier) ClassifyDomainRole(context.Context, string, []string) (string, error) {
	s.calls++
	return s.role, s.err
}

func TestClassifyDomainRoleAttackerPattern(t *testing.T) {
	service := NewService(Options{})
	role := service.classifyDomainRole(context.Background(), "evil.example", "Cảnh báo evil.example là website giả mạo ngân hàng.")
	if role != roleAttacker {
		t.Fatalf("expected attacker, got %s", role)
	}
}

func TestClassifyDomainRoleVictimPattern(t *testing.T) {
	service := NewService(Options{})
	role := service.classifyDomainRole(context.Background(), "vietcombank.com.vn", "Cảnh báo evil.example giả mạo vietcombank.com.vn để lừa đảo.")
	if role != roleVictim {
		t.Fatalf("expected victim, got %s", role)
	}
}

func TestClassifyDomainRoleNegatedWarningIsVictim(t *testing.T) {
	service := NewService(Options{})
	role := service.classifyDomainRole(context.Background(), "vietcombank.com.vn", "Cảnh báo: vietcombank.com.vn không phải website lừa đảo.")
	if role != roleVictim {
		t.Fatalf("expected negated warning to classify as victim, got %s", role)
	}
}

func TestClassifyDomainRoleOfficialSiteBeforeDomainIsVictim(t *testing.T) {
	service := NewService(Options{})
	role := service.classifyDomainRole(context.Background(), "vietcombank.com.vn", "Website chính thức là vietcombank.com.vn; hãy cảnh báo các trang giả mạo.")
	if role != roleVictim {
		t.Fatalf("expected official site to classify as victim, got %s", role)
	}
}

func TestClassifyDomainRoleUsesAIForUnclearContext(t *testing.T) {
	classifier := &stubRoleClassifier{enabled: true, role: roleAttacker}
	service := NewService(Options{RoleClassifier: classifier})

	role := service.classifyDomainRole(context.Background(), "unclear.example", "Bài viết có nhắc tới unclear.example.")
	if role != roleAttacker {
		t.Fatalf("expected AI attacker role, got %s", role)
	}
	if classifier.calls != 1 {
		t.Fatalf("expected one AI call, got %d", classifier.calls)
	}
}

func TestClassifyDomainRoleFallsBackWhenAIFails(t *testing.T) {
	classifier := &stubRoleClassifier{enabled: true, err: errors.New("quota exhausted")}
	service := NewService(Options{RoleClassifier: classifier})

	role := service.classifyDomainRole(context.Background(), "unclear.example", "Bài viết có nhắc tới unclear.example.")
	if role != roleUnclear {
		t.Fatalf("expected unclear fallback, got %s", role)
	}
}

func TestFetchSourceSkipsVictimDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>Cảnh báo evil.example giả mạo vietcombank.com.vn để lừa đảo.</body></html>`))
	}))
	defer server.Close()

	service := NewService(Options{
		Enabled:             true,
		Timeout:             time.Second,
		Sources:             []string{server.URL},
		TrustedDomains:      []string{strings.TrimPrefix(server.URL, "http://")},
		AllowPrivateSources: true,
	})

	report, err := service.Lookup(context.Background(), "vietcombank.com.vn", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Evidence) != 0 || report.ShouldBlock {
		t.Fatalf("expected victim domain to be skipped, got %#v", report)
	}
}

func TestFetchSourceReducesConfidenceForUnclearRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>Cảnh báo lừa đảo trong tuần. Có nhắc tới unclear.example trong danh sách tham khảo.</body></html>`))
	}))
	defer server.Close()

	service := NewService(Options{
		Enabled:             true,
		Timeout:             time.Second,
		Sources:             []string{server.URL},
		TrustedDomains:      []string{strings.TrimPrefix(server.URL, "http://")},
		AllowPrivateSources: true,
	})

	report, err := service.Lookup(context.Background(), "unclear.example", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Evidence) != 1 {
		t.Fatalf("expected one low-confidence evidence item, got %#v", report)
	}
	if report.Evidence[0].Confidence >= strongEvidence || report.ShouldBlock {
		t.Fatalf("expected unclear role not to block, got %#v", report)
	}
}

func TestExtractContextPreservesValidUTF8(t *testing.T) {
	content := strings.Repeat("cảnh báo tiếng Việt ", 30) + "evil.example là website giả mạo"
	contexts := extractContext(content, "evil.example")
	if len(contexts) != 1 {
		t.Fatalf("expected one context, got %d", len(contexts))
	}
	if !strings.Contains(contexts[0], "evil.example") || !strings.Contains(contexts[0], "tiếng việt") {
		t.Fatalf("unexpected context: %q", contexts[0])
	}
}

func TestCacheKeyIncludesSmartOSINTRevision(t *testing.T) {
	if got := cacheKey("evil.example"); got != "safe-zone:osint:evidence:v2:evil.example" {
		t.Fatalf("unexpected cache key: %s", got)
	}
}
