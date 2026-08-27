package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/miekg/dns"
)

// stubBackend trả về response cài sẵn cho mọi truy vấn, ghi lại client info
// để test xác nhận transport truyền đúng identity lên pipeline.
type stubBackend struct {
	response    *dns.Msg
	err         error
	lastClient  ClientInfo
	lastQueries []*dns.Msg
}

func (s *stubBackend) ResolveQuery(_ context.Context, query *dns.Msg, client ClientInfo) (*dns.Msg, error) {
	s.lastClient = client
	s.lastQueries = append(s.lastQueries, query)
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

func testQuery(t *testing.T, name string, qtype uint16) *dns.Msg {
	if t != nil {
		t.Helper()
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	return query
}

func wireOf(t *testing.T, msg *dns.Msg) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack test message: %v", err)
	}
	return wire
}

func testAAnswer(name, ip string, ttl uint32) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(testQuery(nil, name, dns.TypeA))
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	})
	return response
}

func dohRequest(t *testing.T, method, target string, body []byte, contentType string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestHandlerPOSTReturnsAnswerWithCacheControl(t *testing.T) {
	backend := &stubBackend{response: testAAnswer("example.com", "93.184.216.34", 300)}
	handler := NewHandler(backend)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodPost, "/dns-query", wireOf(t, testQuery(t, "example.com", dns.TypeA)), ContentTypeDNSMessage))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != ContentTypeDNSMessage {
		t.Fatalf("expected content-type application/dns-message, got %q", got)
	}
	// RFC 8484 §5.1: freshness lifetime bằng TTL nhỏ nhất trong Answer.
	if got := recorder.Header().Get("Cache-Control"); got != "private, max-age=300" {
		t.Fatalf("expected Cache-Control private max-age=300, got %q", got)
	}

	response := new(dns.Msg)
	if err := response.Unpack(recorder.Body.Bytes()); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(response.Answer))
	}
}

func TestHandlerGETWithDNSParameter(t *testing.T) {
	backend := &stubBackend{response: testAAnswer("example.com", "93.184.216.34", 120)}
	handler := NewHandler(backend)

	encoded := base64.RawURLEncoding.EncodeToString(wireOf(t, testQuery(t, "example.com", dns.TypeA)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodGet, "/dns-query?dns="+url.QueryEscape(encoded), nil, ""))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, max-age=120" {
		t.Fatalf("expected Cache-Control private max-age=120, got %q", got)
	}
	if len(backend.lastQueries) != 1 || backend.lastQueries[0].Question[0].Name != "example.com." {
		t.Fatalf("backend did not receive decoded query: %#v", backend.lastQueries)
	}
}

func TestHandlerPaddedBase64Rejected(t *testing.T) {
	// RFC 8484 §6: "Padding characters for base64url MUST NOT be included".
	backend := &stubBackend{response: testAAnswer("example.com", "93.184.216.34", 120)}
	handler := NewHandler(backend)

	raw := base64.RawURLEncoding.EncodeToString(wireOf(t, testQuery(t, "example.com", dns.TypeA)))
	padded := raw + "="
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodGet, "/dns-query?dns="+url.QueryEscape(padded), nil, ""))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for padded base64url, got %d", recorder.Code)
	}
}

func TestHandlerProtocolErrors(t *testing.T) {
	validWire := wireOf(t, testQuery(t, "example.com", dns.TypeA))

	noQuestion := new(dns.Msg)
	noQuestion.Id = dns.Id()
	noQuestionWire, err := noQuestion.Pack()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		method     string
		target     string
		body       []byte
		contentTye string
		wantStatus int
		wantAllow  string
	}{
		{name: "GET without dns parameter", method: http.MethodGet, target: "/dns-query", wantStatus: http.StatusBadRequest},
		{name: "GET with malformed base64", method: http.MethodGet, target: "/dns-query?dns=%%%invalid", wantStatus: http.StatusBadRequest},
		{name: "POST with wrong content type", method: http.MethodPost, target: "/dns-query", body: validWire, contentTye: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "POST without content type", method: http.MethodPost, target: "/dns-query", body: validWire, wantStatus: http.StatusUnsupportedMediaType},
		{name: "POST with oversized body", method: http.MethodPost, target: "/dns-query", body: bytes.Repeat([]byte{0x00}, MaxDNSMessageSize+1), contentTye: ContentTypeDNSMessage, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "POST with invalid DNS message", method: http.MethodPost, target: "/dns-query", body: []byte{0x01, 0x02, 0x03}, contentTye: ContentTypeDNSMessage, wantStatus: http.StatusBadRequest},
		{name: "POST with no question section", method: http.MethodPost, target: "/dns-query", body: noQuestionWire, contentTye: ContentTypeDNSMessage, wantStatus: http.StatusBadRequest},
		{name: "PUT not allowed", method: http.MethodPut, target: "/dns-query", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, POST"},
		{name: "DELETE not allowed", method: http.MethodDelete, target: "/dns-query", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, POST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(&stubBackend{response: testAAnswer("example.com", "93.184.216.34", 300)})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, dohRequest(t, tt.method, tt.target, tt.body, tt.contentTye))

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d (%s)", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Allow"); got != tt.wantAllow {
				t.Fatalf("expected Allow header %q, got %q", tt.wantAllow, got)
			}
		})
	}
}

func TestHandlerBackendErrorBecomesSERVFAILInsideHTTP200(t *testing.T) {
	// RFC 8484 §4.2.1: lỗi DNS (SERVFAIL) phải đi trong HTTP 200, không phải HTTP 5xx.
	backend := &stubBackend{err: errors.New("upstream unreachable")}
	handler := NewHandler(backend)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodPost, "/dns-query", wireOf(t, testQuery(t, "example.com", dns.TypeA)), ContentTypeDNSMessage))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with SERVFAIL DNS message, got %d", recorder.Code)
	}
	response := new(dns.Msg)
	if err := response.Unpack(recorder.Body.Bytes()); err != nil {
		t.Fatalf("unpack servfail response: %v", err)
	}
	if response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got %s", dns.RcodeToString[response.Rcode])
	}
	if !response.RecursionAvailable {
		t.Fatal("expected RecursionAvailable on SERVFAIL response")
	}
}

func TestHandlerNegativeResponseUsesSOAMinimum(t *testing.T) {
	// RFC 8484 §5.1 + RFC 2308: NXDOMAIN không có Answer nhưng có SOA ở
	// Authority thì freshness không được vượt quá min(SOA TTL, SOA MINIMUM).
	query := testQuery(t, "missing.example", dns.TypeA)
	response := new(dns.Msg)
	response.SetRcode(query, dns.RcodeNameError)
	response.Ns = append(response.Ns, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900},
		Ns:     "ns1.example.",
		Mbox:   "hostmaster.example.",
		Serial: 1,
		Minttl: 30,
	})

	handler := NewHandler(&stubBackend{response: response})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodPost, "/dns-query", wireOf(t, query), ContentTypeDNSMessage))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, max-age=30" {
		t.Fatalf("expected Cache-Control capped at SOA minimum 30, got %q", got)
	}
}

func TestServfailFreshnessIsZero(t *testing.T) {
	// SERVFAIL không có Answer lẫn SOA: freshness phải là 0 để HTTP cache
	// không tự heuristic cache trạng thái lỗi.
	response := new(dns.Msg)
	response.SetRcode(testQuery(t, "example.com", dns.TypeA), dns.RcodeServerFailure)

	if got := CacheFreshnessLifetime(response); got != 0 {
		t.Fatalf("expected freshness 0 for SERVFAIL, got %d", got)
	}
}

func TestHandlerExtractsClientIDFromPathAndQuery(t *testing.T) {
	backend := &stubBackend{response: testAAnswer("example.com", "93.184.216.34", 60)}
	handler := NewHandler(backend)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohRequest(t, http.MethodPost, "/dns-query/kids-group", wireOf(t, testQuery(t, "example.com", dns.TypeA)), ContentTypeDNSMessage))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if backend.lastClient.ClientID != "kids-group" {
		t.Fatalf("expected client_id from path kids-group, got %q", backend.lastClient.ClientID)
	}

	recorderQuery := httptest.NewRecorder()
	handler.ServeHTTP(recorderQuery, dohRequest(t, http.MethodPost, "/dns-query?client_id=guest", wireOf(t, testQuery(t, "example.com", dns.TypeA)), ContentTypeDNSMessage))
	if recorderQuery.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorderQuery.Code)
	}
	if backend.lastClient.ClientID != "guest" {
		t.Fatalf("expected client_id from query param guest, got %q", backend.lastClient.ClientID)
	}
}

func TestCacheFreshnessLifetimeUnitCases(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) *dns.Msg
		want  uint32
	}{
		{
			name:  "nil message",
			build: func(t *testing.T) *dns.Msg { return nil },
			want:  0,
		},
		{
			name: "smallest TTL in answer section wins",
			build: func(t *testing.T) *dns.Msg {
				msg := new(dns.Msg)
				msg.SetReply(testQuery(t, "example.com", dns.TypeA))
				msg.Answer = append(msg.Answer,
					&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, A: net.ParseIP("1.1.1.1")},
					&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("1.1.1.1")},
					&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.1.1.1")},
				)
				return msg
			},
			want: 30,
		},
		{
			name: "SOA minimum caps negative response TTL",
			build: func(t *testing.T) *dns.Msg {
				msg := new(dns.Msg)
				msg.SetRcode(testQuery(t, "missing.example", dns.TypeA), dns.RcodeNameError)
				msg.Ns = append(msg.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1800}, Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 1, Minttl: 60})
				return msg
			},
			want: 60,
		},
		{
			name: "SOA record TTL lower than minimum field",
			build: func(t *testing.T) *dns.Msg {
				msg := new(dns.Msg)
				msg.SetRcode(testQuery(t, "missing.example", dns.TypeA), dns.RcodeNameError)
				msg.Ns = append(msg.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 45}, Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 1, Minttl: 86400})
				return msg
			},
			want: 45,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CacheFreshnessLifetime(tt.build(t)); got != tt.want {
				t.Fatalf("expected freshness %d, got %d", tt.want, got)
			}
		})
	}
}
