package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// fuzzBackend answers every query with a deterministic reply, except for
// names ending in .err which take the SERVFAIL path, so both ResolveQuery
// outcomes are exercised from one corpus.
type fuzzBackend struct{}

func (fuzzBackend) ResolveQuery(_ context.Context, query *dns.Msg, _ ClientInfo) (*dns.Msg, error) {
	if len(query.Question) > 0 && bytes.HasSuffix([]byte(query.Question[0].Name), []byte(".err.")) {
		return nil, context.DeadlineExceeded
	}
	reply := new(dns.Msg)
	reply.SetReply(query)
	if len(query.Question) > 0 {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 1},
		})
	}
	return reply, nil
}

// FuzzDoHServer drives the RFC 8484 HTTP endpoint with arbitrary methods,
// paths, query strings, content types and bodies. The request surface is
// fully untrusted: the handler must answer from a closed set of status
// codes, never panic, and a 200 body must always be a parseable DNS message.
func FuzzDoHServer(f *testing.F) {
	// A valid example.com A query, both as POST body and base64url GET param.
	validQuery := []byte("\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
	seeds := []struct {
		method      string
		path        string
		rawquery    string
		contentType string
		body        []byte
	}{
		{"POST", "/dns-query", "", ContentTypeDNSMessage, validQuery},
		{"GET", "/dns-query", "dns=" + base64.RawURLEncoding.EncodeToString(validQuery), "", nil},
		{"POST", "/dns-query/smoke-client", "", ContentTypeDNSMessage, validQuery},
		{"POST", "/dns-query", "", "text/plain", validQuery},
		{"POST", "/dns-query", "", ContentTypeDNSMessage, nil},
		{"GET", "/dns-query", "", "", nil},
		{"DELETE", "/dns-query", "", "", nil},
		{"POST", "/dns-query", "", ContentTypeDNSMessage, []byte("not a dns message")},
		{"GET", "/dns-query", "dns=!!!not-base64url!!!", "", nil},
		{"GET", "/dns-query", "dns=", "", nil},
		{"POST", "/dns-query", "", ContentTypeDNSMessage, []byte("\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")}, // no question
		{"POST", "/dns-query", "", ContentTypeDNSMessage, validQuery[:8]},
		{"POST", "/dns-query", "", ContentTypeDNSMessage + "; charset=utf-8", validQuery},
	}
	for _, s := range seeds {
		f.Add(s.method, s.path, s.rawquery, s.contentType, s.body)
	}

	handler := NewHandler(fuzzBackend{})
	// Status codes the endpoint may answer with: 200 (DNS reply inside),
	// 400 (malformed), 405 (method), 413 (body cap), 415 (content type),
	// 500 (pack failure on our own reply), plus http.Error's plain text on
	// non-200. Anything else is a regression.
	allowed := map[int]bool{
		http.StatusOK:                    true,
		http.StatusBadRequest:            true,
		http.StatusMethodNotAllowed:      true,
		http.StatusRequestEntityTooLarge: true,
		http.StatusUnsupportedMediaType:  true,
		http.StatusInternalServerError:   true,
	}

	f.Fuzz(func(t *testing.T, method, path, rawquery, contentType string, body []byte) {
		var target string
		if rawquery != "" {
			target = path + "?" + rawquery
		} else {
			target = path
		}
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			t.Skip()
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !allowed[rec.Code] {
			t.Fatalf("unexpected status %d for method=%q path=%q", rec.Code, method, target)
		}
		if rec.Code == http.StatusOK {
			if ct := rec.Header().Get("Content-Type"); ct != ContentTypeDNSMessage {
				t.Fatalf("200 response content type %q, want %q", ct, ContentTypeDNSMessage)
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(rec.Body.Bytes()); err != nil {
				t.Fatalf("200 body is not a DNS message: %v", err)
			}
			if len(msg.Question) > 0 && bytes.HasSuffix([]byte(msg.Question[0].Name), []byte(".err.")) &&
				msg.Rcode != dns.RcodeServerFailure {
				t.Fatalf(".err query answered with rcode %d, want SERVFAIL", msg.Rcode)
			}
		}
	})
}
