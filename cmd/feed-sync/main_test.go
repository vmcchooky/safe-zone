package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/feed"
)

// policySourceURL rewrites a loopback httptest URL to a public RFC 5737
// documentation IP so the source passes the outbound policy checks, while
// the returned client still dials the real loopback listener.
func policySourceURL(t *testing.T, srv *httptest.Server) (string, *http.Client) {
	t.Helper()
	host := srv.URL[len("http://"):]
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatalf("split httptest host: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, dialPort, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", dialPort))
			},
		},
	}
	return "http://" + net.JoinHostPort("198.51.100.10", port), client
}

func TestOpenSourceHandlesGzipHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("bad.test\n"))
		_ = writer.Close()
	}))
	defer server.Close()

	sourceURL, client := policySourceURL(t, server)
	reader, closeReader, err := feed.OpenSourceWithin(context.Background(), sourceURL, client, t.TempDir(), feed.DefaultMaxFeedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	domains, stats := collectParsed(t, reader)

	if stats.Valid != 1 {
		t.Fatalf("expected 1 valid domain, got %d", stats.Valid)
	}
	if len(domains) != 1 || domains[0] != "bad.test" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}

func TestWrapMaybeCompressedReadCloserWithGzipSuffix(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, _ = writer.Write([]byte("evil.test\n"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "feed.txt.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	reader, closeReader, err := feed.OpenSourceWithin(context.Background(), path, nil, filepath.Dir(path), feed.DefaultMaxFeedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	domains, _ := collectParsed(t, reader)
	if len(domains) != 1 || domains[0] != "evil.test" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}

// collectParsed drains a feed through the production ParseEach pipeline.
func collectParsed(t *testing.T, reader io.Reader) ([]string, feed.ParseStats) {
	t.Helper()
	var (
		domains []string
		stats   feed.ParseStats
	)
	err := feed.ParseEach(reader, func(domain string) error {
		domains = append(domains, domain)
		return nil
	}, &stats)
	if err != nil {
		t.Fatal(err)
	}
	return domains, stats
}
