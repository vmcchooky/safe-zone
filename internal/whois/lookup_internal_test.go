package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestQueryReadsLongWhoisLines(t *testing.T) {
	longLine := strings.Repeat("A", 70*1024)
	response := fmt.Sprintf("Creation Date: 2024-01-01T00:00:00Z\nLegal: %s\nRegistrar: Example Registrar\n", longLine)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock WHOIS server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				scanner := bufio.NewScanner(c)
				if !scanner.Scan() {
					return
				}

				_, _ = fmt.Fprint(c, response)
			}(conn)
		}
	}()

	originalDial := whoisDialContext
	whoisDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	t.Cleanup(func() {
		whoisDialContext = originalDial
	})

	raw, err := query(context.Background(), "mock.whois.local", "example.com")
	if err != nil {
		t.Fatalf("query returned error for long WHOIS response: %v", err)
	}

	if !strings.Contains(raw, longLine) {
		t.Fatal("expected long WHOIS line to be preserved in response")
	}
}

func TestQueryAppliesDefaultTimeoutWithoutContextDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	go func() {
		defer serverConn.Close()
		scanner := bufio.NewScanner(serverConn)
		if !scanner.Scan() {
			return
		}
		_, _ = fmt.Fprint(serverConn, "Creation Date: 2024-01-01T00:00:00Z\n")
	}()

	originalDial := whoisDialContext
	var capturedDeadline time.Time
	var sawDeadline bool
	whoisDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		capturedDeadline, sawDeadline = ctx.Deadline()
		return clientConn, nil
	}
	t.Cleanup(func() {
		whoisDialContext = originalDial
	})

	start := time.Now()
	if _, err := query(context.Background(), "mock.whois.local", "example.com"); err != nil {
		t.Fatalf("query returned error: %v", err)
	}
	if !sawDeadline {
		t.Fatal("expected query to apply a default deadline when context has none")
	}

	timeout := capturedDeadline.Sub(start)
	if timeout < 4*time.Second || timeout > 6*time.Second {
		t.Fatalf("expected default timeout near 5s, got %s", timeout)
	}
}
