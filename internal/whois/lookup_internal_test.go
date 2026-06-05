package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
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
