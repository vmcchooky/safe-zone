package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The Grafana dashboard is an operational instrument that reads core-api
// routes directly; nothing consumes it automatically, so a stale URL drifts
// silently. This test pins that every panel target resolves to a route this
// service actually serves, and that the Feed Freshness panel reads the
// authenticated status route (the root path has belonged to the operator UI
// since the React app landed).

const dashboardPath = "../../../ops/grafana/safe-zone-dashboard.json"

func TestDashboardPanelsReferenceRegisteredRoutes(t *testing.T) {
	data, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var dashboard struct {
		Panels []struct {
			Title   string `json:"title"`
			Type    string `json:"type"`
			Targets []struct {
				URL string `json:"url"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatalf("parse dashboard: %v", err)
	}

	registered := map[string]bool{}
	for _, route := range SpecRoutes() {
		registered[route.Path] = true
	}

	for _, panel := range dashboard.Panels {
		for _, target := range panel.Targets {
			if target.URL == "" {
				continue
			}
			path := strings.TrimPrefix(target.URL, "${safe_zone_base}")
			path = strings.SplitN(path, "?", 2)[0]
			// Row and text panels carry no target URL; every URL panel must
			// point at a route the router actually serves.
			if !registered[path] {
				t.Errorf("panel %q reads %q, which no router registers (stale monitoring drift)", panel.Title, target.URL)
			}
		}
	}

	// The Feed Freshness panel predates the UI takeover of "/"; it must read
	// the authenticated status route like the alert rules do.
	for _, panel := range dashboard.Panels {
		if panel.Title != "Feed Freshness" {
			continue
		}
		for _, target := range panel.Targets {
			if got := strings.TrimPrefix(target.URL, "${safe_zone_base}"); got != "/v1/status" {
				t.Errorf("Feed Freshness panel reads %q, want /v1/status", got)
			}
		}
	}
}
