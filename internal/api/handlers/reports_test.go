package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestListReportsHandlerReturnsFilteredTotalForPagination(t *testing.T) {
	ts := newHandlerTestServer(t)
	for _, domain := range []string{"one.example", "two.example", "three.example"} {
		if _, err := ts.Store.CreateBlockReport(context.Background(), domain, "", "Needs review"); err != nil {
			t.Fatalf("create report: %v", err)
		}
	}

	req, err := http.NewRequest(http.MethodGet, ts.Server.URL+"/v1/reports?status=pending&limit=1&offset=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.addAdminBearer(req)

	resp, err := ts.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload struct {
		Reports []struct {
			Domain string `json:"domain"`
		} `json:"reports"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 3 {
		t.Fatalf("expected total 3, got %d", payload.Total)
	}
	if len(payload.Reports) != 1 || payload.Reports[0].Domain != "two.example" {
		t.Fatalf("expected second page to contain two.example, got %+v", payload.Reports)
	}
}
