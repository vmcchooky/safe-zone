package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"safe-zone/internal/analysis"
)

func TestBrandHandlerCRUD(t *testing.T) {
	manager := analysis.NewMemoryBrandStore(nil)
	handler := BrandHandler(manager)

	createRecorder := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/v1/brands", strings.NewReader(`{
		"name": "quorix",
		"official_domain": "quorix.io.vn",
		"alt_domains": ["safe.quorix.io.vn"]
	}`))
	handler(createRecorder, createReq)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created analysis.Brand
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected created id")
	}

	listRecorder := httptest.NewRecorder()
	handler(listRecorder, httptest.NewRequest(http.MethodGet, "/v1/brands", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listRecorder.Code)
	}
	var listPayload struct {
		Items []analysis.Brand `json:"items"`
	}
	if err := json.NewDecoder(listRecorder.Body).Decode(&listPayload); err != nil {
		t.Fatal(err)
	}
	if len(listPayload.Items) != 1 {
		t.Fatalf("expected one brand, got %d", len(listPayload.Items))
	}

	updateRecorder := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPut, "/v1/brands?id=1", strings.NewReader(`{
		"name": "quorix",
		"official_domain": "quorix.com",
		"alt_domains": []
	}`))
	handler(updateRecorder, updateReq)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRecorder.Code, updateRecorder.Body.String())
	}

	deleteRecorder := httptest.NewRecorder()
	handler(deleteRecorder, httptest.NewRequest(http.MethodDelete, "/v1/brands?id=1", nil))
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
}
