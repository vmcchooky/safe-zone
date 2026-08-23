package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildCasesGroupsWWWAndRetainsLicense(t *testing.T) {
	t.Parallel()
	candidates := []byte("domain,evidence_host,evidence_reference,model_probability,would_block,near_threshold\n" +
		"example.vn,tinnhiemmang.vn,https://tinnhiemmang.vn/evidence/example,0.91,true,false\n" +
		"www.license.vn,giayphep.abei.gov.vn,https://giayphep.abei.gov.vn/,0.86,true,true\n" +
		"license.vn,giayphep.abei.gov.vn,https://giayphep.abei.gov.vn/,0.86,true,true\n" +
		"ignored.vn,tinnhiemmang.vn,https://tinnhiemmang.vn/evidence/ignored,0.2,false,false\n")
	metadata := []byte("domain,owner,license_number,status,certified_date,detail_url\n" +
		"example.vn,Example Org,,valid,2026-01-01,https://tinnhiemmang.vn/evidence/example\n" +
		"www.license.vn,License Org,12/GP,valid,2026-01-02,https://giayphep.abei.gov.vn/\n" +
		"license.vn,License Org,12/GP,valid,2026-01-02,https://giayphep.abei.gov.vn/\n")
	cases, err := buildCases(candidates, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("case groups = %d, want 2", len(cases))
	}
	var license evidenceCase
	for _, item := range cases {
		if item.CanonicalDomain == "license.vn" {
			license = item
		}
	}
	if license.LicenseNumber != "12/GP" || len(license.RequestedDomains) != 2 || license.EvidenceType != "license_registry" {
		t.Fatalf("unexpected grouped license case: %+v", license)
	}
}

func TestValidateEvidenceReferenceRejectsHostConfusion(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://tinnhiemmang.vn.attacker.example/evidence",
		"https://tinnhiemmang.vn@attacker.example/evidence",
		"http://tinnhiemmang.vn/evidence",
	} {
		if _, _, err := validateEvidenceReference(raw); err == nil {
			t.Fatalf("expected rejection for %s", raw)
		}
	}
}

func TestScrapeEvidenceUsesOnlyEvidenceURLAndValidatesResponse(t *testing.T) {
	t.Parallel()
	item := evidenceCase{
		CaseID:           "fce-1",
		CanonicalDomain:  "example.vn",
		RequestedDomains: []string{"example.vn"},
		EvidenceHost:     "tinnhiemmang.vn",
		EvidenceURL:      "https://tinnhiemmang.vn/evidence/example",
		EvidenceType:     "trust_directory",
	}
	item.ExtractionPrompt = evidencePrompt(item)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer unit-test-key" {
			t.Fatalf("unexpected request contract")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["url"] != item.EvidenceURL {
			t.Fatalf("request URL = %v, want evidence URL", payload["url"])
		}
		response := `{"success":true,"data":{"json":{"requested_domain":"example.vn","source_host":"tinnhiemmang.vn","evidence_url":"https://tinnhiemmang.vn/evidence/example","record_found":true,"listed_domain":"example.vn","organization_name":"Example","evidence_type":"trust_directory","license_number":"","record_status":"valid","issued_date":"","last_updated_date":"","domain_match":"exact","evidence_excerpt":"Evidence","needs_manual_review":false,"review_reason":""}}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	result := scrapeEvidence(context.Background(), server.Client(), server.URL, "unit-test-key", item)
	if !result.Success || result.Record.ListedDomain != "example.vn" || len(result.RawResponse) == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "unit-test-key") {
		t.Fatal("API key leaked into result")
	}
}

func TestValidateExtractedRecordRequiresExpectedLicense(t *testing.T) {
	t.Parallel()
	item := evidenceCase{
		CanonicalDomain: "license.vn",
		EvidenceHost:    "giayphep.abei.gov.vn",
		EvidenceURL:     "https://giayphep.abei.gov.vn/",
		EvidenceType:    "license_registry",
		LicenseNumber:   "12/GP",
	}
	record := extractedRecord{
		RequestedDomain: "license.vn", SourceHost: item.EvidenceHost, EvidenceURL: item.EvidenceURL,
		RecordFound: true, EvidenceType: item.EvidenceType, LicenseNumber: "wrong",
		RecordStatus: "valid", DomainMatch: "exact",
	}
	if err := validateExtractedRecord(item, record); err == nil {
		t.Fatal("expected license mismatch")
	}
}
