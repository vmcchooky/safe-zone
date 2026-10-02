package httputil

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A payload that cannot be marshalled used to produce HTTP 200 followed by a
// truncated body: WriteHeader ran before the encoder, so the failure was
// discovered only after the status line was on the wire and the client had no
// way to tell the response was incomplete.
func TestWriteJSONRejectsNonFiniteFloats(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"positive infinity", map[string]any{"psi": math.Inf(1)}},
		{"negative infinity", map[string]any{"psi": math.Inf(-1)}},
		{"not a number", map[string]any{"confidence": math.NaN()}},
		{"nested non-finite", map[string]any{"drift": map[string]any{"psi": math.Inf(1)}}},
		{"slice of non-finite", map[string]any{"values": []float64{0.1, math.Inf(1)}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteJSON(rec, http.StatusOK, tc.payload)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: an unencodable payload must not be reported as success", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
			// The error body must itself be valid JSON so a client that only
			// knows how to parse JSON does not fall back to guessing.
			var decoded map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
				t.Fatalf("error body is not valid JSON: %v", err)
			}
			if decoded["error"] == "" {
				t.Fatal("error body must carry an error message")
			}
		})
	}
}

// The failure path must not leave a partial body behind: the client has to
// receive either the whole document or a clean error.
func TestWriteJSONSendsNoPartialBodyOnEncodeFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]any{"ok": "fine", "psi": math.Inf(1)})

	body := rec.Body.String()
	if strings.Contains(body, "fine") {
		t.Fatalf("body leaked the partially encoded payload: %s", body)
	}
	if strings.TrimSpace(body) == "" {
		t.Fatal("expected an error body, got nothing")
	}
}

// A finite payload must be unaffected, and the declared status must be kept.
func TestWriteJSONPreservesStatusForEncodablePayloads(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusTeapot, map[string]any{"state": "watch", "psi": 0.25})

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	var decoded map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["state"] != "watch" || decoded["psi"] != 0.25 {
		t.Fatalf("unexpected payload %v", decoded)
	}
}

func TestWriteErrorStillWorks(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "invalid JSON body")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var decoded map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["error"] != "invalid JSON body" {
		t.Fatalf("unexpected error body %v", decoded)
	}
}

// The sentinel body is a contract: change it and update the tests.
func TestEncodeFailureBodyIsValidJSON(t *testing.T) {
	var decoded map[string]string
	if err := json.Unmarshal([]byte(encodeFailureBody), &decoded); err != nil {
		t.Fatalf("encodeFailureBody is not valid JSON: %v", err)
	}
	if decoded["error"] == "" {
		t.Fatal("encodeFailureBody must carry a message")
	}
}
