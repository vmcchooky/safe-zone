package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type urlShadowCase struct {
	ID            string   `json:"id"`
	RequestedURL  string   `json:"requested_url"`
	ExpectedHost  string   `json:"expected_host"`
	RedirectChain []string `json:"redirect_chain"`
	Tier          string   `json:"tier"`
	Note          string   `json:"note"`
}

type urlShadowFixture struct {
	SchemaVersion int             `json:"schema_version"`
	Name          string          `json:"name"`
	Provenance    string          `json:"provenance"`
	Cases         []urlShadowCase `json:"cases"`
}

func loadURLShadowFixture(t *testing.T) (URLBundleClassifier, urlShadowFixture) {
	t.Helper()
	bundleDir := filepath.Join("..", "..", "ml", "models", "url-v1")
	classifier, err := NewURLBundleClassifier(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("testdata", "url_shadow_negatives.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture urlShadowFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 || len(fixture.Cases) == 0 {
		t.Fatalf("bad shadow fixture: %+v", fixture.Name)
	}
	return *classifier, fixture
}

// Baseline measurement for the URL-shadow negatives set: per-case
// probability/action plus FP/FN tallies. Tier ceilings are pinned once the
// guard lands; this test fails only on harness errors.
func TestURLShadowNegativesBaseline(t *testing.T) {
	classifier, fixture := loadURLShadowFixture(t)
	fp, fn, watchPromote := 0, 0, 0
	for _, tc := range fixture.Cases {
		decision, err := classifier.ClassifyURL(URLContext{
			RequestedURL:  tc.RequestedURL,
			ExpectedHost:  tc.ExpectedHost,
			RedirectChain: tc.RedirectChain,
		})
		if err != nil {
			t.Fatalf("%s: classify error: %v", tc.ID, err)
		}
		promoted := decision.Action == MLActionPromoteMalicious
		t.Logf("%s tier=%s prob=%.4f action=%s", tc.ID, tc.Tier, decision.Probability, decision.Action)
		switch tc.Tier {
		case "must_not_promote":
			if promoted {
				fp++
			}
		case "must_promote":
			if !promoted {
				fn++
			}
		case "watch":
			if promoted {
				watchPromote++
			}
		default:
			t.Fatalf("%s: unknown tier %q", tc.ID, tc.Tier)
		}
	}
	t.Logf("summary: false_positives=%d false_negatives=%d watch_promoted=%d", fp, fn, watchPromote)
}
