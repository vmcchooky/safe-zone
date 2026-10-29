package analysis

import "testing"

// ToSkeletonExtended must cover confusable classes the v1 hand-written map
// misses (fullwidth forms, Greek/Cyrillic lookalikes) while ToSkeleton stays
// pinned for the frozen ML feature contract.
func TestToSkeletonExtendedCoversTR39(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		// v1 map still honored.
		{"аpple", "apple"},   // Cyrillic а
		{"οpenai", "openai"}, // Greek ο
		// TR39 classes the v1 map lacks.
		{"ａｐｐｌｅ", "apple"}, // fullwidth forms
		{"ѕсam", "scam"},   // Cyrillic dze + es
	}
	for _, tc := range cases {
		if got := ToSkeletonExtended(tc.input); got != tc.want {
			t.Errorf("ToSkeletonExtended(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
	// Plain ASCII passes through untouched.
	if got := ToSkeletonExtended("googel.com"); got != "googel.com" {
		t.Fatalf("ASCII passthrough broken: %q", got)
	}
}

func TestToSkeletonUnchangedForML(t *testing.T) {
	// The v1 skeleton must stay exactly as the frozen ML contract expects:
	// fullwidth forms are NOT mapped there.
	if got := ToSkeleton("ａｐｐｌｅ"); got == "apple" {
		t.Fatal("v1 skeleton unexpectedly maps fullwidth forms; ML feature values would shift")
	}
	if got := ToSkeleton("аpple"); got != "apple" {
		t.Fatalf("v1 skeleton lost Cyrillic mapping: %q", got)
	}
}

// Extended skeleton should let the homoglyph spoof path catch a fullwidth
// lookalike of a known brand label.
func TestExtendedSkeletonDetectsFullwidthSpoof(t *testing.T) {
	spoof, reason, _ := CheckBrandSpoofingWithBrands("аmazоn-secure.com", 50, nil)
	if !spoof {
		t.Fatalf("expected homoglyph spoof detection, reason=%q", reason)
	}
}
