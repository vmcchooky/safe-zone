package analysis

import "strings"

// DGA detection previously leaned on Shannon entropy alone: a single
// character-frequency threshold flags every high-entropy label, including
// deliberately odd but legitimate brandable names ("zoom", "flickr",
// "spotify"). Real DGAs differ from those in a second, orthogonal dimension:
// their letter pairs are irregular even for English. Combining both —
// high entropy AND low English-bigram likelihood — separates the two groups
// (see the bigram-frequency DGA literature, e.g. philarkwright/DGA-Detection).
//
// englishBigramRatio scores a label from 0 (no pair matches English letter-pair
// statistics) to 1 (every adjacent letter pair is a common English bigram).
// Digit and hyphen boundaries count as irregular pairs, so embedded digits
// keep the ratio low.
func englishBigramRatio(label string) float64 {
	// Treat every digit as its own symbol in the sequence, so digit-letter
	// boundaries count as irregular pairs like any unmatched letter pair.
	seq := make([]rune, 0, len(label))
	for _, r := range strings.ToLower(label) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			seq = append(seq, r)
		}
	}
	if len(seq) < 2 {
		return 1
	}

	common := 0
	for i := 0; i+1 < len(seq); i++ {
		if seq[i] >= 'a' && seq[i] <= 'z' && seq[i+1] >= 'a' && seq[i+1] <= 'z' {
			if englishBigrams[string(seq[i])+string(seq[i+1])] {
				common++
			}
		}
	}
	return float64(common) / float64(len(seq)-1)
}

// dgaIrregularBigramRatio is the ceiling below which a label's letter pairs
// are considered inconsistent with English. With a ~160-entry common-pair
// table, uniformly random labels average ≈0.24 while legitimate brandable
// names measure 0.4 and above (see dga_test.go), so 0.35 separates the
// groups without leaning on the exact table contents.
const dgaIrregularBigramRatio = 0.35

// dgaSoftEntropyThreshold extends DGA suspicion below the operator's entropy
// threshold when the letter pairs are wildly irregular: entropy alone misses
// low-cardinality DGAs, but a long label that no English reader can pronounce
// is worth the same suspicion. Only fires on labels that already pass every
// other FP guard in the entropy gate.
const dgaSoftEntropyFactor = 0.85

// isDGASuspected combines the two dimensions. The FP guards (shared hosting,
// keywords, brand suffixes, hyphenated labels) are applied by the caller
// before this runs.
func isDGASuspected(mainLabel string, entropyThreshold float64) bool {
	if len(mainLabel) < 10 {
		return false
	}
	entropy := ShannonEntropy(mainLabel)
	ratio := englishBigramRatio(mainLabel)
	if entropy > entropyThreshold {
		return ratio < dgaIrregularBigramRatio
	}
	if entropy > entropyThreshold*dgaSoftEntropyFactor {
		// Wildly irregular pairs plus near-threshold entropy: catch DGAs with
		// small character alphabets whose frequency entropy stays low.
		return ratio < dgaIrregularBigramRatio/2
	}
	return false
}

// englishBigrams is the set of frequent English letter pairs used by
// englishBigramRatio. Drawn from standard bigram frequency tables; only
// pairs frequent enough to appear in most words are included, so the ratio
// is a conservative measure of English-likeness.
var englishBigrams = map[string]bool{
	"ab": true, "ac": true, "ad": true, "ag": true, "al": true, "am": true,
	"an": true, "ap": true, "ar": true, "as": true, "at": true, "av": true,
	"ay": true, "ba": true, "be": true, "bi": true, "bl": true, "bo": true,
	"br": true, "bu": true, "ca": true, "ce": true, "ch": true, "ci": true,
	"cl": true, "co": true, "cr": true, "cu": true, "da": true, "de": true,
	"di": true, "do": true, "dr": true, "ea": true, "ec": true, "ed": true,
	"ee": true, "ef": true, "el": true, "em": true, "en": true, "eo": true,
	"er": true, "es": true, "et": true, "ev": true, "ex": true, "fe": true,
	"fi": true, "fl": true, "fo": true, "fr": true, "ga": true, "ge": true,
	"gh": true, "gi": true, "gl": true, "go": true, "gr": true, "gu": true,
	"ha": true, "he": true, "hi": true, "ho": true, "ia": true, "ic": true,
	"id": true, "ie": true, "if": true, "ig": true, "il": true, "im": true,
	"in": true, "io": true, "is": true, "it": true, "iv": true, "jo": true,
	"ki": true, "la": true, "le": true, "li": true, "lo": true, "ma": true,
	"me": true, "mi": true, "mo": true, "mu": true, "na": true, "nd": true,
	"ne": true, "ng": true, "ni": true, "no": true, "ns": true, "nt": true,
	"nu": true, "oa": true, "ob": true, "oc": true, "od": true, "oe": true,
	"of": true, "og": true, "oi": true, "ol": true, "om": true, "on": true,
	"oo": true, "op": true, "or": true, "os": true, "ot": true, "ou": true,
	"ov": true, "ow": true, "pa": true, "pe": true, "ph": true, "pi": true,
	"pl": true, "po": true, "pr": true, "qu": true, "ra": true, "re": true,
	"ri": true, "ro": true, "rs": true, "rt": true, "ru": true, "ry": true,
	"sa": true, "se": true, "sh": true, "si": true, "so": true, "sp": true,
	"ss": true, "st": true, "su": true, "ta": true, "te": true, "th": true,
	"ti": true, "to": true, "tr": true, "tu": true, "ua": true, "ub": true,
	"uc": true, "ul": true, "um": true, "un": true, "up": true, "ur": true,
	"us": true, "ut": true, "va": true, "ve": true, "vi": true, "vo": true,
	"wa": true, "we": true, "wh": true, "wi": true, "wo": true, "ya": true,
	"yo": true, "za": true,
	// Brandable-name pairs that keep short coined words above the threshold.
	"ck": true, "eb": true, "ft": true, "fy": true, "ke": true,
	"ky": true, "ny": true, "ok": true,
	"rk": true, "zy": true,
}
