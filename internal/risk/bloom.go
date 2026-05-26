package risk

import (
	"hash/fnv"
	"math"
)

// BloomFilter is a memory-efficient probabilistic data structure for set membership.
type BloomFilter struct {
	m    uint64 // number of bits
	k    uint64 // number of hash functions
	bits []byte // bit array represented as a byte slice
}

// NewBloomFilter calculates the optimal number of bits and hash functions,
// then returns an empty Bloom Filter configured for n elements and p false positive rate.
func NewBloomFilter(n int, p float64) *BloomFilter {
	if n <= 0 {
		n = 1000
	}
	if p <= 0 || p >= 1 {
		p = 0.01
	}

	// Calculate optimal m (bits): m = -(n * ln(p)) / (ln(2)^2)
	mFloat := -float64(n) * math.Log(p) / math.Pow(math.Log(2), 2)
	m := uint64(math.Ceil(mFloat))

	// Align m to a multiple of 8 so it maps cleanly to bytes
	if m%8 != 0 {
		m = ((m / 8) + 1) * 8
	}

	// Calculate optimal k (hash functions): k = (m/n) * ln(2)
	kFloat := float64(m) / float64(n) * math.Log(2)
	k := uint64(math.Round(kFloat))
	if k < 1 {
		k = 1
	}

	return &BloomFilter{
		m:    m,
		k:    k,
		bits: make([]byte, m/8),
	}
}

// hash generates two 32-bit hashes from a single 64-bit FNV-1a hash
// using Kirsch-Mitzenmacher optimization.
func (bf *BloomFilter) hash(data string) (uint32, uint32) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(data))
	sum := h.Sum64()
	h1 := uint32(sum & 0xffffffff)
	h2 := uint32(sum >> 32)
	return h1, h2
}

// Add inserts a string element into the Bloom Filter.
func (bf *BloomFilter) Add(data string) {
	if bf == nil || len(bf.bits) == 0 {
		return
	}
	h1, h2 := bf.hash(data)
	for i := uint64(0); i < bf.k; i++ {
		// Double hashing optimization: index = (h1 + i * h2) % m
		idx := (uint64(h1) + i*uint64(h2)) % bf.m

		byteIdx := idx / 8
		bitIdx := idx % 8
		bf.bits[byteIdx] |= (1 << bitIdx)
	}
}

// Test checks if a string element might be in the Bloom Filter.
// If it returns false, the element is definitely NOT in the set.
// If it returns true, the element MIGHT be in the set (subject to false positive rate).
func (bf *BloomFilter) Test(data string) bool {
	if bf == nil || len(bf.bits) == 0 {
		return false
	}
	h1, h2 := bf.hash(data)
	for i := uint64(0); i < bf.k; i++ {
		idx := (uint64(h1) + i*uint64(h2)) % bf.m

		byteIdx := idx / 8
		bitIdx := idx % 8
		if (bf.bits[byteIdx] & (1 << bitIdx)) == 0 {
			return false
		}
	}
	return true
}

// Info returns the configured bits (m) and hash functions (k) for inspection.
func (bf *BloomFilter) Info() (uint64, uint64) {
	return bf.m, bf.k
}
