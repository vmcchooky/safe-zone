package analysis

import "testing"

func BenchmarkLevenshteinDistance(b *testing.B) {
	s1 := "google"
	s2 := "go0g1e"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LevenshteinDistance(s1, s2)
	}
}

func BenchmarkWeightedLevenshteinDistance(b *testing.B) {
	s1 := "facebook"
	s2 := "faceb0ok"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WeightedLevenshteinDistance(s1, s2)
	}
}

func BenchmarkToSkeleton(b *testing.B) {
	s := "аpple" // 'a' is cyrillic
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ToSkeleton(s)
	}
}
