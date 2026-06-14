import re

with open("internal/risk/service_test.go", "r", encoding="utf-8") as f:
    content = f.read()

new_test = """func TestAnalyzeNegativeCachingOnAITimeout(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()
	redisClient := cache.NewRedis(redisServer.Addr(), "", 0)

	aiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer aiServer.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	storeDB, err := store.New(dbPath, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer storeDB.Close()

	cfg := config.DefaultAnalysisConfig()
	cfg.HyphenCountThreshold = 1
	cfg.HyphenScore = 50
	if err := storeDB.SetAnalysisConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		Redis:          redisClient,
		RedisTimeout:   100 * time.Millisecond,
		TTLSuspicious:  time.Hour,
		TTLAllowed:     time.Hour,
		TTLBlocked:     time.Hour,
		Store:          storeDB,
		AnalysisConfig: cfg,
		OllamaBaseURL:  aiServer.URL,
		AIProvider:     "ollama",
		OllamaModel:    "llama3",
	})
	defer func() {
	    // ignore close errors in defer to prevent double-close panics
	    _ = service.Close()
	}()

	ctx := context.Background()
	result := service.Analyze(ctx, "suspicious-timeout.com", ClientInfo{})
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected verdict suspicious, got %s, score=%d", result.Verdict, result.Score)
	}

	ttl := redisServer.TTL("safe-zone:analysis:suspicious-timeout.com")
	if ttl == 0 {
		t.Fatal("expected cache TTL to be set")
	}
	if ttl > 3*time.Minute {
		t.Fatalf("expected negative cache TTL (< 3m), got %v", ttl)
	}
}"""

content = re.sub(r'func TestAnalyzeNegativeCachingOnAITimeout.*?^}$', new_test, content, flags=re.MULTILINE | re.DOTALL)

with open("internal/risk/service_test.go", "w", encoding="utf-8") as f:
    f.write(content)
