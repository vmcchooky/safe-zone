package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"safe-zone/internal/store"
)

func TestAlertTaskName(t *testing.T) {
	task := NewAlertTask(nil, AlertConfig{})
	if task.Name() != "alert" {
		t.Errorf("expected name 'alert', got %q", task.Name())
	}
}

func TestAlertTaskNoWebhookURL(t *testing.T) {
	task := NewAlertTask(nil, AlertConfig{WebhookURL: ""})
	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error with no webhook URL, got %v", err)
	}
}

func TestAlertTaskNilStore(t *testing.T) {
	task := NewAlertTask(nil, AlertConfig{WebhookURL: "https://example.com/webhook"})
	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error with nil store, got %v", err)
	}
}

func TestAlertTaskNoEvents(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer db.Close()

	task := NewAlertTask(db, AlertConfig{
		WebhookURL: "https://example.com/webhook",
		MinEvents:  1,
	})
	task.mu.Lock()
	task.lastAlert = time.Now().Add(-1 * time.Hour)
	task.mu.Unlock()

	err = task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error with no events, got %v", err)
	}
}

func TestAlertTaskSendsWebhook(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer db.Close()

	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "evil.test", `{"score":90}`)
	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "bad.test", `{"score":85}`)

	time.Sleep(50 * time.Millisecond)

	var received AlertPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{
		WebhookURL: server.URL,
		MinEvents:  1,
	})

	task.mu.Lock()
	task.lastAlert = time.Now().Add(-24 * time.Hour)
	task.mu.Unlock()

	err = task.Run(context.Background())
	if err != nil {
		t.Fatalf("alert run error: %v", err)
	}

	if received.EventType != "safe_zone_agent_alert" {
		t.Errorf("expected event_type 'safe_zone_agent_alert', got %q", received.EventType)
	}
	if len(received.Events) != 2 {
		t.Errorf("expected 2 events in payload, got %d", len(received.Events))
	}
}

func TestAlertTaskWebhookError(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer db.Close()

	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "evil.test", `{}`)
	time.Sleep(50 * time.Millisecond)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	task := NewAlertTask(db, AlertConfig{
		WebhookURL: server.URL,
		MinEvents:  1,
	})
	task.mu.Lock()
	task.lastAlert = time.Now().Add(-24 * time.Hour)
	task.mu.Unlock()

	err = task.Run(context.Background())
	if err == nil {
		t.Error("expected error for webhook failure")
	}
}

func TestIsDiscordWebhook(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://discord.com/api/webhooks/123/abc", true},
		{"https://discordapp.com/api/webhooks/123/abc", true},
		{"https://example.com/webhook", false},
		{"https://slack.com/webhook", false},
	}

	for _, tt := range tests {
		got := isDiscordWebhook(tt.url)
		if got != tt.want {
			t.Errorf("isDiscordWebhook(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestBuildDiscordPayload(t *testing.T) {
	payload := AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "safe_zone_agent_alert",
		Summary:   "Test alert",
		Events: []AlertEvent{
			{Type: "auto_block", Domain: "evil.test"},
		},
	}

	body, err := buildDiscordPayload(payload)
	if err != nil {
		t.Fatalf("build discord payload: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal discord payload: %v", err)
	}

	embeds, ok := parsed["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("expected embeds array in discord payload")
	}
}

func TestDetectVietnamBrandSpoof(t *testing.T) {
	tests := []struct {
		domain           string
		expectedSpoof    bool
		expectedBrand    string
		expectedCategory string
	}{
		{"vietcombbank.com.vn", true, "vietcombank", "Ngân hàng Việt Nam"},
		{"chinhphuu.vn", true, "chinhphu", "Cơ quan Nhà nước Việt Nam"},
		{"vietcombank-login-secure.xyz", true, "vietcombank", "Ngân hàng Việt Nam"},
		{"secure-chinhphu-gov.top", true, "chinhphu", "Cơ quan Nhà nước Việt Nam"},
		{"google-verify.com", false, "", ""}, // Google is not a VN brand (though it is a trusted brand)
		{"normaldomain.com", false, "", ""},
	}

	for _, tc := range tests {
		res, got := detectVietnamBrandSpoof(tc.domain)
		if got != tc.expectedSpoof {
			t.Errorf("detectVietnamBrandSpoof(%q) = %v, expected %v", tc.domain, got, tc.expectedSpoof)
		}
		if got {
			if res.BrandName != tc.expectedBrand {
				t.Errorf("detectVietnamBrandSpoof(%q) brand = %q, expected %q", tc.domain, res.BrandName, tc.expectedBrand)
			}
			if res.Category != tc.expectedCategory {
				t.Errorf("detectVietnamBrandSpoof(%q) category = %q, expected %q", tc.domain, res.Category, tc.expectedCategory)
			}
		}
	}
}

func TestAlertTaskAdvancedChannels(t *testing.T) {
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer db.Close()

	// Seed a critical Vietnam bank spoofing event
	_ = db.RecordAgentEvent(context.Background(), "audit", "auto_block", "vietcombbank.com.vn", `{"score":95}`)
	time.Sleep(50 * time.Millisecond)

	var mu sync.Mutex
	var tgReceived map[string]any
	var slackReceived map[string]any

	tgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var temp map[string]any
		_ = json.NewDecoder(r.Body).Decode(&temp)
		mu.Lock()
		tgReceived = temp
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer tgServer.Close()

	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var temp map[string]any
		_ = json.NewDecoder(r.Body).Decode(&temp)
		mu.Lock()
		slackReceived = temp
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	// Khởi tạo config với Telegram và Slack
	cfg := AlertConfig{
		MinEvents:       1,
		TelegramEnabled: true,
		TelegramToken:   "dummy_token",
		TelegramChatID:  "dummy_chat_id",
		SlackEnabled:    true,
		SlackWebhookURL: slackServer.URL,
	}

	task := NewAlertTask(db, cfg)

	task.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.telegram.org" {
			req.URL.Scheme = "http"
			req.URL.Host = rxtHost(tgServer.URL)
		} else if req.URL.Host == rxtHost(slackServer.URL) {
			req.URL.Scheme = "http"
			req.URL.Host = rxtHost(slackServer.URL)
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	task.mu.Lock()
	task.lastAlert = time.Now().Add(-24 * time.Hour)
	task.mu.Unlock()

	err = task.Run(context.Background())
	if err != nil {
		t.Fatalf("alert run error: %v", err)
	}

	// Đợi các goroutines gửi tin nhắn hoàn tất
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	receivedSlack := slackReceived
	receivedTG := tgReceived
	mu.Unlock()

	// Verify Slack payload received
	if receivedSlack == nil {
		t.Error("Slack alert was not received")
	} else {
		text, _ := receivedSlack["text"].(string)
		if !contains(text, "vietcombbank.com.vn") || !contains(text, "Ngân hàng Việt Nam") {
			t.Errorf("Slack payload doesn't contain spoof details: %q", text)
		}
	}

	// Verify Telegram payload received
	if receivedTG == nil {
		t.Error("Telegram alert was not received")
	} else {
		text, _ := receivedTG["text"].(string)
		if !contains(text, "vietcombbank.com.vn") || !contains(text, "Ngân hàng Việt Nam") {
			t.Errorf("Telegram payload doesn't contain spoof details: %q", text)
		}
	}
}

func TestSendSMTPRejectsPlaintextSubmission(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 test smtp\r\n250 AUTH PLAIN\r\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = sendSMTP(ctx, listener.Addr().String(), "127.0.0.1", 587, nil, "from@example.test", []string{"to@example.test"}, []byte("test"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS rejection, got %v", err)
	}
	<-done
}

func TestSendTelegramEscapesHTMLSensitiveFields(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode telegram payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := NewAlertTask(nil, AlertConfig{
		TelegramEnabled: true,
		TelegramToken:   "dummy_token",
		TelegramChatID:  "dummy_chat_id",
	})
	task.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.telegram.org" {
			req.URL.Scheme = "http"
			req.URL.Host = rxtHost(server.URL)
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	err := task.sendTelegram(context.Background(), []SpoofResult{{
		Domain:         `<b>evil</b>.example.com`,
		Category:       `phish & grab`,
		BrandName:      `<img src=x onerror=alert(1)>`,
		OfficialDomain: `trusted.example.com" onclick="alert(1)`,
		Reason:         `reason with <script>alert(1)</script>`,
	}})
	if err != nil {
		t.Fatalf("sendTelegram returned error: %v", err)
	}

	text, _ := received["text"].(string)
	if !strings.Contains(text, "<code>&lt;b&gt;evil&lt;/b&gt;.example.com</code>") {
		t.Fatalf("expected escaped domain in telegram payload, got %q", text)
	}
	if strings.Contains(text, `<code><b>evil</b>.example.com</code>`) {
		t.Fatalf("expected raw HTML domain to be escaped, got %q", text)
	}
	if !strings.Contains(text, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatalf("expected escaped brand name, got %q", text)
	}
	if !strings.Contains(text, `https://trusted.example.com&#34; onclick=&#34;alert(1)`) {
		t.Fatalf("expected escaped official domain in href, got %q", text)
	}
	if !strings.Contains(text, "reason with &lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("expected escaped reason, got %q", text)
	}
}

func TestNewAlertTaskDefaultsSMTPUsernameToFrom(t *testing.T) {
	task := NewAlertTask(nil, AlertConfig{
		EmailFrom: "sender@example.test",
	})
	if task.config.EmailSMTPUsername != "sender@example.test" {
		t.Fatalf("expected SMTP username fallback, got %q", task.config.EmailSMTPUsername)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func rxtHost(urlStr string) string {
	if len(urlStr) > 7 && urlStr[:7] == "http://" {
		return urlStr[7:]
	}
	return urlStr
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
