package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
	"safe-zone/internal/store"
)

// AlertConfig holds configuration for the webhook and advanced multi-channel alert tasks.
type AlertConfig struct {
	WebhookURL string
	MinEvents  int
	Timeout    time.Duration

	// Telegram settings
	TelegramEnabled bool
	TelegramToken   string
	TelegramChatID  string

	// Slack settings
	SlackEnabled    bool
	SlackWebhookURL string

	// Email (SMTP) settings
	EmailEnabled      bool
	EmailSMTPHost     string
	EmailSMTPPort     int
	EmailSMTPUsername string
	EmailFrom         string
	EmailPassword     string
	EmailTo           string
}

// alertCursorState is the persisted alert position over the agent event log.
// The keyset is (created_at, id) in SQLite datetime format, matching
// store.QueryAgentEventsPage. Version guards future schema changes.
type alertCursorState struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	ID        int64  `json:"id"`
}

const (
	alertCursorVersion    = 1
	alertCursorConfigKey  = "agent_alert_cursor"
	alertEventPageSize    = 100
	alertMaxPagesPerCycle = 20
	sqliteDatetimeLayout  = "2006-01-02 15:04:05"
)

// AlertTask sends webhook notifications when significant agent events occur
// (auto-blocks, feed sync errors).
//
// Delivery contract: at-least-once per event. The cursor only advances past
// events whose page was delivered successfully through every configured
// channel; a failed page is retried on the next cycle, so operators may see
// duplicate alerts after a partial failure (correlation IDs in the
// alert_sent/alert_failed events identify replays). The cursor is persisted
// so a restart does not skip events raised during downtime.
type AlertTask struct {
	store  *store.DB
	config AlertConfig
	http   *http.Client

	mu     sync.Mutex
	cursor alertCursorState
}

// AlertPayload is the JSON structure sent to the webhook.
type AlertPayload struct {
	Timestamp string       `json:"timestamp"`
	EventType string       `json:"event_type"`
	Summary   string       `json:"summary"`
	Events    []AlertEvent `json:"events"`
}

// AlertEvent is a single event within a webhook payload.
type AlertEvent struct {
	Type      string `json:"type"`
	Domain    string `json:"domain,omitempty"`
	Details   string `json:"details,omitempty"`
	CreatedAt string `json:"created_at"`
}

// SpoofResult represents a detected critical brand spoofing event.
type SpoofResult struct {
	Domain         string
	IsSpoof        bool
	BrandName      string
	OfficialDomain string
	Category       string // "Ngân hàng Việt Nam" hoặc "Cơ quan Nhà nước Việt Nam"
	Reason         string
}

// NewAlertTask creates an AlertTask with the given configuration.
func NewAlertTask(db *store.DB, cfg AlertConfig) *AlertTask {
	if cfg.MinEvents <= 0 {
		cfg.MinEvents = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.EmailSMTPUsername == "" {
		cfg.EmailSMTPUsername = cfg.EmailFrom
	}
	task := &AlertTask{
		store:  db,
		config: cfg,
		http:   netguard.NewHTTPClient(nil, cfg.Timeout, false),
		cursor: alertCursorState{
			Version:   alertCursorVersion,
			CreatedAt: time.Now().UTC().Format(sqliteDatetimeLayout),
		},
	}
	if db != nil && db.Enabled() {
		task.loadCursor(context.Background())
	}
	return task
}

// loadCursor restores the persisted alert position. Any failure falls back to
// the construction-time cursor, which can replay recent alerts
// (at-least-once) but never silently skips a backlog.
func (t *AlertTask) loadCursor(ctx context.Context) {
	raw, err := t.store.GetSystemConfig(ctx, alertCursorConfigKey)
	if err != nil {
		logjson.Warn("alert cursor load failed; starting from startup", map[string]any{
			"service": "core-api",
			"task":    "alert",
			"error":   err.Error(),
		})
		return
	}
	if raw == "" {
		return
	}
	var cursor alertCursorState
	if err := json.Unmarshal([]byte(raw), &cursor); err != nil || cursor.Version != alertCursorVersion || cursor.CreatedAt == "" {
		logjson.Warn("alert cursor unreadable; starting from startup", map[string]any{
			"service": "core-api",
			"task":    "alert",
		})
		return
	}
	t.cursor = cursor
}

func (t *AlertTask) snapshotCursor() alertCursorState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cursor
}

func (t *AlertTask) Name() string { return "alert" }

// advanceCursor moves the keyset forward and persists it. A persistence
// failure keeps the in-memory progress (this process will not resend) and is
// logged; a restart may replay from the last persisted position.
func (t *AlertTask) advanceCursor(ctx context.Context, last store.AgentEvent) {
	cursor := alertCursorState{Version: alertCursorVersion, CreatedAt: last.CreatedAt, ID: last.ID}
	t.mu.Lock()
	t.cursor = cursor
	t.mu.Unlock()

	if t.store == nil || !t.store.Enabled() {
		return
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		logjson.Warn("alert cursor encode failed; restart may replay a page", map[string]any{
			"service": "core-api",
			"task":    "alert",
			"error":   err.Error(),
		})
		return
	}
	if err := t.store.SetSystemConfig(ctx, alertCursorConfigKey, string(encoded)); err != nil {
		logjson.Warn("alert cursor persist failed; restart may replay a page", map[string]any{
			"service": "core-api",
			"task":    "alert",
			"error":   err.Error(),
		})
	}
}

func (t *AlertTask) Run(ctx context.Context) error {
	webhookURL := t.config.WebhookURL
	if t.store != nil && t.store.Enabled() {
		if customURL, err := t.store.GetSystemConfig(ctx, "agent_webhook_url"); err == nil && customURL != "" {
			webhookURL = customURL
		}
	}

	// Kiểm tra xem có cấu hình bất kỳ kênh cảnh báo nào không
	hasWebhook := strings.TrimSpace(webhookURL) != ""
	hasTelegram := t.config.TelegramEnabled
	hasSlack := t.config.SlackEnabled
	hasEmail := t.config.EmailEnabled

	if !hasWebhook && !hasTelegram && !hasSlack && !hasEmail {
		return nil // no alert channels configured
	}

	if t.store == nil || !t.store.Enabled() {
		return nil
	}

	runID := correlation.RunID(ctx)
	deliveredPages := 0
	deliveredEvents := 0

	// MinEvents gates on the whole pending backlog, not the first page, so a
	// threshold above the page size still triggers once enough events are
	// pending instead of starving forever.
	cursor := t.snapshotCursor()
	pending, err := t.store.CountAgentEventsAfter(ctx, cursor.CreatedAt, cursor.ID, []string{
		"auto_block", "feed_error",
	})
	if err != nil {
		// Cursor stays put: the pending backlog is retried next cycle.
		return fmt.Errorf("count pending agent events: %w", err)
	}
	if pending < int64(t.config.MinEvents) {
		return nil // not enough pending events to trigger an alert yet
	}

	for page := 0; page < alertMaxPagesPerCycle; page++ {
		cursor := t.snapshotCursor()
		events, err := t.store.QueryAgentEventsPage(ctx, cursor.CreatedAt, cursor.ID, []string{
			"auto_block", "feed_error",
		}, alertEventPageSize)
		if err != nil {
			// Cursor stays put: the pending backlog is retried next cycle.
			return fmt.Errorf("query agent events page: %w", err)
		}
		if len(events) == 0 {
			break
		}

		// Build payload and detect critical brand spoofing for this page.
		alertEvents := make([]AlertEvent, len(events))
		var criticalEvents []SpoofResult
		autoBlocks := 0
		feedErrors := 0
		for i, e := range events {
			alertEvents[i] = AlertEvent{
				Type:      e.EventType,
				Domain:    e.Domain,
				Details:   e.Details,
				CreatedAt: e.CreatedAt,
			}
			switch e.EventType {
			case "auto_block":
				autoBlocks++
				// Detect critical Vietnam brand spoofing
				if spoof, yes := detectVietnamBrandSpoof(e.Domain); yes {
					criticalEvents = append(criticalEvents, spoof)
				}
			case "feed_error":
				feedErrors++
			}
		}

		var summaryParts []string
		if autoBlocks > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("%d domains auto-blocked", autoBlocks))
		}
		if feedErrors > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("%d feed sync errors", feedErrors))
		}

		payload := AlertPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "safe_zone_agent_alert",
			Summary:   "Safe Zone: " + strings.Join(summaryParts, ", "),
			Events:    alertEvents,
		}

		// Deliver through every configured channel and wait for all of them:
		// no detached goroutine may influence whether the page counts as sent.
		failures := t.deliverPage(ctx, webhookURL, payload, criticalEvents, hasWebhook, hasTelegram, hasSlack, hasEmail)
		lastEvent := events[len(events)-1]
		if len(failures) > 0 {
			// The page was not delivered everywhere: the cursor stays on it
			// so the next cycle replays the whole page (at-least-once).
			_ = t.store.RecordAgentEvent(ctx, "alert", "alert_failed", "",
				fmt.Sprintf(`{"run_id":%q,"last_event_id":%d,"failures":[%s]}`, runID, lastEvent.ID, joinQuoted(failures)))
			return fmt.Errorf("send alert failures: %s", strings.Join(failures, "; "))
		}

		t.advanceCursor(ctx, lastEvent)
		deliveredPages++
		deliveredEvents += len(events)

		_ = t.store.RecordAgentEvent(ctx, "alert", "alert_sent", "",
			fmt.Sprintf(`{"run_id":%q,"page":%d,"events_count":%d,"last_event_id":%d}`, runID, deliveredPages, len(events), lastEvent.ID))

		if len(events) < alertEventPageSize {
			break
		}
	}

	if deliveredPages == 0 {
		return nil
	}

	logjson.Info("agent alert triggered", correlation.Fields(ctx, map[string]any{
		"service": "core-api",
		"task":    "alert",
		"events":  deliveredEvents,
		"pages":   deliveredPages,
	}))

	return nil
}

// deliverPage sends one page through all configured channels in parallel and
// blocks until every send has finished, collecting per-channel failures.
func (t *AlertTask) deliverPage(ctx context.Context, webhookURL string, payload AlertPayload, criticalEvents []SpoofResult, hasWebhook, hasTelegram, hasSlack, hasEmail bool) []string {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []string
	)
	record := func(channel, taskName string, err error) {
		if err == nil {
			return
		}
		logjson.Error(channel+" alert failed", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    taskName,
			"error":   err.Error(),
		}))
		mu.Lock()
		failures = append(failures, fmt.Sprintf("%s: %v", channel, err))
		mu.Unlock()
	}
	channelCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, t.config.Timeout)
	}

	if hasWebhook {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendCtx, cancel := channelCtx()
			defer cancel()
			record("webhook", "alert", t.sendWebhook(sendCtx, webhookURL, payload))
		}()
	}
	if len(criticalEvents) > 0 && hasTelegram {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendCtx, cancel := channelCtx()
			defer cancel()
			record("telegram", "alert", t.sendTelegram(sendCtx, criticalEvents))
		}()
	}
	if len(criticalEvents) > 0 && hasSlack {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendCtx, cancel := channelCtx()
			defer cancel()
			record("slack", "alert", t.sendSlack(sendCtx, criticalEvents))
		}()
	}
	if len(criticalEvents) > 0 && hasEmail {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendCtx, cancel := channelCtx()
			defer cancel()
			record("email", "alert", t.sendEmail(sendCtx, criticalEvents))
		}()
	}

	wg.Wait()
	return failures
}

func joinQuoted(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ",")
}

func (t *AlertTask) sendWebhook(ctx context.Context, webhookURL string, payload AlertPayload) error {
	var body []byte
	var err error

	if isDiscordWebhook(webhookURL) {
		body, err = buildDiscordPayload(payload)
	} else {
		body, err = json.Marshal(payload)
	}
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}

	return nil
}

func (t *AlertTask) sendTelegram(ctx context.Context, criticalEvents []SpoofResult) error {
	token := t.config.TelegramToken
	chatID := t.config.TelegramChatID
	if token == "" || chatID == "" {
		return fmt.Errorf("invalid telegram configuration")
	}

	var msg strings.Builder
	msg.WriteString("⚠️ <b>[CẢNH BÁO ĐE DỌA NGHIÊM TRỌNG]</b> ⚠️\n")
	msg.WriteString("---------------------------------------------\n")
	msg.WriteString("🛡️ <b>HỆ THỐNG AN NINH SAFE ROAD</b>\n")
	msg.WriteString("---------------------------------------------\n")
	msg.WriteString("🚨 <b>Phát hiện Website giả mạo Ngân hàng / Cơ quan Nhà nước!</b>\n\n")

	for _, e := range criticalEvents {
		domain := html.EscapeString(e.Domain)
		category := html.EscapeString(e.Category)
		brand := html.EscapeString(e.BrandName)
		officialDomain := html.EscapeString(e.OfficialDomain)
		reason := html.EscapeString(e.Reason)

		fmt.Fprintf(&msg, "📌 <b>Tên miền vi phạm:</b> <code>%s</code>\n", domain)
		fmt.Fprintf(&msg, "🏷️ <b>Phân loại:</b> %s\n", category)
		fmt.Fprintf(&msg, "🏢 <b>Thương hiệu bị mạo danh:</b> <b>%s</b>\n", brand)
		fmt.Fprintf(&msg, "🌐 <b>Tên miền chính thức:</b> <a href=\"https://%s\">%s</a>\n", officialDomain, officialDomain)
		fmt.Fprintf(&msg, "📝 <b>Lý do:</b> <i>%s</i>\n\n", reason)
	}
	msg.WriteString("---------------------------------------------\n")
	msg.WriteString("🔒 <i>Safe Zone - Bảo vệ người dân Việt Nam trước lừa đảo công nghệ cao.</i>")

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       msg.String(),
		"parse_mode": "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("telegram http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned HTTP %d", resp.StatusCode)
	}

	return nil
}

func (t *AlertTask) sendSlack(ctx context.Context, criticalEvents []SpoofResult) error {
	webhookURL := t.config.SlackWebhookURL
	if webhookURL == "" {
		return fmt.Errorf("invalid slack configuration")
	}

	var msg strings.Builder
	msg.WriteString("*⚠️ [CẢNH BÁO ĐE DỌA NGHIÊM TRỌNG] ⚠️*\n")
	msg.WriteString("=============================================\n")
	msg.WriteString("*🛡️ HỆ THỐNG AN NINH SAFE ROAD*\n")
	msg.WriteString("=============================================\n")
	msg.WriteString("*🚨 Phát hiện Website giả mạo Ngân hàng / Cơ quan Nhà nước!*\n\n")

	for _, e := range criticalEvents {
		fmt.Fprintf(&msg, "• *Tên miền vi phạm:* `%s`\n", e.Domain)
		fmt.Fprintf(&msg, "• *Phân loại:* _%s_\n", e.Category)
		fmt.Fprintf(&msg, "• *Thương hiệu bị mạo danh:* *%s*\n", e.BrandName)
		fmt.Fprintf(&msg, "• *Tên miền chính thức:* <https://%s|%s>\n", e.OfficialDomain, e.OfficialDomain)
		fmt.Fprintf(&msg, "• *Lý do:* _%s_\n\n", e.Reason)
	}
	msg.WriteString("=============================================\n")
	msg.WriteString("_🔒 Safe Zone - Bảo vệ người dân Việt Nam trước lừa đảo công nghệ cao._")

	payload := map[string]any{
		"text": msg.String(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("slack http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}

	return nil
}

func (t *AlertTask) sendEmail(ctx context.Context, criticalEvents []SpoofResult) error {
	host := t.config.EmailSMTPHost
	port := t.config.EmailSMTPPort
	from := t.config.EmailFrom
	username := t.config.EmailSMTPUsername
	password := t.config.EmailPassword
	to := t.config.EmailTo

	if host == "" || port <= 0 || from == "" || to == "" || username == "" || password == "" {
		return fmt.Errorf("invalid smtp configuration")
	}

	var htmlBody strings.Builder
	htmlBody.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f6f9; color: #333333; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border: 1px solid #e1e8ed; }
        .header { background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); color: #ffffff; padding: 30px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 24px; font-weight: bold; letter-spacing: 0.5px; }
        .content { padding: 30px 25px; line-height: 1.6; }
        .badge { display: inline-block; background-color: #ffeef0; color: #ff334b; font-weight: bold; padding: 6px 12px; border-radius: 20px; font-size: 13px; margin-bottom: 20px; border: 1px solid #ffd1d6; }
        .item-box { background: #f8fafc; border-left: 4px solid #ff334b; padding: 15px 20px; border-radius: 0 8px 8px 0; margin-bottom: 20px; }
        .field { font-size: 14px; margin-bottom: 8px; }
        .field-label { font-weight: bold; color: #64748b; }
        .field-value { color: #1e293b; font-family: monospace; font-size: 15px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SAFE ROAD AN NINH CẢNH BÁO</h1>
        </div>
        <div class="content">
            <div class="badge">🚨 PHÁT HIỆN GIẢ MẠO CỰC KỲ NGHIÊM TRỌNG</div>
            <p>Hệ thống Safe Zone đã phát hiện website giả mạo các cơ quan tổ chức hoặc ngân hàng tại Việt Nam và thực hiện tự động chặn đứng (auto-block):</p>`)

	for _, e := range criticalEvents {
		fmt.Fprintf(&htmlBody, `
            <div class="item-box">
                <div class="field"><span class="field-label">Tên miền giả mạo:</span> <span class="field-value">%s</span></div>
                <div class="field"><span class="field-label">Phân loại:</span> <strong>%s</strong></div>
                <div class="field"><span class="field-label">Thương hiệu bị nhắm tới:</span> <strong>%s</strong></div>
                <div class="field"><span class="field-label">Tên miền chính chủ:</span> <a href="https://%s" style="color: #ff334b; font-weight: bold;">%s</a></div>
                <div class="field"><span class="field-label">Lý do phát hiện:</span> <span class="field-value">%s</span></div>
            </div>`,
			html.EscapeString(e.Domain),
			html.EscapeString(e.Category),
			html.EscapeString(e.BrandName),
			html.EscapeString(e.OfficialDomain),
			html.EscapeString(e.OfficialDomain),
			html.EscapeString(e.Reason))
	}

	htmlBody.WriteString(`
            <p>Vui lòng kiểm tra Dashboard quản trị để biết thêm chi tiết và cập nhật các biện pháp ứng phó cần thiết.</p>
        </div>
        <div class="footer">
            🔒 Safe Zone - Đồng hành cùng nhân dân Việt Nam chống tội phạm công nghệ cao.
        </div>
    </div>
</body>
</html>`)

	subject := fmt.Sprintf("Subject: 🛡️ [SAFE ROAD CRITICAL ALERT] Phát hiện %d Website giả mạo ngân hàng/cơ quan nhà nước\n", len(criticalEvents))
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	msg := []byte(subject + mime + htmlBody.String())

	auth := smtp.PlainAuth("", username, password, host)
	addr := fmt.Sprintf("%s:%d", host, port)

	if err := sendSMTP(ctx, addr, host, port, auth, from, []string{to}, msg); err != nil {
		return fmt.Errorf("smtp send mail: %w", err)
	}

	return nil
}

func sendSMTP(ctx context.Context, addr, host string, port int, auth smtp.Auth, from string, to []string, msg []byte) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	var (
		conn net.Conn
		err  error
	)
	switch port {
	case 465:
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return dialErr
		}
		tlsConn := tls.Client(rawConn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := setConnDeadline(ctx, tlsConn); err != nil {
			_ = tlsConn.Close()
			return err
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tlsConn.Close()
			return err
		}
		conn = tlsConn
	case 587:
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported smtp port %d: use 465 implicit TLS or 587 STARTTLS", port)
	}
	defer func() { _ = conn.Close() }()
	_ = setConnDeadline(ctx, conn)

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if port == 587 {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not advertise STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
		_ = setConnDeadline(ctx, conn)
	}

	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(msg); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func setConnDeadline(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(deadline)
	}
	return conn.SetDeadline(time.Now().Add(10 * time.Second))
}

func detectVietnamBrandSpoof(domain string) (SpoofResult, bool) {
	isSpoof, reason, _ := analysis.CheckBrandSpoofing(domain, 30)
	if !isSpoof {
		return SpoofResult{}, false
	}

	// Danh sách Cơ quan Nhà nước Việt Nam
	govBrands := map[string]string{
		"chinhphu":     "chinhphu.vn",
		"bocongan":     "bocongan.gov.vn",
		"baohiemxahoi": "baohiemxahoi.gov.vn",
		"vtv":          "vtv.vn",
	}

	// Danh sách Ngân hàng Việt Nam
	bankBrands := map[string]string{
		"vietcombank": "vietcombank.com.vn",
		"techcombank": "techcombank.com.vn",
		"bidv":        "bidv.com.vn",
		"vietinbank":  "vietinbank.vn",
		"mbbank":      "mbbank.com.vn",
		"agribank":    "agribank.com.vn",
		"vpbank":      "vpbank.com.vn",
		"acb":         "acb.com.vn",
		"sacombank":   "sacombank.com.vn",
		"tpbank":      "tpb.vn",
		"vib":         "vib.com.vn",
		"hdbank":      "hdbank.com.vn",
		"shb":         "shb.com.vn",
		"scb":         "scb.com.vn",
	}

	isBrandMatch := func(reasonText, brandName string) bool {
		r := strings.ToLower(reasonText)
		b := strings.ToLower(brandName)
		return strings.Contains(r, "of "+b+" brand") ||
			strings.Contains(r, "keyword ("+b+")") ||
			strings.Contains(r, "subdomain usage ("+b+")")
	}

	for brand, official := range govBrands {
		if isBrandMatch(reason, brand) {
			return SpoofResult{
				Domain:         domain,
				IsSpoof:        true,
				BrandName:      brand,
				OfficialDomain: official,
				Category:       "Cơ quan Nhà nước Việt Nam",
				Reason:         reason,
			}, true
		}
	}

	for brand, official := range bankBrands {
		if isBrandMatch(reason, brand) {
			return SpoofResult{
				Domain:         domain,
				IsSpoof:        true,
				BrandName:      brand,
				OfficialDomain: official,
				Category:       "Ngân hàng Việt Nam",
				Reason:         reason,
			}, true
		}
	}

	return SpoofResult{}, false
}

func isDiscordWebhook(url string) bool {
	return strings.Contains(url, "discord.com/api/webhooks") ||
		strings.Contains(url, "discordapp.com/api/webhooks")
}

func buildDiscordPayload(payload AlertPayload) ([]byte, error) {
	var desc strings.Builder
	for i, e := range payload.Events {
		if i >= 10 {
			fmt.Fprintf(&desc, "\n... and %d more events", len(payload.Events)-10)
			break
		}
		switch e.Type {
		case "auto_block":
			fmt.Fprintf(&desc, "🚫 Auto-blocked: `%s`\n", e.Domain)
		case "feed_error":
			fmt.Fprintf(&desc, "⚠️ Feed error: %s\n", e.Details)
		default:
			fmt.Fprintf(&desc, "ℹ️ %s: %s\n", e.Type, e.Domain)
		}
	}

	discord := map[string]any{
		"embeds": []map[string]any{
			{
				"title":       "🛡️ Safe Zone Agent Alert",
				"description": desc.String(),
				"color":       15158332, // red-ish
				"footer": map[string]string{
					"text": payload.Summary,
				},
				"timestamp": payload.Timestamp,
			},
		},
	}

	return json.Marshal(discord)
}
