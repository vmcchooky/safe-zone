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

// AlertTask sends webhook notifications when significant agent events occur
// (auto-blocks, feed sync errors).
type AlertTask struct {
	store  *store.DB
	config AlertConfig
	http   *http.Client

	mu        sync.Mutex
	lastAlert time.Time
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
	return &AlertTask{
		store:     db,
		config:    cfg,
		http:      &http.Client{Timeout: cfg.Timeout},
		lastAlert: time.Now(),
	}
}

func (t *AlertTask) Name() string { return "alert" }

func (t *AlertTask) Run(ctx context.Context) error {
	webhookURL := t.config.WebhookURL
	if t.store != nil && t.store.Enabled() {
		if customURL, err := t.store.GetSystemConfig(context.Background(), "agent_webhook_url"); err == nil && customURL != "" {
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

	t.mu.Lock()
	since := t.lastAlert
	t.mu.Unlock()

	// Query for alertable events since last check.
	events, err := t.store.QueryAgentEvents(context.Background(), since, []string{
		"auto_block", "feed_error",
	}, 100)
	if err != nil {
		return fmt.Errorf("query agent events: %w", err)
	}

	if len(events) < t.config.MinEvents {
		return nil // not enough events to trigger alert
	}

	// Build payload and search for critical brand spoofing
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

	var errorsList []string

	// 1. Send default webhook (Discord/Generic)
	if hasWebhook {
		if err := t.sendWebhook(ctx, webhookURL, payload); err != nil {
			errorsList = append(errorsList, fmt.Sprintf("webhook: %v", err))
		}
	}

	// 2. Send critical notifications if there are any Vietnam spoofing events
	if len(criticalEvents) > 0 {
		if hasTelegram {
			tgBaseCtx := correlation.WithRunID(context.Background(), correlation.RunID(ctx))
			tgCtx, tgCancel := context.WithTimeout(tgBaseCtx, t.config.Timeout)
			go func() {
				defer tgCancel()
				if err := t.sendTelegram(tgCtx, criticalEvents); err != nil {
					logjson.Error("telegram alert failed", correlation.Fields(tgCtx, map[string]any{
						"service": "core-api",
						"task":    "alert",
						"error":   err.Error(),
					}))
				}
			}()
		}
		if hasSlack {
			slBaseCtx := correlation.WithRunID(context.Background(), correlation.RunID(ctx))
			slCtx, slCancel := context.WithTimeout(slBaseCtx, t.config.Timeout)
			go func() {
				defer slCancel()
				if err := t.sendSlack(slCtx, criticalEvents); err != nil {
					logjson.Error("slack alert failed", correlation.Fields(slCtx, map[string]any{
						"service": "core-api",
						"task":    "alert",
						"error":   err.Error(),
					}))
				}
			}()
		}
		if hasEmail {
			emBaseCtx := correlation.WithRunID(context.Background(), correlation.RunID(ctx))
			emCtx, emCancel := context.WithTimeout(emBaseCtx, t.config.Timeout)
			go func() {
				defer emCancel()
				if err := t.sendEmail(emCtx, criticalEvents); err != nil {
					logjson.Error("email alert failed", correlation.Fields(emCtx, map[string]any{
						"service": "core-api",
						"task":    "alert",
						"error":   err.Error(),
					}))
				}
			}()
		}
	}

	// Update last alert time on success.
	t.mu.Lock()
	t.lastAlert = time.Now()
	t.mu.Unlock()

	_ = t.store.RecordAgentEvent(context.Background(), "alert", "alert_sent", "",
		fmt.Sprintf(`{"events_count":%d,"critical_count":%d}`, len(events), len(criticalEvents)))

	logjson.Info("agent alert triggered", correlation.Fields(ctx, map[string]any{
		"service":         "core-api",
		"task":            "alert",
		"events":          len(events),
		"critical_events": len(criticalEvents),
	}))

	if len(errorsList) > 0 {
		errStr := strings.Join(errorsList, "; ")
		_ = t.store.RecordAgentEvent(context.Background(), "alert", "alert_failed", "", errStr)
		return fmt.Errorf("send alert failures: %s", errStr)
	}

	return nil
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
	defer resp.Body.Close()

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
		fmt.Fprintf(&msg, "📌 <b>Tên miền vi phạm:</b> <code>%s</code>\n", html.EscapeString(e.Domain))
		fmt.Fprintf(&msg, "🏷️ <b>Phân loại:</b> %s\n", html.EscapeString(e.Category))
		fmt.Fprintf(&msg, "🏢 <b>Thương hiệu bị mạo danh:</b> <b>%s</b>\n", html.EscapeString(e.BrandName))
		fmt.Fprintf(&msg, "🌐 <b>Tên miền chính thức:</b> <a href=\"https://%s\">%s</a>\n", html.EscapeString(e.OfficialDomain), html.EscapeString(e.OfficialDomain))
		fmt.Fprintf(&msg, "📝 <b>Lý do:</b> <i>%s</i>\n\n", html.EscapeString(e.Reason))
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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	if port == 465 {
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
	} else if port == 587 {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported smtp port %d: use 465 implicit TLS or 587 STARTTLS", port)
	}
	defer conn.Close()
	_ = setConnDeadline(ctx, conn)

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

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
