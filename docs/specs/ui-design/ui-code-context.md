# Safe Zone UI Code Context

This context document collects compact, factual code snippets related to Safe Zone's user interfaces, templates, CSS styling, client-side JavaScript, and browser-facing Go route handlers. It provides external reviewers and future implementers with a self-contained reference of all code-level dependencies and visual contracts.

> **Current scope:** The primary operator UI is the React workspace in `ui/`, served at `/app/*`. The template and asset references in this document describe the legacy compatibility UI served at `/dashboard` and `/block`.

---

## 1. Purpose of This File

This file compiles compact code snippets related to Safe Zone's current UI, dashboard, block page, CSS, JavaScript, browser-facing routes, and UI-consumed APIs. 

*   **Intended Audience**: External UI/UX designer and frontend reviewer.
*   **Intended Use**: Static architectural reference to guide a future aesthetic refactoring. It maps out DOM contracts, CSS namespaces, data models, and API boundaries.
*   **Non-Goal**: It does not implement the redesign or execute code changes.

---

## 2. UI File Map

The following table lists all files directly involved in rendering, styling, or routing Safe Zone's browser-facing user interfaces:

| Path | Purpose | Why It Matters for Redesign |
| --- | --- | --- |
| `internal/api/views/dashboard.html` | Core UI markup and controller JavaScript | Contains the structural grids for all five operational tabs, as well as the main inline script managing REST queries and canvas background drawings. |
| `internal/api/views/login.html` | Administrator connection screen | Uses the embedded local CSS assets to style a standalone dark glassmorphic portal page. |
| `internal/api/views/block.html` | Redirection warning landing page | A Go standard `html/template` that requires exact variable parameters (`{{.Domain}}`, etc.) to parse without compiler crashes. |
| `internal/api/assets/safe-zone.css` | Custom layout overrides stylesheet | Defines primary CSS variables (colors, fonts, blurs) and visual animations (vertical lasers, expanding shockwaves). |
| `internal/api/assets/quorix.min.css` | Baseline enterprise style sheet | Vendor-provided CSS bundle that sets grid rules. Visual styles inside must be overridden in `safe-zone.css`. |
| `internal/api/assets/quorix.min.js` | Vendor animation helper script | A deferred vendor helper bundle. |
| `internal/api/assets/FragmentMono-Regular-GORNZRHI.woff2` | Embedded monospace font | Binary font asset loaded in CSS to style code grids, hashes, and numbers. |
| `internal/serve/http.go` | HTTP Panic Recovery middleware | Houses a hardcoded emergency Vietnamese-localized HTTP 500 landing page inside a Go string literal (`getGlassmorphicErrorHTML`). |
| `internal/api/handlers/dashboard.go` | Renders dashboard / login pages | Binds the embedded assets filesystem and validates administrator cookies before returning HTML. |
| `internal/api/handlers/block.go` | Compiles block templates data | Extracts request metadata and parses `block.html` using the standard `html/template` library. |
| `cmd/core-api/main.go` | Registers application routes and boundaries | Defines the backend router paths (`/dashboard`, `/v1/*`, etc.) and enforces static Bearer tokens and cookie CSRF checks. |

---

## 3. HTML/Template Snippets

Below are compact code snippets representing the markup structure of each primary user-facing surface:

### Dashboard Shell
[HTML SNIPPET]
<!-- File: internal/api/views/dashboard.html -->
<body class="dashboard-page">
<canvas id="appCanvasBackground"></canvas>
<div class="shell">

  <header>
    <div class="hero">
      <div class="title">
        <h1>Safe Zone Dashboard</h1>
      </div>
      <div class="status-pills">
        <span class="chip" id="api-status"><strong>core-api</strong> checking</span>
        <span class="chip" id="cache-state"><strong>cache</strong> idle</span>
        <span class="chip" id="rl-status"><strong>rate limit</strong> —</span>
      </div>
    </div>
    <div class="hero-grid">
      <div class="metric"><strong id="metric-total">0</strong><span>Total (24h)</span></div>
      <div class="metric"><strong id="metric-safe">0</strong><span>Safe</span></div>
      <div class="metric"><strong id="metric-suspicious">0</strong><span>Suspicious</span></div>
      <div class="metric"><strong id="metric-malicious">0</strong><span>Malicious</span></div>
      <div class="metric"><strong id="metric-cache">0</strong><span>Cache hits</span></div>
    </div>
  </header>

  <!-- Tab Navigation -->
  <nav class="tabs" role="tablist">
    <button class="tab-btn active" role="tab" data-tab="analysis" id="tab-btn-analysis">🔍 Analysis</button>
    <button class="tab-btn" role="tab" data-tab="telemetry" id="tab-btn-telemetry">📊 Telemetry</button>
    <button class="tab-btn" role="tab" data-tab="overrides" id="tab-btn-overrides">🛡 Overrides</button>
    <button class="tab-btn" role="tab" data-tab="clients" id="tab-btn-clients">👥 Clients & Policies</button>
    <button class="tab-btn" role="tab" data-tab="system" id="tab-btn-system">⚙️ System</button>
    <button class="tab-btn logout-btn" id="logout-btn" onclick="handleLogout()">🚪 Đăng xuất</button>
  </nav>
[/HTML SNIPPET]

### Domain Analyzer Form
[HTML SNIPPET]
<!-- File: internal/api/views/dashboard.html -->
  <div class="tab-content active" id="tab-analysis">
    <main>
      <form class="toolbar" id="analyze-form" style="position: relative; z-index: 20;">
        <input id="domain-input" name="domain" autocomplete="off" spellcheck="false" placeholder="secure-login-wallet-example.com">
        <button id="analyze-btn" type="submit" style="position: relative;">
          <span style="position: relative; z-index: 2;">Analyze</span>
          <div id="analyze-shockwave" class="shockwave"></div>
        </button>
      </form>
[/HTML SNIPPET]

### Risk Result Display Panel
[HTML SNIPPET]
<!-- File: internal/api/views/dashboard.html -->
      <div class="grid-2">
        <section class="panel" style="position: relative;">
          <div class="panel-head"><h2>Live result</h2><span id="result-state">waiting</span></div>
          <div id="result" style="position: relative; overflow: hidden;">
            <div class="scanner-laser blue" id="result-scanner"></div>
            <div class="empty">Awaiting input...</div>
          </div>
        </section>
[/HTML SNIPPET]

### Metrics / Status Area (Telemetry Panel)
[HTML SNIPPET]
<!-- File: internal/api/views/dashboard.html -->
  <div class="tab-content" id="tab-telemetry">
    <main>
      <div class="panel">
        <div class="panel-head">
          <h2>Verdict Distribution</h2>
          <div class="period-bar">
            <button class="period-btn active" data-period="24h">24h</button>
            <button class="period-btn" data-period="7d">7d</button>
            <button class="period-btn" data-period="30d">30d</button>
          </div>
        </div>
        <div class="stats-grid">
          <div class="stat-card"><div class="stat-val" id="st-total">—</div><div class="stat-lbl">Total</div></div>
          <div class="stat-card"><div class="stat-val SAFE" id="st-safe">—</div><div class="stat-lbl">Safe</div></div>
          <div class="stat-card"><div class="stat-val SUSPICIOUS" id="st-suspicious">—</div><div class="stat-lbl">Suspicious</div></div>
          <div class="stat-card"><div class="stat-val MALICIOUS" id="st-malicious">—</div><div class="stat-lbl">Malicious</div></div>
          <div class="stat-card"><div class="stat-val" id="st-cache">—</div><div class="stat-lbl">Cache hits</div></div>
        </div>
        <div class="chart-wrap">
          <div class="chart-container"><canvas id="verdict-chart"></canvas></div>
        </div>
[/HTML SNIPPET]

### Agent / System Tab Controls
[HTML SNIPPET]
<!-- File: internal/api/views/dashboard.html -->
  <div class="tab-content" id="tab-system">
    <main>
      <div class="panel">
        <div class="panel-head"><h2>Service Health</h2><span id="sys-uptime">—</span></div>
        <div class="system-grid">
          <div class="sys-card">
            <div class="sys-name">core-api</div>
            <div class="sys-status" id="sys-api-status">—</div>
            <div class="sys-detail" id="sys-api-detail">—</div>
          </div>
          ...
        </div>
      </div>
      ...
      <div class="panel" style="margin-top:16px">
        <div class="panel-head"><h2>Agent Engine</h2><span id="agent-overall-status">—</span></div>
        <div id="agent-panel-body" style="padding:16px">
          <div class="empty">Loading Agent status...</div>
        </div>
      </div>
    </main>
  </div>
[/HTML SNIPPET]

### Block Page Redirect Template
[HTML SNIPPET]
<!-- File: internal/api/views/block.html -->
<body class="block-page">
  <div class="cyber-grid-bg"></div>
  <div class="scanner-laser red active"></div>
  <main class="shell block-shell">
    <section class="hero block-hero">
      <div class="eyebrow danger-soft">Safe Zone Block Page</div>
      <h1>This site was blocked.</h1>
      <p class="lede">Safe Zone redirected this request...</p>
    </section>

    <section class="grid block-grid">
      <div class="main block-main">
        {{if .ReportReceived}}
        <div class="card success block-card">
          Your false-positive report was received. An operator can now review it with request ID <code>{{.RequestID}}</code>.
        </div>
        {{end}}

        <div class="card block-card">
          <h2>What was blocked</h2>
          <div class="fact">
            <span>Blocked domain</span>
            <strong>{{.Domain}}</strong>
          </div>
          <div class="fact">
            <span>Requested path</span>
            <strong>{{.RequestedPath}}</strong>
          </div>
          ...
        </div>
      </div>
    </section>
  </main>
</body>
[/HTML SNIPPET]

### Emergency Panic Page (Embedded String Snippet)
[HTML SNIPPET]
<!-- File: internal/serve/http.go -->
func getGlassmorphicErrorHTML(errStr string) string {
	return `<!DOCTYPE html>
<html lang="vi">
<head>
    ...
    <title>500 - Lỗi Hệ Thống | Safe Zone</title>
    ...
</head>
<body>
    <div class="container">
        <div class="card">
            ...
            <h1>Hệ Thống Gặp Sự Cố</h1>
            <div class="status-badge">HTTP 500 Internal Error</div>
            <p>Đã xảy ra lỗi runtime không mong muốn trong quá trình xử lý yêu cầu...</p>
            <div class="error-details">Sự cố: ` + htmlEscape(errStr) + `</div>
            <a href="/dashboard" class="btn">Quay Lại Dashboard</a>
        </div>
    </div>
</body>
</html>`
}
[/HTML SNIPPET]

---

## 4. CSS Snippets

Below are compact code snippets from `internal/api/assets/safe-zone.css` showcasing the layout styling rules:

### Global / Base Styles
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
:root {
  color-scheme: dark;
  --qx-font-body: 'Inter', system-ui, sans-serif;
  --qx-font-heading: 'Inter', system-ui, sans-serif;
  --qx-font-ui: 'Inter', system-ui, sans-serif;
  --qx-font-mono: 'Fira Code', monospace;

  --bg: #0b0f19;
  --panel: rgba(17, 24, 39, 0.45);
  --panel-strong: rgba(17, 24, 39, 0.7);
  --ink: #e2e8f0;
  --muted: #94a3b8;
  --line: rgba(255, 255, 255, 0.08);
  
  --safe: #10b981;
  --warn: #eab308;
  --bad: #f43f5e;
  
  --accent: #60a5fa;
  --accent-alpha: rgba(96, 165, 250, 0.2);
  
  --shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  --glass-blur: blur(12px);
}
[/CSS SNIPPET]

### Layout Styles
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
.shell, .login-container { width: min(1240px, calc(100vw - 32px)); margin: 0 auto; }
.shell { padding: 24px 0 48px; position: relative; z-index: 10; }

.hero-grid, .stats-grid, .system-grid, .subgrid, .grid-2, .override-form, .login-grid, .block-grid { display: grid; gap: 16px; }
.hero-grid, .stats-grid { grid-template-columns: repeat(5, minmax(0, 1fr)); }
.grid-2, .block-grid { grid-template-columns: minmax(0, 1fr) 360px; }
.system-grid, .subgrid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
[/CSS SNIPPET]

### Cards / Panels
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
header, .panel, .toolbar, .login-card, .block-shell, .card, .subcard, .metric, .recent-item, .group-card, .sys-card, .stat-card, .modal-card {
  background: var(--panel);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: var(--shadow);
  transition: border-color 0.4s ease, box-shadow 0.4s ease, transform 0.4s ease;
}
.panel:hover, .card:hover, .stat-card:hover {
  border-color: rgba(255,255,255, 0.15);
}
[/CSS SNIPPET]

### Buttons
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
.tab-btn, button, .period-btn {
  min-height: 36px; border: 1px solid transparent; border-radius: 8px; font: inherit; font-weight: 600; font-size: 0.85rem; cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: inline-flex; align-items: center; justify-content: center; position: relative; overflow: hidden;
}
.tab-btn.active, .period-btn.active { background: rgba(96, 165, 250, 0.15); border-color: rgba(96, 165, 250, 0.3); color: var(--accent); }
button:not(.tab-btn):not(.period-btn):not(.ghost):not(.modal-close) {
  padding: 0 20px; background: rgba(96, 165, 250, 0.15); color: #93c5fd; border: 1px solid rgba(96, 165, 250, 0.3);
}
.btn-danger, .btn-block { background: rgba(244, 63, 94, 0.15) !important; color: #fca5a5 !important; border-color: rgba(244, 63, 94, 0.3) !important; }
[/CSS SNIPPET]

### Inputs / Forms
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
input, select, textarea {
  width: 100%; min-height: 40px; border: 1px solid var(--line); border-radius: 8px; padding: 0 16px;
  background: rgba(0,0,0,0.2); color: white; font-family: var(--qx-font-mono); font-size: 0.9rem; outline: none; transition: all 0.3s;
}
input:focus, select:focus, textarea:focus { border-color: var(--accent); background: rgba(0,0,0,0.4); box-shadow: 0 0 0 2px rgba(96,165,250,0.2); }
[/CSS SNIPPET]

### Badges / Status / Risk States
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
.chip, .verdict, .badge-allow, .badge-block, .grp-badge, .recent-tags span, .meta span, .eyebrow {
  display: inline-flex; align-items: center; min-height: 24px; padding: 0 10px; border-radius: 9999px;
  border: 1px solid var(--line); background: rgba(0,0,0,0.3); font-size: 0.7rem; font-weight: 700; text-transform: uppercase; font-family: var(--qx-font-mono);
}
.chip.ok, .badge-allow, .qx-text-success { color: var(--safe); border-color: rgba(16,185,129,0.3); background: rgba(16,185,129,0.1); }
.chip.bad, .INVALID, .badge-block, .qx-text-danger { color: var(--bad); border-color: rgba(244,63,94,0.3); background: rgba(244,63,94,0.1); }
[/CSS SNIPPET]

### Tables / Lists / Logs
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
.override-table, .metrics-table { width: 100%; border-collapse: collapse; font-family: var(--qx-font-mono); font-size: 0.85rem; }
.override-table th, .override-table td, .metrics-table th, .metrics-table td { padding: 12px 16px; border-bottom: 1px dashed var(--line); text-align: left; }
.telemetry-row {
  display: grid; grid-template-columns: minmax(14rem, 1fr) 7rem 4rem 5rem 6rem auto; gap: 12px; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--line); font-family: var(--qx-font-mono); font-size: 0.8rem;
}
[/CSS SNIPPET]

### Responsive Styles
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
@media (max-width: 980px) {
  .hero-grid, .stats-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .grid-2, .block-grid { grid-template-columns: 1fr; }
  .system-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 720px) {
  .hero-grid, .stats-grid, .subgrid, .system-grid, .toolbar, .override-form { grid-template-columns: 1fr; }
  .telemetry-row { grid-template-columns: minmax(12rem, 1fr) 5rem 4rem; }
  .telemetry-row > *:nth-child(n+4) { display: none; }
}
[/CSS SNIPPET]

### Animation / Motion Styles
[CSS SNIPPET]
/* File: internal/api/assets/safe-zone.css */
.cyber-grid-bg {
  position: absolute; inset: 0; z-index: 0; pointer-events: none; opacity: 0.4;
  background-image: linear-gradient(rgba(244, 63, 94, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(244, 63, 94, 0.1) 1px, transparent 1px);
  background-size: 30px 30px; animation: gridPan 10s linear infinite;
}
@keyframes gridPan { 0% { transform: translateY(0); } 100% { transform: translateY(30px); } }

.scanner-laser {
  position: absolute; left: 0; right: 0; top: 0; height: 2px; z-index: 3; opacity: 0; pointer-events: none;
}
.scanner-laser.active { opacity: 1; animation: scanDown 1.5s cubic-bezier(0.7, 0, 0.2, 1) forwards; }
@keyframes scanDown { 0% { transform: translateY(0); } 100% { transform: translateY(500px); opacity: 0; } }
[/CSS SNIPPET]

---

## 5. JavaScript Snippets

These snippets represent the client-side JavaScript located inside the script block of `internal/api/views/dashboard.html`:

### State Initialization
[JS SNIPPET]
// File: internal/api/views/dashboard.html
const state = {
  activeTab: 'analysis',
  latest: null,
  recent: [],
  telemetry: { stats: {}, items: [], page: 0, pageSize: 20, period: '24h', total: 0 },
  overrides: { items: [], filter: '' },
  system: { health: {}, metrics: {}, status: {} },
  chart: null,
  clients: { groups: [], mappings: [], overrides: [] },
};
[/JS SNIPPET]

### DOM Selector Helpers
[JS SNIPPET]
// File: internal/api/views/dashboard.html
const $ = id => document.getElementById(id);
const analyzeForm     = $('analyze-form');
const domainInput     = $('domain-input');
const analyzeBtn      = $('analyze-btn');
const osintBtn        = $('osint-btn');
const resultEl        = $('result');
const recentEl        = $('recent');
const recentCount     = $('recent-count');
const cacheState      = $('cache-state');
const apiStatus       = $('api-status');
const rlStatus        = $('rl-status');
const resultState     = $('result-state');
[/JS SNIPPET]

### Domain Analysis Request
[JS SNIPPET]
// File: internal/api/views/dashboard.html
async function analyzeDomain(domain, forceEvidence) {
  analyzeBtn.disabled = true;
  osintBtn.disabled = true;
  resultState.textContent = forceEvidence ? 'checking public evidence…' : 'analyzing…';
  try {
    const suffix = '?include_evidence=1' + (forceEvidence ? '&force_osint=1' : '');
    const r = await fetch('/v1/analyze' + suffix, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const payload = await r.json();
    state.latest = payload;
    renderResult(payload);
    await loadRecent();
    resultState.textContent = 'fresh result';
  } catch {
    resultEl.innerHTML = '<div class="empty">Request failed.</div>';
    resultState.textContent = 'request failed';
  } finally {
    analyzeBtn.disabled = false;
    osintBtn.disabled = false;
  }
}
[/JS SNIPPET]

### Rendering Result States
[JS SNIPPET]
// File: internal/api/views/dashboard.html
function renderResult(item) {
  cacheState.innerHTML = item.cache_hit ? '<strong>cache</strong> hit' : '<strong>cache</strong> fresh';
  const blocked = item.verdict === 'MALICIOUS';
  const policyLabel = blocked ? 'Block' : 'Allow';
  const policyClass = blocked ? 'badge-block' : 'badge-allow';
  const reasons = (item.reasons && item.reasons.length)
    ? '<ul class="reasons">' + item.reasons.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul>'
    : '<ul class="reasons"><li>no risk signals</li></ul>';
  const evidence = renderEvidence(item.evidence || []);
  const reviewPanel = renderFalsePositiveReviewPanel(item);
  resultEl.innerHTML =
    '<div class="result-body">' +
      '<div class="verdict-banner">' +
        '<div class="verdict-row">' +
          '<strong class="' + item.verdict + '">' + esc(item.verdict) + '</strong>' +
          '<span class="verdict-meta">' + Math.round(item.confidence * 100) + '% confidence &middot; score ' + item.score + '</span>' +
        '</div>' +
      '</div>' +
      ...
    '</div>';
}
[/JS SNIPPET]

### Metrics & Status Fetching
[JS SNIPPET]
// File: internal/api/views/dashboard.html
async function checkHealth() {
  try {
    const [hRes, sRes] = await Promise.all([fetch('/healthz'), fetch('/')]);
    const health = await hRes.json();
    const status = await sRes.json();
    const ok = health.status === 'ok';
    apiStatus.className = ok ? 'chip ok' : 'chip bad';
    apiStatus.innerHTML = '<strong>core-api</strong> ' + (ok ? 'healthy' : 'limited');
    $('sys-api-status').textContent = ok ? '● Online' : '⚠ Limited';
    // Redis Cache check
    const redis = status.redis || {};
    const redisOk = redis.status === 'ok';
    $('sys-redis-status').textContent = redis.configured ? (redisOk ? '● Connected' : '⚠ Unavailable') : '○ Disabled';
    cacheState.innerHTML = redis.configured && redisOk ? '<strong>cache</strong> ok' : '<strong>cache</strong> offline';
  } catch {
    apiStatus.className = 'chip bad';
    apiStatus.innerHTML = '<strong>core-api</strong> offline';
  }
}
[/JS SNIPPET]

### Agent / System Action Trigger
[JS SNIPPET]
// File: internal/api/views/dashboard.html
async function triggerAgentTask(name) {
  if (!confirm('Manually trigger agent task "' + name + '"?')) return;
  try {
    const r = await fetch('/v1/agent/trigger?task=' + encodeURIComponent(name), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Task "' + name + '" triggered successfully', 'ok');
    await loadAgentStatus();
  } catch(err) {
    showToast('Error: ' + err.message, 'err');
  }
}
[/JS SNIPPET]

### Loading / Error Toast Notification
[JS SNIPPET]
// File: internal/api/views/dashboard.html
let toastTimer;
function showToast(msg, type) {
  toast.textContent = msg;
  toast.className = 'toast ' + type + ' show';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.classList.remove('show'); }, 3000);
}
[/JS SNIPPET]

---

## 6. Browser-Facing Route/Handler Snippets

Below are the Go route endpoints serving visual HTML pages or static files:

### Dashboard Route
[GO SNIPPET]
// File: cmd/core-api/main.go
// Endpoint: GET /dashboard
mux.HandleFunc("/dashboard", api.dashboardHandler)
mux.HandleFunc("/dashboard/", api.dashboardHandler)
[/GO SNIPPET]

[GO SNIPPET]
// File: internal/api/handlers/dashboard.go
func (a *app) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value == "" {
		_, _ = w.Write([]byte(loginHTML))
		return
	}
	_, err = auth.VerifySessionCookieValue(cookie.Value, a.sessionSecret)
	if err != nil {
		// Session expired; clear cookie and render login page
		_, _ = w.Write([]byte(loginHTML))
		return
	}
	_, _ = w.Write([]byte(dashboardHTML))
}
[/GO SNIPPET]

### Block Page Route
[GO SNIPPET]
// File: cmd/core-api/main.go
// Endpoint: GET /block
mux.HandleFunc("/block", api.blockPageHandler)
[/GO SNIPPET]

[GO SNIPPET]
// File: internal/api/handlers/block.go
func (a *app) blockPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data := blockPageData{
		Domain:          blockedDomainFromRequest(r),
		RequestedPath:   blockedPathFromRequest(r),
		Category:        firstNonEmpty(r.URL.Query().Get("category"), "policy block"),
		Reason:          firstNonEmpty(r.URL.Query().Get("reason"), "This request was redirected because the requested domain matched a Safe Zone block policy."),
		SupportEmail:    strings.TrimSpace(config.String("SAFE_ZONE_BLOCK_PAGE_SUPPORT_EMAIL", "")),
		ReportReceived:  r.URL.Query().Get("reported") == "1",
		RequestID:       serve.RequestID(r.Context()),
		HTTPSLimitation: true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = blockTemplate.Execute(w, data)
}
[/GO SNIPPET]

### Static Asset Serving
[GO SNIPPET]
// File: cmd/core-api/main.go
// Endpoint: GET /assets/*
//go:embed assets/*
var assetsFS embed.FS
...
mux.Handle("/assets/", http.FileServer(http.FS(assetsFS)))
[/GO SNIPPET]

### Other Browser-Facing HTML Routes
All other routes defined inside `core-api` return raw JSON models. The fallback path `/` is a JSON API summary served on `GET /` (`statusHandler`). No other standalone browser HTML routes exist in the codebase.

---

## 7. API Endpoints Consumed by the UI

The table below outlines all backend endpoints queried asynchronously by JavaScript inside `dashboard.html` or through standard forms:

| Endpoint | Request Fields | Response Fields | Used by UI Selector / Function |
| --- | --- | --- | --- |
| `POST /v1/auth/login` | `username` (string)<br>`password` (string) | `status` (string)<br>`message` (string) | `login.html` authentication form submit listener |
| `POST /v1/auth/logout` | None | `status` (string)<br>`message` (string) | `dashboard.html` `#logout-btn` logout click handler |
| `GET /healthz` | None | `service` (string)<br>`status` (string)<br>`time` (string) | `dashboard.html` health polling `checkHealth()` |
| `GET /` | None | `redis` status object<br>`feed_sync` object<br>`deployment_tier` (string) | `dashboard.html` health polling `checkHealth()` |
| `POST /v1/analyze` | `domain` (string)<br>Query: `?include_evidence=1` | `verdict` (string)<br>`score` (int)<br>`confidence` (float)<br>`reasons` (array)<br>`evidence` (array) | `dashboard.html` `#analyze-form` analyzer submit listener |
| `GET /v1/analysis/recent` | None | `items` (array of threat results) | `dashboard.html` `loadRecent()` activity list |
| `GET /v1/overrides` | Query: `?action=allow\|block` | `items` (array of override objects) | `dashboard.html` `loadOverrides()` listing |
| `POST /v1/overrides` | `domain` (string)<br>`action` (string)<br>`reason` (string) | `status` (string)<br>`domain` (string)<br>`action` (string) | `dashboard.html` `#override-form` add override submit |
| `DELETE /v1/overrides` | Query: `?domain=domain.com` | `status` (string)<br>`domain` (string) | `dashboard.html` `deleteOverride(domain)` click handler |
| `POST /v1/overrides/review-false-positive` | `domain` (string)<br>`reason` (string)<br>`source` (string)<br>`previous_action` (string) | `status` (string)<br>`domain` (string)<br>`action` (string) | `dashboard.html` `submitFalsePositiveReview()` whitelister |
| `GET /v1/telemetry/recent` | Query: `?limit=20&offset=0` | `items` (array of telemetry objects) | `dashboard.html` `loadTelemetryItems()` query log |
| `GET /v1/telemetry/stats` | Query: `?period=24h\|7d\|30d` | `total` (int)<br>`safe` (int)<br>`suspicious` (int)<br>`malicious` (int) | `dashboard.html` `loadTelemetryStats()` charts metrics |
| `GET /v1/agent/status` | None | `enabled` (bool)<br>`tasks` (array of task objects) | `dashboard.html` `loadAgentStatus()` systems grid |
| `POST /v1/agent/trigger` | Query: `?task=task_name` | `status` (string)<br>`task` (string) | `dashboard.html` `triggerAgentTask(name)` trigger click |
| `GET /v1/groups` | None (or Query: `?id=1`) | `items` (array of group objects) | `dashboard.html` `loadGroups()` policy groups card grids |
| `POST /v1/groups`<br>`PUT /v1/groups` | `name` (string)<br>`description` (string)<br>`block_categories` (array)<br>`strict_phishing` (bool)<br>`strict_malware` (bool) | `id` (int)<br>`status` (string) | `dashboard.html` `#group-form` group save click |
| `DELETE /v1/groups` | Query: `?id=1` | `status` (string) | `dashboard.html` `deleteGroup(id, name)` grid delete link |
| `GET /v1/mappings` | None | `items` (array of mapping objects) | `dashboard.html` `loadMappings()` clients table list |
| `POST /v1/mappings` | `mapping_type` (string)<br>`value` (string)<br>`group_id` (int) | `id` (int)<br>`status` (string) | `dashboard.html` `#mapping-form` mapping form submit |
| `DELETE /v1/mappings` | Query: `?id=1` | `status` (string) | `dashboard.html` `deleteMapping(id)` row delete click |
| `GET /v1/group-overrides` | Query: `?group_id=1` | `items` (array of group overrides) | `dashboard.html` `loadGroupOverrides()` sub-panel table |
| `POST /v1/group-overrides` | `group_id` (int)<br>`domain` (string)<br>`action` (string)<br>`reason` (string) | `status` (string) | `dashboard.html` `#group-override-form` form submit |
| `DELETE /v1/group-overrides` | Query: `?group_id=1&domain=d.com` | `status` (string) | `dashboard.html` `deleteGroupOverride(gid, domain)` |

### API Consumed Endpoint Code Snippet (Domain Analysis)
[GO SNIPPET]
// File: cmd/core-api/main.go
// Endpoint: POST /v1/analyze
func (a *app) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string
	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		defer r.Body.Close()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		domain = req.Domain
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	clientInfo := extractClientInfo(r)
	response := a.risk.AnalyzeWithOptions(r.Context(), domain, clientInfo, risk.AnalyzeOptions{
		IncludeEvidence: r.URL.Query().Get("include_evidence") == "1",
		ForceOSINT:      r.URL.Query().Get("force_osint") == "1",
	})
	a.risk.RecordRecent(r.Context(), response)
	writeJSON(w, http.StatusOK, response)
}
[/GO SNIPPET]

---

## 8. Current DOM Contract

The client-side JavaScript controller in the HTML templates depends on these DOM elements. They **must not be renamed or removed** during redesign:

| Selector / ID / Class | Used in File | Purpose | Safe to Rename? |
| --- | --- | --- | --- |
| `analyze-form` | `dashboard.html` | Submits analysis queries | **No**. JS binds submit listener. |
| `domain-input` | `dashboard.html` | Input text box for the domain query | **No**. JS extracts string query. |
| `analyze-btn` | `dashboard.html` | Submit action button trigger | **No**. JS disables this during fetch. |
| `osint-btn` | `dashboard.html` | Forces public intelligence refresh | **No**. JS disables this during fetch. |
| `result` | `dashboard.html` | Renders search threat verdict | **No**. JS writes results HTML. |
| `recent` | `dashboard.html` | Renders previous query logs list | **No**. JS writes history list. |
| `recent-count` | `dashboard.html` | Displays search query count chip | **No**. JS writes active count. |
| `cache-state` | `dashboard.html` | Displays Redis connection status | **No**. JS writes connected state. |
| `api-status` | `dashboard.html` | Displays core-api connection state | **No**. JS writes online status. |
| `rl-status` | `dashboard.html` | Displays rate limiter active state | **No**. JS writes active state. |
| `result-state` | `dashboard.html` | Displays current search load text | **No**. JS writes loading logs. |
| `metric-total` | `dashboard.html` | Header metric showing query count | **No**. JS writes total counts. |
| `st-total` | `dashboard.html` | Telemetry grid total metric | **No**. JS writes count. |
| `verdict-chart` | `dashboard.html` | Doughnut verdict chart canvas element | **No**. Chart.js binds to selector. |
| `sys-api-status` | `dashboard.html` | System tab API status pill | **No**. JS writes online status. |
| `sys-redis-status` | `dashboard.html` | System tab cache status pill | **No**. JS writes connection status. |
| `metrics-tbody` | `dashboard.html` | Endpoints latency table container | **No**. JS writes dynamic rows. |
| `agent-overall-status`| `dashboard.html` | Background task engine active badge | **No**. JS writes active status. |
| `agent-panel-body` | `dashboard.html` | Background agent lists container | **No**. JS writes list rows. |
| `groups-grid` | `dashboard.html` | Grid container displaying client groups | **No**. JS writes group cards. |
| `mappings-tbody` | `dashboard.html` | Client mappings lists table body | **No**. JS writes rows. |
| `override-group-select`| `dashboard.html` | Select dropdown filtering group overrides| **No**. JS binds change listener. |
| `group-overrides-tbody`| `dashboard.html` | Group overrides table body | **No**. JS writes rows. |
| `group-modal` | `dashboard.html` | Policy group edit popup dialog | **No**. JS toggles `active` class. |
| `group-form` | `dashboard.html` | Modal group input submit form | **No**. JS binds submit listener. |
| `fp-review-reason` | `dashboard.html` | False-positive whitelisting textarea | **No**. JS reads value for payload. |
| `toast` | `dashboard.html` | Floating confirmation toast container | **No**. JS writes feedback strings. |
| `appCanvasBackground` | `dashboard.html` | Canvas overlay rendering background particles| **No**. JS canvas writes to element. |
| `result-scanner` | `dashboard.html` | Laser scanning animation line | **No**. JS triggers animation. |
| `analyze-shockwave` | `dashboard.html` | Search button wave animation block | **No**. JS triggers animation. |

---

## 9. Current CSS Contract

Below are the important styling classes that shape the visual grids and layout elements across the interfaces:

| Class / Selector | Defined in | Used in | Purpose | Can Be Replaced Later? |
| --- | --- | --- | --- | --- |
| `.dashboard-page` | `safe-zone.css` | `dashboard.html` | Base styling wrapper for the dashboard view | **Yes**, safe to modify style properties. |
| `.shell` | `safe-zone.css` | `dashboard.html`, `block.html` | Limits content width to a maximum of 1240px and centers layout | **Yes**, keep wrapper size constraints. |
| `.panel` | `safe-zone.css` | `dashboard.html` | Translucent glassmorphic card container for dashboard grids | **Yes**, but elements must retain basic padding and rounded corners. |
| `.tab-btn` | `safe-zone.css` | `dashboard.html` | Styles navigation tab buttons (active displays blue background) | **Yes**, can be redesigned, but do not touch event listener selector loops. |
| `.tab-content` | `safe-zone.css` | `dashboard.html` | Manages display views (toggles visibility using `.active`) | **No**. JavaScript relies on `.active` toggles to swap tab views. |
| `.verdict-banner` | `safe-zone.css` | `dashboard.html` | Binds color highlights based on verdict values (`SAFE`, `MALICIOUS`) | **Yes**. Style states can be redesigned visually. |
| `.recent-item` | `safe-zone.css` | `dashboard.html` | Container displaying previous query records | **Yes**, safe to redesign. |
| `.telemetry-row` | `safe-zone.css` | `dashboard.html` | Grid row displaying paginated query records | **Yes**, safe to adjust columns. |
| `.override-table` | `safe-zone.css` | `dashboard.html` | Styles custom rules tables | **Yes**, safe to redesign table classes. |
| `.modal-overlay` | `safe-zone.css` | `dashboard.html` | Centered modal backdrop (displays only when appended with `.active`) | **No**. JS relies on `.active` class toggle to show the policy group modal. |
| `.toast` | `safe-zone.css` | `dashboard.html` | Floating notification card positioned in bottom-right corner | **Yes**, but keep `.show` class transitions. |
| `.scanner-laser` | `safe-zone.css` | `dashboard.html`, `block.html` | Sliding laser animation container (triggered using `.active`) | **Yes**, but do not remove `.active` selector animations in JS. |
| `.shockwave` | `safe-zone.css` | `dashboard.html` | Search button wave expanding circle animation | **Yes**, safe to redesign. |
| `.block-page` | `safe-zone.css` | `block.html` | Grid wrapper centering the sinkhole block screen | **Yes**, safe to adjust margins. |
| `.block-shell` | `safe-zone.css` | `block.html` | Glassmorphic container wrapper for the block warning panel | **Yes**, safe to redesign. |

---

## 10. Current Data Contract Used by UI

The JavaScript controller parses and renders the following JSON key fields returned by `core-api` endpoint payloads. These **must not be renamed** in API responses:

| Data Source / Endpoint | Field | Meaning in UI | Required? | Notes |
| --- | --- | --- | --- | --- |
| `/v1/analyze` <br> `/v1/analysis/recent` | `domain` | Target web domain name | **Yes** | Printed inside result header. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `verdict` | Security evaluation (`SAFE`, `SUSPICIOUS`, `MALICIOUS`) | **Yes** | Renders color tags and whitelisting review modules. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `score` | Domain threat hazard integer (0-100) | **Yes** | Renders score metrics. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `confidence` | Analysis accuracy level (0.0 - 1.0) | **Yes** | Multiplied by 100 to show confidence percentage. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `category` | Classification category (e.g. `phishing`) | **Yes** | Shows category badge. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `analyzed_at` | Analysis execution timestamp | **Yes** | Displays query execution timestamp. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `cache_hit` | Indicates if query is cached | **Yes** | Toggles `"cache hit"` or `"cache fresh"` badges. |
| `/v1/analyze` <br> `/v1/analysis/recent` | `reasons` | Slices of descriptive reasons | **Yes** | Renders the "Signals" pills list. |
| `/v1/analyze` | `evidence` | intelligence warn list | **No** | Populates the OSINT warning feed. |
| `/v1/telemetry/stats` | `total` | Aggregated query logs count | **Yes** | Populates the overview and chart stats. |
| `/v1/telemetry/stats` | `safe` | Total safe queries count | **Yes** | Feeds Doughnut Chart dataset. |
| `/v1/telemetry/stats` | `suspicious` | Total suspicious queries count | **Yes** | Feeds Doughnut Chart dataset. |
| `/v1/telemetry/stats` | `malicious` | Total malicious queries count | **Yes** | Feeds Doughnut Chart dataset. |
| `/v1/telemetry/stats` | `cache_hits` | Total cache hits queries count | **Yes** | Renders cache counters. |
| `/v1/agent/status` | `enabled` | Indicates if Agent engine is active | **Yes** | Shows task lists or displays "Agent engine disabled". |
| `/v1/agent/status` | `tasks` | Array of registered background tasks | **Yes** | Renders scheduled task listings. |

---

## 11. Current UX State Coverage

The table below indicates the UX states supported by features in the current codebase:

| Feature | Idle | Loading | Success | Warning | Danger | Error | Empty | Disabled | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Domain Analyzer** | Yes | Yes | Yes | No | No | Yes | No | No | Idle state displays "Awaiting input...". Loading state disables buttons and runs lasers. |
| **Risk Result** | No | No | Yes | Yes | Yes | No | No | No | Visual treatments are customized for `SAFE`, `SUSPICIOUS`, and `MALICIOUS` verdicts. |
| **Metrics / Status** | No | No | Yes | No | No | Yes | No | No | Core stats are loaded on tabs initialization. |
| **Agent / System Actions**| Yes | No | Yes | No | No | Yes | Yes | Yes | Triggering a manual task displays a native browser confirmation box before execution. |
| **Threat Feed Status** | Yes | No | Yes | Yes | No | Yes | No | Yes | Feeds show green healthy or amber limited warnings inside header badges depending on Redis connection state. |
| **Block Page** | No | No | Yes | No | Yes | Yes | No | No | `reported=1` query parameter renders a green success confirmation block at the top of the details panel. |

---

## 12. Redesign Safety Guidelines

Keep these guidelines in mind during future redesign implementations:

*   **Files Safest to Edit First**:
    *   `internal/api/assets/safe-zone.css`: Pure layout overrides stylesheet. Editing visual properties here has no impact on server functions or database logic.
    *   `internal/api/views/login.html`: The login page layout is isolated and styled using shared local CSS classes. Visually refactoring it will not break database sessions.
*   **Highly Risky Files**:
    *   `internal/api/views/block.html`: Server-rendered template file. Deleting template parameters (such as `{{.Domain}}` or the conditional `{{if .ReportReceived}}`) will trigger compile/runtime errors, causing the server to crash (HTTP 500) when rendering.
    *   `internal/serve/http.go`: Emergency panic recovery module. Edits require updating Go files and compiling.
    *   `cmd/core-api/main.go` & `dashboard.go`: Handles authentication tokens and routing configurations. Avoid editing these unless you are migrating API endpoints.
*   **Keep DOM Selectors Intact**: Do not rename critical DOM element IDs (such as `domain-input`, `analyze-btn`, `result`, `recent`, `st-total`, etc.) to prevent JavaScript fetch and DOM paint operations from breaking.
*   **Security-Critical Text to Preserve**: The HTTPS note panel on the blocked redirect page (`block.html`, lines 82-84) provides network clients with explanation warnings regarding browser certificate validations. Keep this notice fully intact during a visual layout refactoring.

---

## 13. External Reviewer Summary

### 1. Frontend Architecture
The Safe Zone codebase embeds all user interface files directly inside the Go backend executable using `go:embed`. Custom styles are managed globally inside `internal/api/assets/safe-zone.css`, while template structures reside in `internal/api/views/dashboard.html` and `internal/api/views/block.html`.

### 2. Redesign Focus
*   Start by refactoring visual properties inside `internal/api/assets/safe-zone.css`. Feel free to redefine visual colors, panel variables, fonts, active outline glows, and hover transition indicators.
*   Next, modernize layouts inside `internal/api/views/dashboard.html` by replacing emoji labels with clean typography, updating stats cards, and structuring results.
*   Finally, refactor the false-positive form submission in `block.html` to submit asynchronously via JavaScript `fetch` calls, preventing full-page browser redirects.

### 3. Critical Constraints
*   **Do Not Rename Selectors**: Keep all current DOM element IDs intact.
*   **Do Not Modify Templates**: Preserve all Go template parameters (such as `{{.Domain}}` inside `block.html`) to prevent server-side compilation crashes.
*   **Do Not Change APIs**: All relative endpoint paths (`/v1/*`), HTTP query parameters, and JSON payloads are hardcoded in the backend. Keep all API contracts unchanged.
*   **Keep Changes Safe**: Always run `go build ./...` after updating template files to verify that pages compile and render cleanly.
