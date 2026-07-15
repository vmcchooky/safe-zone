# Safe Zone UI Inventory

This inventory report provides a detailed factual catalog of the front-end layout, visual architectures, routing, state models, and underlying API contracts for the Safe Zone repository. It serves as a comprehensive reference guide for a future UI/UX redesign.

> **Current scope:** The primary operator UI is the React workspace in `ui/`, served at `/app/*` and embedded by `core-api`. This document focuses on the legacy compatibility UI at `/dashboard`, whose templates live under `internal/api/views` and whose static assets live under `internal/api/assets`.

---

## 1. Full Repository Structure

Below is the repository tree outlining all top-level directories and nested paths relevant to the system's user interfaces, configuration, deployment, and documentation.

```
safe-zone/
├─ cmd/                 # Go service entrypoints only
│  ├─ core-api/         # Core HTTP API process
│  ├─ dns-resolver/     # DoH/DoT policy service
│  ├─ feed-sync/        # One-shot threat-feed sync tool
│  ├─ feed-syncd/       # Scheduled threat-feed sync daemon
│  └─ load-test/        # Load-test executable
├─ internal/            # Private Go packages and embedded browser surfaces
│  ├─ api/               # Handlers, legacy views/assets, and embedded React bundle mount
│  ├─ agent/             # Optional background task engine
│  ├─ analysis/          # Lexical parsing and domain heuristics
│  ├─ config/            # Environment and configuration parsing
│  ├─ risk/              # Analysis, cache, feed, policy, and OSINT orchestration
│  └─ store/             # SQLite and persistence adapters
├─ ui/                  # Primary React/Vite workspace served at /app/*
│  ├─ public/            # Frontend public assets
│  ├─ src/               # React application source
│  └─ tests/             # Playwright E2E and manual UI checks
├─ docs/                # Project plans, manuals, specifications, and checklists
├─ ops/                 # Deployment, alerting, cron, and secret guidance
├─ scripts/             # Deployment, maintenance, QA, and release helpers
├─ tmp/                 # Ignored local runtime/release evidence output
├─ Caddyfile            # Production reverse-proxy configuration
├─ Dockerfile           # Multi-stage release container definition
├─ docker-compose.yml   # Base Compose configuration
├─ go.mod               # Go module definition
├─ README.md            # Repository overview and setup documentation
└─ start.bat / stop.bat # Windows convenience automation scripts
```

### Top-Level Directory Purposes
*   **`cmd/`**: Holds compile-ready entrypoints for the application binaries. Every subfolder builds into a distinct tool or service.
*   **`internal/`**: Contains shared packages implementing all domain and threat intelligence, whitelisting, database abstractions, scheduling engines, and AI algorithms. Code inside `internal` cannot be imported by external packages.
*   **`docs/`**: Technical guides, operation runbooks, checklist specifications, and system architectural records.
*   **`ops/`**: Houses files and configurations required to operate the application in staging and production (including Docker Compose definitions, alerts templates, and system crons).
*   **`scripts/`**: Holds automated PowerShell and shell scripts utilized for deployment, backups, restores, and log pruning.
*   **`tmp/`**: A git-ignored workspace directory used to dump local log files and auto-generated temporary admin passwords.

---

## 2. Frontend/UI-Related Files

Below is a complete factual inventory of every file related to UI structure, styling, logic delivery, template rendering, and browser-facing routes.

| Path | Type | Purpose | UI Elements | Routes/pages | Safe to edit? | Risk | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `internal/api/views/dashboard.html` | HTML / CSS / JS | Main Single-Page Admin Dashboard interface | Hero summary stats grid, tab selector controls, live results search input form, dynamic laser scanner animations, verdict charts (Chart.js doughnut), recent activity logs, overrides tables, policy card grid, client mapping forms, system health cards, agent trigger tables | `GET /dashboard`, `GET /dashboard/` (when session is active) | Partially. Safe to modify structural HTML/CSS, but DOM element IDs and CSS layout bindings must align with the inline Javascript logic to avoid breaks. | Medium | Relies heavily on relative REST fetches targeting `/v1/*` endpoints. Loads the embedded Chart.js bundle from `/assets/chart.umd.min.js`. |
| `internal/api/views/login.html` | HTML / CSS / JS | Administrator gateway authentication login screen | Dark glassmorphic card container, Identity input field, Access Token password field, Connection submit button, loading animations, error toast | Served via `GET /dashboard` when no session is active | Yes. Uses the embedded local CSS assets, so inline visual styling edits can be made with high isolation. | Low | Submits JSON request to `/v1/auth/login`. Triggers `window.location.reload()` on status 200. |
| `internal/api/views/block.html` | Go HTML Template | Site blocking notification landing page | Cyber warning header banner, blocked data summary (domain, path, category, policy reason, request ID), false-positive report inputs, next step guidelines, HTTPS certificate warning block | `GET /block` | Yes, but Go template interpolation blocks (e.g. `{{.Domain}}`, `{{.RequestedPath}}`) must be preserved exactly. | Medium | Directly parsed by `blockTemplate` inside Go backend. Form submits standard POST payload to `/block/report`. |
| `internal/api/assets/safe-zone.css` | CSS | Primary custom styling sheet for the user interfaces | Base typography settings, glassmorphic panels styles, color palettes, visual layout grids, status text glows, scan animations, modal overlays, toasts transitions | `GET /dashboard`, `GET /block` | Yes. Safe to edit styling properties. Highly recommended starting point for visual adjustments. | Low | Extends and overrides default components provided by `quorix.min.css`. |
| `internal/api/assets/quorix.min.css` | CSS (Minified) | Vendor system styles baseline layout framework | Baseline margins, grid architectures, default typographic scaling | `GET /dashboard`, `GET /block` | No. Minified vendor dependency. Visual overrides should reside in `safe-zone.css`. | High | Imported style asset that must be protected. |
| `internal/api/assets/quorix.min.js` | JS (Minified) | Vendor utility framework for base animations | Core canvas helpers and visual triggers | `GET /dashboard`, `GET /block` | No. Minified asset. | High | Deferred vendor script. |
| `internal/api/assets/FragmentMono-Regular-GORNZRHI.woff2` | WOFF2 Font | Embedded monospace font asset | Monospace tables, codes, and metric prints | `GET /dashboard`, `GET /block` | No. Binary asset. | Low | Loaded via CSS `@font-face` rules. |
| `internal/serve/http.go` | Go Source (embedded HTML) | Emergency server recovery page | Danger warning banner, call stack trace dump, redirect action button | Any active route under `core-api` that undergoes a runtime panic (for HTML requests) | No. Requires updating Go code and compiling. | High | Serves as the panic recovery interface. HTML is hardcoded as a Go string literal inside `getGlassmorphicErrorHTML`. |
| `internal/api/handlers/dashboard.go` | Go Source | Orchestrates dashboard delivery and session checks | None directly (serves as the delivery controller) | `GET /dashboard` | No. Backend session validation. | High | Renders the embedded `dashboard.html` and `login.html` templates after validating the session cookie; static assets are mounted by the router. |
| `internal/api/handlers/block.go` | Go Source | Parses query info and compiles block template data | None directly (server controller executing `blockTemplate`) | `GET /block`, `POST /block/report` | No. Controls DB writes and redirection routing. | High | Directly binds template parameters and processes false-positive form inputs. |
| `cmd/core-api/main.go` | Go Source | Configures application handlers and router scopes | None directly (registers route patterns) | All web routes (`/dashboard`, `/assets/*`, `/v1/*`) | No. | High | Defines API routes and CORS/CSRF boundaries. Modifying this breaks Javascript fetches. |

### Risk Level Guide
*   **Low**: Involves changing static visual properties (CSS rules, typography alignments, Tailwind modifiers) that do not break functional code.
*   **Medium**: Involves HTML layout adjustments or template adjustments (like `dashboard.html` or `block.html`) where selectors must match dynamic JavaScript variables, or where Go template directives must remain intact.
*   **High**: Involves server-side Go route registration, security cookie validations, CSRF defenses, or panic recovery routines. Edits require compilation and directly impact service stability.

---

## 3. Frontend Structure Only

The primary frontend lives in the dedicated `ui/` React/Vite workspace. Its production bundle is built into `internal/api/app/dist` and embedded by `core-api`. The legacy compatibility templates and static assets remain separate under `internal/api/views` and `internal/api/assets`:

```
safe-zone/
├─ ui/
│  ├─ public/                                # Public React assets
│  ├─ src/                                   # Primary React application source
│  └─ tests/                                 # Playwright and manual UI tests
├─ internal/
│  ├─ api/app/                               # Embedded React build mounted at /app/*
│  ├─ api/assets/                            # Legacy CSS, JS, and font assets
│  │  ├─ FragmentMono-Regular-GORNZRHI.woff2
│  │  ├─ quorix.min.css
│  │  ├─ quorix.min.js
│  │  └─ safe-zone.css
│  ├─ api/views/                             # Legacy dashboard/login/block templates
│  │  ├─ block.html
│  │  ├─ dashboard.html
│  │  └─ login.html
│  └─ serve/http.go                          # Panic recovery with embedded HTTP 500 HTML
```

---

## 4. Browser-Facing Routes/Pages

The following table documents all web routes served by `core-api` that return HTML pages to the user:

| Route | Source File / Handler | Purpose | Query Params | Data / API Dependencies | UI States | Redesign Safety Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `GET /dashboard` <br> `GET /dashboard/` | `internal/api/handlers/dashboard.go` <br> `dashboardHandler` | Serves the central Control Plane Dashboard | None | `auth.VerifySessionCookieValue` verifies the `admin_session` cookie. | • **Unauthenticated:** Shows `login.html`. <br>• **Authenticated:** Shows `dashboard.html`. | **Highly Safe.** Structural visual changes can be made, provided script-targeted element IDs (e.g. `domain-input`) are kept. |
| `GET /block` | `internal/api/handlers/block.go` <br> `blockPageHandler` | Displays details about a blocked domain redirection | • `domain` (falls back to header/host) <br>• `path` (falls back to header/path) <br>• `category` <br>• `reason` <br>• `reported` | `config.String("SAFE_ZONE_BLOCK_PAGE_SUPPORT_EMAIL")`, `serve.RequestID(ctx)`. | • **Blocked State:** Shows domain, path, category, and reasons. <br>• **Report Confirmed State:** (`?reported=1`) Shows a success card stating the report has been received. | **Safe.** Requires preserving all Go `{{.Field}}` template tags and keeping the form submission target pointing to `/block/report`. |
| `POST /block/report` | `internal/api/handlers/block.go` <br> `blockReportHandler` | Handles false-positive form reports | None | `a.risk.StoreDB().RecordAgentEvent` | • **Redirect State:** Performs HTTP 303 redirection to `/block?reported=1...` on success. <br>• **Error State:** Renders JSON error. | **API Only.** Returns no HTML. Input names (`domain`, `requested_path`, `contact`, `note`) must not be changed. |
| `GET /assets/*` | `cmd/core-api/main.go` <br> `assetsFS` | File server serving CSS, JS, and font files | None | Static file system | Renders file bytes. | **Fully Safe** to override or expand rules in `safe-zone.css`. |
| Embedded panic page | `internal/serve/http.go` <br> `serve.Recovery` | Intercepts system crashes and shows debug data | None | System Go runtime panic triggers | Shows a glassmorphic error panel detailing HTTP 500 and the runtime panic message. | **Risky.** Embedded inside Go source code. Requires editing `http.go` and rebuilding. |

---

## 5. API Endpoints Consumed by the UI

These API endpoints are queried dynamically by JavaScript in `dashboard.html` or through forms to load data or submit state modifications:

| Endpoint | Method | Source File | Used By | Request Shape | Response Shape | Error Handling | Do Not Change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/v1/auth/login` | `POST` | `cmd/core-api/main.go` <br> `authLoginHandler` | `login.html` authentication form | JSON: `{"username":"...", "password":"..."}` | JSON: `{"status":"ok"}` (Sets `admin_session` cookie) | `400 Bad Request` (Invalid JSON), `401 Unauthorized` (Invalid credentials). UI shows toast. | URL path, method, payload JSON keys (`username`, `password`), cookie key. |
| `/v1/auth/logout` | `POST` | `cmd/core-api/main.go` <br> `authLogoutHandler` | `dashboard.html` logout click | Empty body | JSON: `{"status":"ok", "message":"..."}` (Clears `admin_session` cookie) | Returns `500` on failure. | URL path, method, cookie deletion behavior. |
| `/healthz` | `GET` | `cmd/core-api/main.go` <br> `healthHandler` | `dashboard.html` `checkHealth()` polling | Empty query | JSON: `{"service":"core-api", "status":"ok", "time":"..."}` | Timeout or failure triggers the UI header status indicator to shift to "offline" (red). | JSON keys `status`, `service`. |
| `/` | `GET` | `cmd/core-api/main.go` <br> `statusHandler` | `dashboard.html` health polling checks | Empty query | JSON status representing database caching configurations and threat sync summaries. | Failure marks dashboard status indicator offline. | Nested keys `redis.configured` and `redis.status`. |
| `/v1/analyze` | `POST` | `cmd/core-api/main.go` <br> `analyzeHandler` | `dashboard.html` domain query submit | JSON: `{"domain":"..."}` (Query: `?include_evidence=1`) | JSON: Domain analysis payload including score, verdict state, category, analysis timestamp, cache state, reasons slice, and public OSINT evidence array. | `400` (Invalid body), `405` (Invalid method). Renders "<div class='empty'>Request failed.</div>" inside UI result. | Payload key `domain`, and output verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`). |
| `/v1/analysis/recent` | `GET` | `cmd/core-api/main.go` <br> `recentAnalysisHandler` | `dashboard.html` Recent Activity panel | Empty query | JSON: `{"items": [ {analysis_object}, ... ]}` | Renders "Recent unavailable." inside panel on failure. | Output key `items` containing recent analysis runs. |
| `/v1/overrides` | `GET` | `cmd/core-api/main.go` <br> `overridesHandler` | `dashboard.html` Overrides tab lists | Query: `?action=allow\|block` (optional) | JSON: `{"items": [ {"domain":"...", "action":"...", "reason":"...", "updated_at":"..."}, ... ]}` | `500` (Store failure). Renders "Overrides unavailable." inside UI table. | JSON structures and the `items` array. |
| `/v1/overrides` | `POST` | `cmd/core-api/main.go` <br> `overridesHandler` | `dashboard.html` Add Override form | JSON: `{"domain":"...", "action":"allow\|block", "reason":"..."}` | JSON: `{"status":"ok", "domain":"...", "action":"..."}` | `400` (Validation/DB error), `401` (Unauthorized), `403` (CSRF failure). UI outputs toast error. | Action values (must be `"allow"` or `"block"`). CSRF protection is active. |
| `/v1/overrides` | `DELETE` | `cmd/core-api/main.go` <br> `overridesHandler` | `dashboard.html` Delete Override click | Query: `?domain=example.com` | JSON: `{"status":"ok", "domain":"..."}` | `404` (Not found), `401`, `403` (CSRF fail). UI outputs toast. | URL, method, and query parameters. CSRF protection is active. |
| `/v1/overrides/review-false-positive` | `POST` | `cmd/core-api/main.go` <br> `reviewFalsePositiveHandler` | `dashboard.html` Live results false positive review form | JSON: `{"domain":"...", "reason":"...", "source":"...", "previous_action":"..."}` | JSON: `{"status":"ok", "domain":"...", "action":"allow", "reason":"..."}` | `400` (Validation fail), `401` (Unauthorized), `403` (CSRF failure). UI shows error toast. | Target domain must resolve to `"allow"`. CSRF protection is active. |
| `/v1/telemetry/recent` | `GET` | `cmd/core-api/main.go` <br> `telemetryRecentHandler` | `dashboard.html` Telemetry tab pagination | Query: `?limit=20&offset=0` | JSON: `{"items": [ {"domain":"...", "verdict":"...", "score":10, "source":"...", "analyzed_at":"..."}, ... ]}` | Renders "Telemetry unavailable." inside table on error. | Output schema inside the `items` list. |
| `/v1/telemetry/stats` | `GET` | `cmd/core-api/main.go` <br> `telemetryStatsHandler` | `dashboard.html` Telemetry verdict metrics & doughnut charts | Query: `?period=24h\|7d\|30d` | JSON: `{"total": 10, "safe": 8, "suspicious": 1, "malicious": 1, "cache_hits": 5, "period": "24h"}` | Fail silently (Chart.js falls back to empty values). | JSON statistics keys (`total`, `safe`, `suspicious`, `malicious`, `cache_hits`). |
| `/v1/agent/status` | `GET` | `cmd/core-api/main.go` <br> `agentStatusHandler` | `dashboard.html` System tab agent panel lists | Empty query | JSON representing background engine config, active status, tasks, interval counters, next run schedules, error states, and run counters. | UI falls back to print generic loading failure messages. | Boolean parameter `enabled` and key `tasks`. |
| `/v1/agent/trigger` | `POST` | `cmd/core-api/main.go` <br> `agentTriggerHandler` | `dashboard.html` System tab trigger clicks | Query: `?task=audit\|feed_sync\|osint\|alert\|whitelist` | JSON: `{"status":"triggered", "task":"..."}` | `400` (Task empty), `404` (Task not registered), `401`, `503` (Agent engine disabled). Toast error. | URL, method, and query variable `task`. |
| `/v1/groups` | `GET` | `cmd/core-api/main.go` <br> `groupsHandler` | `dashboard.html` Policy Groups card grids | Query: `?id=1` (optional) | JSON: Array `items` containing group descriptions, category matrices, and phishing/malware strict bits. | UI outputs raw error string into groups grid space. | JSON fields `id` and `items`. |
| `/v1/groups` | `POST` <br> `PUT` | `cmd/core-api/main.go` <br> `groupsHandler` | `dashboard.html` Policy Group modal save | Query: `?id=1` (for PUT) <br>JSON: `{name, description, block_categories, strict_phishing, strict_malware}` | JSON: `{"id": 2, "status": "created"}` or `{"status": "updated"}` | `400` (Validation), `401` (Unauthorized), `403` (CSRF failure). UI shows error toast. | CSRF protection is active. Default group ID `1` cannot be modified/renamed. |
| `/v1/groups` | `DELETE` | `cmd/core-api/main.go` <br> `groupsHandler` | `dashboard.html` Policy Group card delete | Query: `?id=2` | JSON: `{"status": "deleted"}` | `401` (Unauthorized), `403` (CSRF failure), `500` (DB check failure). UI shows error toast. | Default group ID `1` ("default") cannot be deleted. |
| `/v1/mappings` | `GET` | `cmd/core-api/main.go` <br> `mappingsHandler` | `dashboard.html` Client Mappings list table | Empty query | JSON: `{"items": [ {"id":1, "mapping_type":"...", "value":"...", "group_id":2, "group_name":"...", "created_at":"..."}, ... ]}` | UI renders error in mapping list space. | Output keys inside the `items` array. |
| `/v1/mappings` | `POST` | `cmd/core-api/main.go` <br> `mappingsHandler` | `dashboard.html` Add Mapping form | JSON: `{"mapping_type":"ip\|cidr\|client_id", "value":"...", "group_id":2}` | JSON: `{"id":1, "status":"created"}` | `400` (Invalid mapping details/value), `401` (Unauthorized), `403` (CSRF failure). | CSRF protection is active. Valid mapping types must be IP, CIDR, or Client ID. |
| `/v1/mappings` | `DELETE` | `cmd/core-api/main.go` <br> `mappingsHandler` | `dashboard.html` Client Mapping row delete | Query: `?id=1` | JSON: `{"status":"deleted"}` | `404` (Not found), `401`, `403` (CSRF). | CSRF protection is active. |
| `/v1/group-overrides` | `GET` | `cmd/core-api/main.go` <br> `groupOverridesHandler` | `dashboard.html` Group Overrides subtable | Query: `?group_id=2` | JSON: `{"items": [ {"group_id":2, "domain":"...", "action":"...", "reason":"...", "updated_at":"..."}, ... ]}` | Renders "Select a group to load overrides" or error in the table space. | JSON schema for overrides array. |
| `/v1/group-overrides` | `POST` | `cmd/core-api/main.go` <br> `groupOverridesHandler` | `dashboard.html` Group Override form | JSON: `{"group_id":2, "domain":"...", "action":"allow\|block", "reason":"..."}` | JSON: `{"status":"ok"}` | `400` (Validation/DB error), `401`, `403`. | CSRF protection is active. |
| `/v1/group-overrides` | `DELETE` | `cmd/core-api/main.go` <br> `groupOverridesHandler` | `dashboard.html` Group Override row delete | Query: `?group_id=2&domain=test.com` | JSON: `{"status":"ok"}` | `404` (Not found), `401`, `403`. | CSRF protection is active. |

---

## 6. Current UX Flows

Below is a step-by-step description of the operational flows available in the codebase, detailing the files involved, existing user experience limitations, and critical items to preserve during a redesign.

### 1. Open Dashboard
*   **Steps**:
    1.  User enters browser path `http://localhost:8080/dashboard` (or `http://localhost:8080/dashboard/`).
    2.  `core-api` intercepts request and checks for a valid session cookie `admin_session`.
    3.  *Cookie missing/expired:* Serves `login.html` instead.
    4.  User inputs credentials (username pre-filled to `"admin"`) and Password/Access Token, clicking "Establish Connection".
    5.  JavaScript sends credentials as a JSON payload to `POST /v1/auth/login`.
    6.  *Success:* Cookie `admin_session` is set and UI executes `window.location.reload()`.
    7.  *Failure:* Toast display indicates authentication errors, and input forms reset.
    8.  Upon reload, session cookie is valid; `core-api` serves `dashboard.html`.
    9.  The particle canvas initializes floating background animations.
    10. Default tab "Analysis" loads, and `refreshShell()` polls status, cache state, and recent activity.
*   **Current Files Involved**: `internal/api/handlers/dashboard.go`, `internal/api/views/login.html`, `internal/api/views/dashboard.html`, `cmd/core-api/main.go`
*   **Current UX Issues**: Clicking "Establish Connection" does not feature a progress indicator overlay; success reload feels sudden; page context menus are completely disabled via `oncontextmenu="return false;"`.
*   **Redesign Caution**: Authentication cookies delivery is critical. Preserve form structures and endpoint actions exactly.

### 2. Analyze a Domain
*   **Steps**:
    1.  On the "Analysis" tab, the user types a target domain (e.g. `malicious-domain.com`) into `#domain-input`.
    2.  User submits form `#analyze-form` (clicks `#analyze-btn` or hits Enter).
    3.  Both forms and buttons disable. Result state updates to `analyzing...`.
    4.  Concentric shockwave circle expands (`#analyze-shockwave`) and laser slide scanning lines (`#result-scanner`) trigger in the results panel.
    5.  Asynchronous POST payload is delivered to `/v1/analyze?include_evidence=1`.
    6.  *Response loaded:* Forms re-enable, results render inside `#result`, and recent query lists refresh.
*   **Current Files Involved**: `internal/api/views/dashboard.html` (HTML structure + inline JS), `cmd/core-api/main.go` (`analyzeHandler`)
*   **Current UX Issues**: Loading indicator is basic plain text inside the results block header; query failure renders a generic `<div class="empty">Request failed.</div>` string.
*   **Redesign Caution**: The scanner and shockwave animations rely on specific classes (`.scanner-laser.blue.active` and `.shockwave.active`) toggled via script.

### 3. View Risk Result & False-Positive Review
*   **Steps**:
    1.  Domain verdict loads into `#result` from `/v1/analyze` response.
    2.  Shows colored, uppercase verdict string: `SAFE` (green), `SUSPICIOUS` (orange), or `MALICIOUS` (red) alongside confidence percentage and exact score.
    3.  A subcard details grid shows domain name, category, default policy state (Allow or Block badge), analyzed timestamp, cache status, and raw score.
    4.  Under "Signals", reasons are represented as a list of circular pill badges.
    5.  Under "Evidence", threat intelligence warnings are displayed as an expandable feed containing matching sources, confidence levels, retrieved times, and tags.
    6.  *If MALICIOUS or SUSPICIOUS:* A "False-positive review" panel is generated at the bottom of the result.
    7.  The user can input an operational note in the review textarea `#fp-review-reason` and click "Allow / whitelist domain".
    8.  JavaScript submits a JSON payload to `POST /v1/overrides/review-false-positive`.
    9.  On status 200 OK, whitelisting confirmation is toasted, the override list is re-pulled, and a new analysis search is issued for that domain.
*   **Current Files Involved**: `internal/api/views/dashboard.html` (`renderResult`, `renderEvidence`, `renderFalsePositiveReviewPanel`, `submitFalsePositiveReview`)
*   **Current UX Issues**: whitelisting submits lack a processing loader state; whitelisting confirmation requires fully re-querying the domain.
*   **Redesign Caution**: Whitelist notes textarea MUST retain ID `#fp-review-reason` for whitelisting actions to parse it. Whitelisting action function `submitFalsePositiveReview` must be kept.

### 4. View Telemetry Summary & Pagination
*   **Steps**:
    1.  User clicks the "Telemetry" tab.
    2.  `loadTelemetry()` queries `/v1/telemetry/stats?period=24h` (default period).
    3.  UI statistics cards (Total, Safe, Suspicious, Malicious, Cache hits) populate.
    4.  Chart.js constructs a doughnut slice chart inside the `<canvas id="verdict-chart">` element.
    5.  `loadTelemetryItems()` calls `/v1/telemetry/recent?limit=20&offset=0` to load recent items.
    6.  Telemetry table populates showing domain name, colored verdict, score, source, analyzed time, and actions.
    7.  Clicking "← Prev" or "Next →" adjusts pagination offsets and reloads tables.
    8.  Selecting period buttons (24h, 7d, 30d) adjusts period variables and refreshes statistics and charts.
*   **Current Files Involved**: `internal/api/views/dashboard.html` (`loadTelemetryStats`, `loadTelemetryItems`, `renderChart`, `renderTelemRow`)
*   **Current UX Issues**: Doughnut chart colors are hardcoded inside Javascript; failure of the embedded Chart.js bundle breaks rendering, which falls back to plain text.
*   **Redesign Caution**: Keep exact dataset parsing fields inside stats responses. Chart canvas ID `#verdict-chart` must be preserved.

### 5. Manage Client Groups, Mappings, and Overrides
*   **Steps**:
    1.  User selects "Clients & Policies" tab.
    2.  `loadGroups()` queries `/v1/groups` and renders policy groups as responsive cards listing configuration details and strict security state switches.
    3.  Clicking "+ New Group" (or "Edit" on a card) sets modal IDs and renders `#group-modal` modal overlay by appending class `active` to it.
    4.  User adjusts settings, checks categories, and clicks "Save Group".
    5.  JavaScript validates input name and submits payload via POST/PUT to `/v1/groups`. On success, grid refreshes.
    6.  The mappings table fetches client associations from `/v1/mappings`. Adding new IP mappings executes `POST /v1/mappings` and reloads mapping lists.
    7.  Selecting group selectors loads overrides specific to that policy group by executing `GET /v1/group-overrides?group_id=...`. Adding/deleting group overrides performs actions against `/v1/group-overrides` and updates grids.
*   **Current Files Involved**: `internal/api/views/dashboard.html` (`loadClientsTab`, modal controls, save handlers), `cmd/core-api/main.go` (handlers)
*   **Current UX Issues**: Category lists in the group creation modal are static checkboxes; default group ID `1` cannot be renamed or deleted, but this limitation is only visually enforced by hiding buttons, which may confuse operators.
*   **Redesign Caution**: Modal overlay visibility relies on the CSS class `.modal-overlay.active { display: grid; }`. Keep this class name or update modal controls.

### 6. Inspect Service Health & Manually Trigger Background Agents
*   **Steps**:
    1.  User clicks the "System" tab.
    2.  `checkHealth()` queries `/healthz` and `/` status, updating the `core-api` connection status badge (green `"healthy"` or red `"offline"`) and individual subcards (API, Redis, and Enrichment).
    3.  `loadMetrics()` queries `/metrics` to generate latencies summaries inside `#metrics-tbody`.
    4.  `loadAgentStatus()` queries `/v1/agent/status`.
    5.  *If agents are enabled:* Populates active agent tasks (audit, feed sync, etc.) showing statuses, scheduled times, run count distributions, and last exceptions.
    6.  Clicking the "Trigger" action button opens a browser confirmation box (`confirm('Manually trigger agent task...')`).
    7.  *Confirmed:* Sends POST query to `/v1/agent/trigger?task=<task_name>` and toasts success, then reloads agent table status.
*   **Current Files Involved**: `internal/api/views/dashboard.html` (`loadSystem`, `checkHealth`, `loadAgentStatus`, `triggerAgentTask`), `cmd/core-api/main.go`
*   **Current UX Issues**: Latencies are displayed in raw milliseconds without units formatting; task error output columns are cut off without full text expansion.
*   **Redesign Caution**: Trigger action MUST parse and supply the exact agent task name string (e.g., `"audit"`, `"feed_sync"`) to `/v1/agent/trigger?task=...`.

### 7. Open Block Page & Submit False Positive Report
*   **Steps**:
    1.  The user's DNS request matches a blocking policy and points to the sinkhole IP, redirecting the browser to `/block`.
    2.  `core-api` receives `GET /block` and parses query values or headers to compile data payload.
    3.  The page renders an uppercase "This site was blocked." warning alongside details cards listing domain, path, category, request ID, and explanation.
    4.  To report a false positive, the user enters information in the "Think this is a false positive?" form inputs (optional `contact` and `note` details).
    5.  User clicks "Submit False-Positive Report".
    6.  Browser issues a standard `POST` request to `/block/report`.
    7.  Backend parses parameters, records a DB event with event type `"false_positive_report"` and redirects browser to `/block?reported=1&domain=...&path=...`.
    8.  Upon reloading with `reported=1`, the block page displays a green success confirmation block at the top of the details panel.
*   **Current Files Involved**: `internal/api/handlers/block.go`, `internal/api/views/block.html`
*   **Current UX Issues**: Full page redirect makes the process feel sluggish; block page layout uses simple default tables.
*   **Redesign Caution**: Retain exact template variables (`{{.Domain}}`, `{{.RequestedPath}}`, `{{.Category}}`, `{{.Reason}}`, `{{.RequestID}}`, `{{.ReportReceived}}`, and `{{.SupportEmail}}`). Keep form field names `contact` and `note` unchanged.

### 8. Panic Recovery Screen (Emergency UI)
*   **Steps**:
    1.  A severe unexpected failure (panic) occurs inside the Go server.
    2.  `Recovery` middleware recovers the thread and intercepts output streams.
    3.  If the Accept header indicates `text/html` or path begins with `/dashboard`, it writes a `500 Internal Server Error` header and returns a fallback glassmorphic incident page.
    4.  Displays a warning badge (`"HTTP 500 Internal Error"`) and outputs the panic call stack dump inside a monospace panel.
    5.  User can click "Quay Lại Dashboard" to navigate back to `/dashboard`.
*   **Current Files Involved**: `internal/serve/http.go` (`getGlassmorphicErrorHTML`, `Recovery` middleware)
*   **Current UX Issues**: Embedded stack details container is static and does not scale; warning labels are hardcoded in Vietnamese ("Hệ Thống Gặp Sự Cố", "Quay Lại Dashboard") whereas the main dashboard is completely in English.
*   **Redesign Caution**: The error page HTML is hardcoded directly inside `http.go`. Redesigning it requires editing Go files and compiling.

---

## 7. Current Visual Design

The current UI design relies on an aesthetic theme based on the custom variables inside `safe-zone.css`:

### Theme & Colors
*   **Dark Mode First**: The system forces dark mode natively (`color-scheme: dark;` inside `:root`).
*   **Backgrounds**: Set to dark indigo-black (`--bg: #0b0f19`). The login background uses the same base (`bg-[#05070f]`). A floating background effect is achieved by rendering a canvas with rising blue-white particles.
*   **Panels / Cards**: Translucent glassmorphism container panels utilize dark grey backgrounds (`--panel: rgba(17, 24, 39, 0.45)`) combined with a heavy backdrop filter (`--glass-blur: blur(12px)`) and a thin translucent border (`--line: rgba(255, 255, 255, 0.08)`).
*   **Text colors**: Ink color is light grey (`--ink: #e2e8f0`), and muted text uses slate-grey (`--muted: #94a3b8`).
*   **Status Indicators**:
    *   **Safe / Healthy**: Emerald Green (`#10b981`, `--safe`).
    *   **Suspicious**: Amber Yellow (`#eab308`, `--warn`).
    *   **Malicious / Danger**: Rose Red (`#f43f5e`, `--bad`).
*   **Accent Glows**: Sky Blue (`#60a5fa`, `--accent`).

### Layout & Spacing
*   **Margins**: The main wrapper uses auto horizontal margin bounds to fit containers (`width: min(1240px, calc(100vw - 32px))`).
*   **Grid layout**: Renders tables and panels using modern layout grids (`.hero-grid`, `.stats-grid`, `.system-grid`, `.subgrid`, `.grid-2`, `.override-form`, `.block-grid`).

### Typography
*   **Body & UI Titles**: Sets standard font-face to `Inter` (with fallback `system-ui, sans-serif`).
*   **Headings**: Set to bold weight (`font-weight: 700`) with compact letter kerning (`letter-spacing: -0.02em`).
*   **Monospace**: Sets code displays, logs, status values, and database IDs to `Fira Code` (with fallback `monospace`).

### Components & Controls
*   **Tab buttons**: Transparent backgrounds with grey text. Active tabs acquire a blue background tint (`rgba(96, 165, 250, 0.15)`) and border highlights.
*   **Interactive Toggles**: Hovering over panels, cards, or status blocks changes the border outline opacity from `0.08` to `0.15`.
*   **Inputs**: Feature dark translucent backgrounds (`rgba(0,0,0,0.2)`) and monospace formatting. Active input focus triggers a blue border and soft outer shadow.
*   **Toasts**: Positioned floating in the bottom-right corner (`position: fixed; right: 24px; bottom: 24px`). Use translucent grey backdrops and borders that turn green (`.toast.ok`) or red (`.toast.err`) to indicate actions outcome.
*   **Animations**:
    *   **Scanner**: A linear color bar (`.scanner-laser`) slides vertically down the results box in a cubic-bezier transition, colored blue during dashboard analysis and red on block pages.
    *   **Shockwave**: Clicking "Analyze" triggers an expanding concentric border ripple animation (`.shockwave`) on the form container.
    *   **Canvas Particles**: Rising floating bubbles rendered continuously on a fixed canvas overlay.

### Accessibility Concerns
*   **Contrast Limitations**: High-transparency card backdrops and small uppercase text labels (`0.75rem`) have low contrast ratios against the dark background, which may make reading difficult for some users.
*   **Interactive Focus**: Elements lack high-visibility focus borders when navigated using keyboards, which may impact keyboard navigation.
*   **Icons**: The dashboard relies entirely on generic emojis (`🔍`, `📊`, `🛡`, `👥`, `⚙️`, `🚪`), which lack semantic clarity compared to standardized vector iconography. The login page uses Lucide vector icons.

---

## 8. Current CSS/JS Architecture

The front-end code is organized around embedded delivery templates and static asset pipelines:

*   **CSS Architecture**:
    *   Base styling variables and design tokens are defined globally in `:root` inside `internal/api/assets/safe-zone.css`.
    *   The core grid layout and visual elements are styled using global selectors inside `safe-zone.css`. These are loaded in conjunction with the pre-compiled `quorix.min.css` system baseline framework.
    *   The administrator login panel uses the same embedded local CSS assets as the rest of the legacy UI; it does not depend on an external CSS CDN.
*   **JS Architecture**:
    *   Uses a mixed-delivery architecture.
    *   `login.html` features an inline form listener that handles asynchronous authentication requests.
    *   `dashboard.html` contains a single block of **inline JavaScript** (approx. 500 lines) situated at the bottom of the template.
    *   This script acts as the dashboard's controller. It manages:
        *   An in-memory local state dictionary (`const state = { ... }`).
        *   Tab selection and view switching logic.
        *   Dynamic data fetches to `/v1/*` endpoints.
        *   DOM rendering and table generation using direct selectors (`document.getElementById`).
        *   HTML5 canvas animations.
        *   Dynamic Chart.js doughnut chart rendering.
*   **Templates & Backend Coupling**:
    *   **`block.html`**: A server-rendered Go template (`html/template`). Interpolation parameters (such as `{{.Domain}}` and `{{.Reason}}`) are bound at render time inside `block.go`, and missing variables will break page rendering.
    *   **`dashboard.html` & `login.html`**: Loaded from disk or the embedded filesystem and written directly to the HTTP response stream by `dashboardHandler` without template processing. All dynamic data is fetched asynchronously via JSON REST queries and painted on the client side using JavaScript DOM selectors.
    *   **API Coupling**: High. Frontend JavaScript is tightly coupled to Go route handlers. Route structures, query parameter keys, and JSON response paths must match backend logic exactly.

---

## 9. Problems and Constraints

Below is a factual catalog of visual inconsistencies, architecture constraints, and breaking change risks in the codebase:

| Problem | Evidence / File | Impact | Redesign Caution |
| --- | --- | --- | --- |
| **Visual Inconsistency** | `internal/api/views/login.html` vs `internal/api/views/dashboard.html` | The login interface uses a polished glassmorphic treatment, while the dashboard relies on custom CSS grids and emoji labels. This creates a visual mismatch during the transition from login to dashboard. | Consolidate both legacy templates on the shared `safe-zone.css` design tokens without introducing an external CSS dependency or breaking structural grids. |
| **Hardcoded Color Tokens in Javascript** | `internal/api/views/dashboard.html` <br> (Line 621) | Chart.js doughnut colors are hardcoded as hexadecimal strings (`'#177d53'`, `'#ab2f3f'`). If the system color palette (such as `--safe` or `--bad`) is modified in the CSS variables, the charts will retain the hardcoded values, leading to visual mismatch. | Redesign chart render logic to dynamically read computed styles from the CSS variables of the container elements. |
| **Risk of Breaking DOM Selectors** | `internal/api/views/dashboard.html` <br> (Lines 338–357) | JavaScript relies on exact DOM ID references (e.g. `domainInput`, `resultEl`, `metricTotal`, `recentEl`) to query and paint variables. | If the HTML layout is reorganized, these elements must retain their exact DOM IDs. Do not change these IDs without updating their references in the script block. |
| **Server-Side Template Failure Risk** | `internal/api/views/block.html` <br> (Lines 23–27, 33–42) | The block page contains embedded Go template directives (`{{if .ReportReceived}}`, `{{.Domain}}`, `{{.RequestID}}`). | If these variables are modified or mistyped during an HTML redesign, the Go template compiler will fail, causing server crashes (HTTP 500) at render time. |
| **Full-Page Reloads on Form Submission** | `internal/api/views/block.html` <br> (Line 53) | The false-positive report form uses a standard POST request `<form action="/block/report" method="post">`, which causes a full-page reload on submission. | Refactor form submission to use an asynchronous AJAX `fetch` request, allowing visual feedback without reloading the page. |
| **Mixed Locales / Languages in UI** | `internal/api/views/dashboard.html` <br> (Lines 43, 1210) <br> `internal/api/views/login.html` | The UI is mostly written in English, but contains mixed Vietnamese labels (e.g. the tab logout button `🚪 Đăng xuất` and logout confirmation box `Bạn có chắc chắn...`), which impacts internationalization. | Standardize UI text elements to a single language or implement standard locale translation properties. |
| **Synchronous UI Updates During Whitelisting** | `internal/api/views/dashboard.html` <br> (Line 760) | whitelisting a domain executes `Promise.all([loadOverrides(), analyzeDomain(...)])`, forcing the UI to perform a full reload of overrides and trigger a fresh analysis query to update the verdict, which is slow. | Visual status transitions can be updated immediately in the local JS state without triggering redundant fetch sequences. |
| **CSRF Blocking Risks on API Changes** | `cmd/core-api/main.go` <br> (Line 1168) | State-modifying requests (POST, PUT, DELETE) using session cookies are strictly checked for valid Origin and Referer header matches. | Ensure that all dashboard fetch commands target local relative paths to prevent CSRF verification failures. |

---

## 10. Recommended Safe Editing Order

To safely execute a complete front-end redesign without breaking functionality, follow this step-by-step implementation order:

### 1. Centralize Design Tokens
*   **Goal**: Standardize the visual palette, hover glows, and sizing scales globally inside `:root` inside `safe-zone.css`.
*   **Files Likely Touched**: `internal/api/assets/safe-zone.css`
*   **Risk Level**: Low
*   **What Must Not Be Touched**: DOM IDs and element class names.
*   **Manual Test Steps**: Load the dashboard and ensure all tables and panels render correctly with the updated tokens.

### 2. Add Reusable Base CSS Classes
*   **Goal**: Replace custom inline style bindings (e.g. `style="display: grid; ..."` inside mappings forms) with semantic utility classes in `safe-zone.css` to clean up the markup.
*   **Files Likely Touched**: `internal/api/assets/safe-zone.css`, `internal/api/views/dashboard.html`
*   **Risk Level**: Low
*   **What Must Not Be Touched**: JavaScript event handlers and functional selectors.
*   **Manual Test Steps**: Verify form alignments under the "Clients & Policies" tab to ensure they match mockups.

### 3. Redesign Dashboard Shell
*   **Goal**: Update the header panel, status badges, and tab selector buttons, adding visual hover indicators and outline animations.
*   **Files Likely Touched**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Risk Level**: Low
*   **What Must Not Be Touched**: The tab button `data-tab="..."` attributes and element IDs (`tab-btn-analysis`, etc.) which are bound to the JS tab router.
*   **Manual Test Steps**: Click through all navigation tabs to confirm they switch panel views correctly.

### 4. Redesign Domain Analyzer Control Toolbar
*   **Goal**: Modernize the query text input field and search button, incorporating high-visibility active ring glows.
*   **Files Likely Touched**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Risk Level**: Low to Medium
*   **What Must Not Be Touched**: Form ID `#analyze-form`, input ID `#domain-input`, and button ID `#analyze-btn`.
*   **Manual Test Steps**: Input a domain, submit the query, and confirm the laser animations and shockwaves trigger correctly.

### 5. Redesign Analysis Risk Results Panel
*   **Goal**: Modernize the visual output layout of `renderResult(item)`, replacing simple list items with detailed grid grids, polishing evidence lists, and redesigning whitelisting panels.
*   **Files Likely Touched**: `internal/api/views/dashboard.html` (specifically functions `renderResult`, `renderEvidence`, and `renderFalsePositiveReviewPanel`), `internal/api/assets/safe-zone.css`
*   **Risk Level**: Medium to High
*   **What Must Not Be Touched**: Whitelist note text-area ID `#fp-review-reason` and whitelist action button trigger bindings `submitFalsePositiveReview()`.
*   **Manual Test Steps**: Query a malicious domain, type a whitelisting note in the panel, click whitelist, and verify the domain shifts to the allowlist.

### 6. Redesign Telemetry Metrics & Charting
*   **Goal**: Style the telemetry summary metrics cards. Refactor the `renderChart` JS function to parse and apply CSS variable tokens for Chart.js.
*   **Files Likely Touched**: `internal/api/views/dashboard.html` (specifically `renderChart`), `internal/api/assets/safe-zone.css`
*   **Risk Level**: Medium
*   **What Must Not Be Touched**: canvas ID `#verdict-chart` and statistical DOM IDs (such as `st-total`, `st-safe`, etc.).
*   **Manual Test Steps**: Open the Telemetry tab, change time periods (24h, 7d, 30d), and confirm charts reload with correct alignments and colors.

### 7. Redesign System Tab & Background Agents
*   **Goal**: Style service health status panels, latency metrics listings, and background agent task trigger tables.
*   **Files Likely Touched**: `internal/api/views/dashboard.html`, `internal/api/assets/safe-zone.css`
*   **Risk Level**: Medium
*   **What Must Not Be Touched**: The trigger function binding `triggerAgentTask(name)`.
*   **Manual Test Steps**: Open the System tab, verify latency columns load, click "Trigger" next to a background task, and verify task runs.

### 8. Redesign Block Page Landing
*   **Goal**: Polish block page templates layout. Replace standard form submissions with AJAX fetches to prevent full-page refreshes.
*   **Files Likely Touched**: `internal/api/views/block.html`, `internal/api/assets/safe-zone.css`
*   **Risk Level**: Medium
*   **What Must Not Be Touched**: Go template interpolation tags (e.g. `{{.Domain}}`).
*   **Manual Test Steps**: Navigate to `/block?domain=malicious.com`, fill out false-positive details, click submit, and verify success indicators display.

### 9. Mobile Responsive Optimization
*   **Goal**: Improve responsive media queries in `safe-zone.css` to support tablet and mobile screens, focusing on menu tabs wrap behaviors and table column responsive hides.
*   **Files Likely Touched**: `internal/api/assets/safe-zone.css`
*   **Risk Level**: Low
*   **What Must Not Be Touched**: HTML layouts or template structure.
*   **Manual Test Steps**: Resize browser viewport down to mobile width (360px) and check if dashboard structures wrap correctly.

### 10. Motion & Accessibility Optimization
*   **Goal**: Apply standardized keyboard focus indices (`tabindex` and `outline-glow` indicators), implement semantic ARIA tags, and refine background canvas float properties.
*   **Files Likely Touched**: `internal/api/views/dashboard.html`, `internal/api/views/block.html`, `internal/api/views/login.html`
*   **Risk Level**: Low to Medium
*   **What Must Not Be Touched**: API integration scopes or core router structures.
*   **Manual Test Steps**: Navigate through all tabs and panels using only the Tab and Enter keys, confirming focus rings are clearly visible.

---

## 11. Files and Selectors That Must Be Protected

During a front-end redesign, these backend structures, API paths, DOM IDs, and JavaScript parameters **must not be renamed or changed** without updating all references, as doing so will break core system functionality.

### Route Handlers & Middlewares
*   `dashboardHandler` (`/dashboard` and `/dashboard/` endpoints)
*   `blockPageHandler` (`/block` template controller)
*   `blockReportHandler` (`/block/report` form target)
*   `requireAuthFunc` (Static Bearer token + CSRF check middleware wrapper)

### API Endpoints
*   `/v1/auth/login`
*   `/v1/auth/logout`
*   `/v1/analyze`
*   `/v1/analysis/recent`
*   `/v1/overrides`
*   `/v1/overrides/review-false-positive`
*   `/v1/telemetry/recent`
*   `/v1/telemetry/stats`
*   `/v1/agent/status`
*   `/v1/agent/trigger`
*   `/v1/groups`
*   `/v1/mappings`
*   `/v1/group-overrides`
*   `/healthz`
*   `/metrics`

### DOM IDs (JavaScript Bindings)
*   `domain-input` (Text search query element)
*   `analyze-btn` (Submit trigger button)
*   `osint-btn` (OSINT intelligence fetcher button)
*   `result` (Analysis results render box)
*   `recent` (Recent history grid container)
*   `recent-count` (Recent query counter chip)
*   `api-status` (Connection state badge)
*   `cache-state` (Redis connection chip)
*   `rl-status` (Rate limiting active chip)
*   `result-state` (Analysis load string)
*   `metric-total` (Summary total query count)
*   `st-total` (Telemetry summary total count)
*   `verdict-chart` (Chart.js doughnut target canvas)
*   `sys-api-status` (System tab health badge)
*   `sys-redis-status` (System tab cache badge)
*   `metrics-tbody` (Endpoint metrics container table body)
*   `agent-overall-status` (Background engine status indicator)
*   `agent-panel-body` (Agent list table body container)
*   `groups-grid` (Groups list container)
*   `mappings-tbody` (Client mapping list table body)
*   `override-group-select` (Group override filter dropdown)
*   `group-overrides-tbody` (Group override table body)
*   `group-modal` (Policy group edit modal container)
*   `group-form` (Policy group submit form)
*   `fp-review-reason` (False-positive whitelisting note textarea)
*   `toast` (Notification card float target)
*   `appCanvasBackground` (Floating particles canvas background element)
*   `result-scanner` (Laser animation line container)

### CSS Style Identifiers (JS & Transition Bindings)
*   `.tab-btn` (Active tab selector styles)
*   `.tab-content` (Tab panels display state toggle)
*   `.verdict-banner` (Result verdict banners styling container)
*   `.recent-item` (Recent queries summary container)
*   `.telemetry-row` (Paginated stats data listing container)
*   `.modal-overlay` (Popup modal grid layout visibility class)
*   `.scanner-laser` (Vertical scanning laser animation class)
*   `.shockwave` (Analyze button expanding circle animation class)
*   `.block-shell` (Block page container class)

### JavaScript Core Controller Functions
*   `switchTab(name)` (Client-side view tab controller)
*   `analyzeDomain(domain, forceEvidence)` (Queries domain risk score)
*   `loadRecent()` (Loads previous analysis activities)
*   `renderResult(item)` (Generates results panels output HTML)
*   `submitFalsePositiveReview()` (Saves a whitelisting record to database)
*   `loadTelemetry()` (Orchestrates telemetry statistics checks)
*   `renderChart(s)` (Triggers Chart.js drawing routines)
*   `loadSystem()` (Orchestrates status and metrics checks)
*   `loadAgentStatus()` (Loads active background task logs)
*   `triggerAgentTask(name)` (Triggers a background task manual execution run)
*   `loadGroups()` (Queries active policy groups)
*   `loadMappings()` (Queries client mapping lists)
*   `loadGroupOverrides()` (Loads specific overrides for the selected policy group)
*   `showToast(msg, type)` (Spawns a floating notification)

### JSON Schema Keys
*   `domain`, `verdict`, `score`, `confidence`, `category`, `analyzed_at`, `cache_hit`, `reasons`, `evidence` (Analysis object fields)
*   `status`, `items` (Array wraps)
*   `enabled`, `tasks` (Agent structures)
*   `mapping_type`, `value`, `group_id`, `group_name` (Client mapping properties)
*   `block_categories`, `strict_phishing`, `strict_malware` (Policy group properties)

### Query Parameters
*   `domain`, `include_evidence`, `force_osint` (Analyzer controls)
*   `reported`, `category`, `reason`, `path` (Block page redirect controls)
*   `limit`, `offset`, `period` (Telemetry query selectors)
*   `group_id`, `id` (Client policy selector IDs)
*   `task` (Agent task selector names)
*   `refresh`, `force` (OSINT control flags)

---

## 12. Summary for External UI Reviewer

Welcome! Here is an overview of the Safe Zone front-end architecture to help you plan a future visual redesign:

### 1. Where the UI Lives
Safe Zone has a dedicated React frontend workspace plus a legacy server-rendered compatibility UI:
*   **Primary UI**: `ui/src/` contains the React application served at `/app/*`; its production bundle is embedded under `internal/api/app/dist`.
*   **Legacy templates**: `internal/api/views/` contains `dashboard.html`, `login.html`, and `block.html` for `/dashboard` and `/block`.
*   **Styles**: `internal/api/assets/safe-zone.css` contains custom visual styling rules.
*   **Emergency Layouts**: `internal/serve/http.go` contains an emergency server panic page embedded as a multiline string in Go source code.

### 2. Main User-Facing Pages
The application serves three primary web views:
1.  **Dashboard / Control Plane (`/dashboard`)**: A single-page, tabbed administrator panel. It handles manual domain analysis queries, renders threat telemetry doughnut charts, manages domain whitelists and overrides, configures policy groups, and monitors background agent task run counts.
2.  **Login Gateway**: A dark glassmorphic portal page displayed when the user does not have a valid session cookie.
3.  **Block Landings (`/block`)**: A clean warning page displayed when a user's web query matches a blocking policy. It includes a text form to submit false-positive report details.

### 3. Safe Starting Edits (Low Risk)
To begin visual adjustments, start with these low-risk areas:
*   **`internal/api/assets/safe-zone.css`**: This file contains purely visual styling. You can safely edit CSS variables, layout grids, colors, hover rules, and button styles.
*   **`internal/api/views/login.html`**: The login layout is isolated and styled using shared local CSS classes. Modifying it is safe, provided form inputs and button trigger names remain unchanged.

### 4. Risky Areas (High Risk)
Avoid making unstructured modifications to these high-risk areas:
*   **DOM IDs inside `dashboard.html`**: JavaScript relies on exact DOM IDs (e.g. `domain-input`, `st-total`, `metrics-tbody`, `result`, etc.) to query and paint dynamic elements. Renaming these IDs will break the dashboard's javascript code.
*   **Go Template interpolations inside `block.html`**: The block page is rendered using server-side Go templating. Modifying curly template bindings (e.g. `{{.Domain}}`, `{{if .ReportReceived}}`) will trigger compile/runtime errors, causing the server to crash (HTTP 500) when rendering the block page.
*   **CSRF & Security structures inside `main.go`**: All state-modifying requests (POST, PUT, DELETE) are protected by CSRF origin checks and session validations. All fetches must remain relative.
*   **Emergency HTML strings in `internal/serve/http.go`**: Modifying the emergency panic page requires editing Go source code and recompiling the application.

### 5. Unknown from Current Code
*   **Telemetry History DB Volume**: The telemetry query fetches `/v1/telemetry/recent` and `/v1/telemetry/stats` from the backend, but the exact database size limits and storage retention policies (e.g., when threat records are pruned or archived) are managed in background database drivers and are unknown from the frontend UI code alone.
*   **Gemini AI Response Bounds**: The dynamic analyzer can trigger Gemini AI analysis for ambiguous domains, but the exact prompt constraints, rate limit limits for the Gemini API key, and response token boundaries are managed server-side and are not visible in the frontend codebase.
