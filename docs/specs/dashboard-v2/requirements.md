# Requirements: Admin Dashboard v2

## Goal

Evolve the existing embedded dashboard from a simple "analyze & view recent" tool into a full operational control plane. Admin can monitor system health, manage overrides, view telemetry trends, and act on threats — all from a single HTML page served by `core-api`.

## Current State

The existing dashboard (`dashboard.html`, ~716 lines) provides:
- Domain analysis form with quick-check buttons.
- Live result display (verdict, score, confidence, reasons).
- Recent activity list (from Redis, ephemeral).
- API health check + cache status pills.
- Metrics: total/safe/suspicious/malicious counts (from recent list only).
- Auto-refresh every 15 seconds.

**What's missing**:
- No override management UI.
- No long-term telemetry visualization (only Redis recent list).
- No charts or trend visualization.
- No system metrics display (uptime, request counts, latency).
- No filtering/search on recent activity.

## Milestones

### Milestone 1: Telemetry Dashboard Tab

- **Stats cards**: Total, Safe, Suspicious, Malicious, Cache Hits — from `/v1/telemetry/stats`.
- **Period selector**: 24h / 7d / 30d toggle.
- **Trend chart**: Doughnut or bar chart showing verdict distribution — using Chart.js from CDN.
- **Recent telemetry table**: Paginated, sortable, from `/v1/telemetry/recent`.

### Milestone 2: Override Manager Tab

- **Override list**: Table of all overrides with domain, action, reason, timestamps.
- **Add override form**: Domain input, action toggle (allow/block), reason text.
- **Delete override**: One-click delete with confirmation.
- **Filter**: Filter by action (all / allow / block).
- **Inline feedback**: Success/error messages after mutations.

### Milestone 3: System Health Tab

- **Service status**: core-api health, Redis connectivity, SQLite status.
- **Uptime & metrics**: From `/metrics` endpoint — request counts, latency, bytes.
- **Auto-refresh**: Every 15 seconds (same as current).

### Milestone 4: Navigation & Polish

- **Tab navigation**: Tabs for Analysis / Telemetry / Overrides / System.
- **Dark mode**: Optional toggle (CSS custom properties already in place).
- **Mobile responsive**: Existing responsive layout extended to new sections.
- **Preserve existing functionality**: All current features remain working.

## Technical Constraints

- **Single HTML file**: Embedded via `//go:embed`. No build step, no npm, no bundler.
- **Minimal external deps**: Only Chart.js from CDN (already a standard choice for lightweight charts).
- **No framework**: Vanilla JS only. Alpine.js optional if it simplifies state management significantly.
- **Budget VPS friendly**: No WebSocket, no SSE. Polling only (15s interval).
- **Offline-capable**: Dashboard works even when CDN unreachable (charts just don't render).

## Acceptance Criteria

- All existing dashboard features remain functional.
- Override CRUD works from the dashboard UI.
- Telemetry stats and chart render correctly for all three periods.
- Tab navigation works without page reload.
- Dashboard loads in < 2 seconds on a budget VPS.
- Mobile layout is usable on 375px+ screens.
- No new Go files needed (only `dashboard.html` changes).

## What This Does NOT Include

- User authentication or login (deferred to auth feature).
- Real-time streaming (WebSocket/SSE — overkill for single VPS).
- Multi-tenant dashboard.
- Exportable reports (CSV/PDF).
