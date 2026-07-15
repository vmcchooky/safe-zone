# Tasks: Admin Dashboard v2

Synced with repository state on 2026-05-26. Code-backed items are checked; remaining open items are manual browser/mobile verification only.

## Phase 1: Tab Navigation & Layout Restructuring

- [x] Add CSS for tab bar, tab content sections, and responsive breakpoints.
- [x] Restructure existing HTML into `#tab-analysis` content section.
- [x] Create empty tab content sections: `#tab-telemetry`, `#tab-overrides`, `#tab-system`.
- [x] Add tab switching JS logic with state management.
- [x] Verify existing analysis functionality still works after restructuring.

## Phase 2: Telemetry Tab

- [x] Add telemetry stats cards (Total, Safe, Suspicious, Malicious, Cache Hits).
- [x] Add period selector (24h / 7d / 30d) with active state.
- [x] Add the embedded Chart.js bundle from `/assets/chart.umd.min.js` with graceful fallback.
- [x] Add doughnut chart for verdict distribution.
- [x] Add paginated telemetry recent table.
- [x] Add pagination controls (Prev / Next / Page indicator).
- [x] Wire up period selector to re-fetch stats and update chart.
- [x] Wire up auto-refresh for active telemetry tab.

## Phase 3: Overrides Tab

- [x] Add "Add Override" form: domain input, action toggle (allow/block), reason input.
- [x] Add form submission handler with API call to `POST /v1/overrides`.
- [x] Add override list table rendering from `GET /v1/overrides`.
- [x] Add action filter buttons (All / Allow / Block).
- [x] Add delete button per override with confirmation prompt.
- [x] Add inline success/error toast messages.
- [x] Wire up auto-refresh for override list.

## Phase 4: System Tab

- [x] Add service status cards (core-api, Redis, SQLite).
- [x] Add uptime display (from `/metrics` uptime_seconds).
- [x] Add request summary table (from `/metrics` request_summary).
- [x] Calculate and display average latency per endpoint.
- [x] Wire up auto-refresh.

## Phase 5: Polish & Responsive

- [x] Add smooth tab transition animations.
- [ ] Test mobile layout (375px+) for all tabs.
- [x] Add dark mode CSS via `@media (prefers-color-scheme: dark)`.
- [x] Verify Chart.js graceful degradation when the embedded asset is unavailable.
- [x] Update header metrics to use telemetry stats instead of recent list.

## Phase 6: Verification

- [x] `go build ./cmd/core-api/...` — compiles with updated embed.
- [ ] Manual test: analysis, telemetry, overrides, and system tabs render correctly.
- [ ] Manual test: override CRUD works from UI.
- [ ] Manual test: telemetry chart updates on period change.
- [ ] Manual test: mobile layout on Chrome DevTools.
