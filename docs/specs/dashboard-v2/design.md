# Design: Admin Dashboard v2

## Architecture

Single embedded HTML file (`dashboard.html`, `//go:embed`), no build step. All state managed in a vanilla JS `state` object. New sections added as tabs alongside existing functionality.

## Tab Structure

```
┌──────────┬───────────┬───────────┬─────────┐
│ Analysis │ Telemetry │ Overrides │ System  │
└──────────┴───────────┴───────────┴─────────┘
```

- **Analysis** (existing): Domain analyzer + live result + recent activity.
- **Telemetry** (new): Stats cards + verdict chart + paginated history.
- **Overrides** (new): Override list + add/delete forms.
- **System** (new): Health, metrics, uptime.

Only one tab's content is visible at a time. Tab state managed via CSS class toggling.

## API Dependencies

All APIs already exist from previous work:

| API | Used By Tab | Method |
|---|---|---|
| `POST /v1/analyze` | Analysis | Analyze domain |
| `GET /v1/analysis/recent` | Analysis | Recent results (Redis) |
| `GET /v1/telemetry/stats?period=24h` | Telemetry | Aggregate stats |
| `GET /v1/telemetry/recent?limit=20` | Telemetry | Paginated history |
| `GET /v1/overrides` | Overrides | List overrides |
| `POST /v1/overrides` | Overrides | Add/update override |
| `DELETE /v1/overrides?domain=x` | Overrides | Remove override |
| `GET /healthz` | System | Health check |
| `GET /metrics` | System | Request metrics |
| `GET /` | System | Service status + Redis info |

## UI Component Designs

### Telemetry Tab

```
┌─────────────────────────────────────────────┐
│  [24h] [7d] [30d]           Period Selector │
├──────────┬──────────┬──────────┬────────────┤
│  Total   │   Safe   │ Suspect  │ Malicious  │
│  1,234   │   890    │   210    │    134     │
├──────────┴──────────┴──────────┴────────────┤
│          ┌────────────────┐                 │
│          │   Doughnut     │   Legend        │
│          │   Chart.js     │   • Safe 72%    │
│          │                │   • Suspicious  │
│          │                │   • Malicious   │
│          └────────────────┘                 │
├─────────────────────────────────────────────┤
│  Recent Telemetry Table (paginated)         │
│  Domain | Verdict | Score | Source | Time   │
│  ─────────────────────────────────────────  │
│  evil.com | MALICIOUS | 95 | feed | 12:01  │
│  ok.com   | SAFE      |  0 | cache | 12:00 │
│  ...                                        │
│  [← Prev] Page 1 of 5 [Next →]             │
└─────────────────────────────────────────────┘
```

### Overrides Tab

```
┌──────────────────────────────────────────────┐
│  Add Override                                │
│  ┌─────────────┐ ┌────┐ ┌────┐ ┌──────────┐ │
│  │ domain.com  │ │Allow│ │Block│ │  Reason  │ │
│  └─────────────┘ └────┘ └────┘ └──────────┘ │
│  [Add Override]                              │
├──────────────────────────────────────────────┤
│  Filter: [All ▼] [Allow] [Block]             │
├──────────────────────────────────────────────┤
│  Override List                               │
│  Domain      │ Action │ Reason    │ Actions  │
│  ──────────────────────────────────────────  │
│  evil.com    │ Block  │ phishing  │ [Delete] │
│  trust.com   │ Allow  │ internal  │ [Delete] │
└──────────────────────────────────────────────┘
```

### System Tab

```
┌─────────────────────────────────────────────┐
│  Service Status                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ core-api │ │  Redis   │ │   SQLite     │ │
│  │ ● online │ │ ● online │ │  ● online    │ │
│  └──────────┘ └──────────┘ └──────────────┘ │
├──────────────────────────────────────────────┤
│  Uptime: 4d 12h 33m                         │
│  Total Requests: 45,231                      │
│  Avg Latency: 12ms                           │
├──────────────────────────────────────────────┤
│  Request Breakdown (from /metrics)           │
│  GET /v1/analyze 200     │ 12,345 │ 15ms avg│
│  POST /dns-query 200     │ 30,120 │ 8ms avg │
│  GET /healthz 200        │  2,766 │ 1ms avg │
└──────────────────────────────────────────────┘
```

## Chart.js Integration

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
```

- Loaded from CDN. If CDN unavailable, chart simply doesn't render (graceful degradation).
- One `<canvas>` element per chart. Chart instance stored in JS state.
- Chart updated on tab switch and period change (`.data.datasets[0].data = [...]`, `.update()`).

## CSS Architecture

Extend existing CSS custom properties:

```css
/* Tab navigation */
.tabs { display: flex; gap: 4px; }
.tab { padding: 8px 16px; cursor: pointer; border-radius: 12px; }
.tab.active { background: var(--accent); color: white; }

/* Tab content */
.tab-content { display: none; }
.tab-content.active { display: block; }
```

Dark mode (optional toggle):
```css
@media (prefers-color-scheme: dark) {
  :root {
    --ink: #e4e8ec;
    --bg: #0f1419;
    --panel: rgba(30, 40, 50, 0.88);
    /* ... */
  }
}
```

## State Management

```javascript
const state = {
  activeTab: 'analysis',
  latest: null,
  recent: [],
  telemetry: { stats: {}, recent: [], page: 0, pageSize: 20 },
  overrides: { items: [], filter: '' },
  system: { health: {}, metrics: {}, status: {} },
};
```

Tab switching:
```javascript
function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelector(`#tab-${tabName}`).classList.add('active');
  // Load data for the newly active tab
  loadTabData(tabName);
}
```

## Polling Strategy

- **Every 15 seconds** (unchanged from current):
  - Health check (`/healthz`)
  - Refresh data for the **active tab only** (avoid unnecessary API calls).
- **On tab switch**: Immediate data load for the new tab.
- **On user action**: Immediate refresh after mutations (add/delete override, analyze domain).

## Files Changed

| File | Change |
|---|---|
| `cmd/core-api/dashboard.html` | Major rewrite: add tabs, telemetry, overrides, system |
| `cmd/core-api/main.go` | No changes needed (all APIs already exist) |

## What This Design Excludes

- Dark mode toggle button (CSS `prefers-color-scheme` only for now).
- Real-time updates (WebSocket/SSE).
- Advanced filtering (date range, regex search).
- Export functionality (CSV, PDF).
