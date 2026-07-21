# Safe Zone UI Workspace

`ui/` is the source workspace for the primary operator UI, embedded by
`core-api` and served at `/app/`. It remains outside Go `internal/` packages
because it is a Node.js/React workspace.

## UI routing policy

- Primary UI: `/app/*`
- `/dashboard` redirects to `/app/`

The React UI is the sole operator interface. The redirect keeps existing
`/dashboard` bookmarks working without exposing the legacy template.

## Verification

```sh
npm run check
npm run test:e2e
```

Playwright starts an isolated React/API pair by default on ports `15173` and
`18080`; it never reuses servers on the normal development ports `5173` and
`8080`. Override these only when necessary:

```sh
SAFE_ZONE_E2E_UI_PORT=15174 SAFE_ZONE_E2E_API_PORT=18081 npm run test:e2e
```
