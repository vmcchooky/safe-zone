# Requirements: Guest Read-Only Dashboard

## Goal

Add a `guest` dashboard role that can inspect Safe Zone data and run read-only workflows from `/dashboard`, while ensuring guest actions can never mutate policy, settings, or runtime state.

## Security Position

This feature intentionally expands the authenticated surface area, so server-side enforcement is mandatory.

- Guest permissions must never rely on disabled buttons alone.
- The repository must not hard-code or auto-seed a globally enabled public guest credential into every environment.
- Admin must be able to create, enable, disable, rotate, or delete the guest account manually.

## Risk Assessment

Key risks introduced by a public guest account:

1. Credential sharing and brute-force pressure increase because `guest` becomes a known username.
2. Any handler that only trusts “authenticated” instead of “admin” becomes a privilege-escalation risk.
3. Read-only views can still leak operational detail if sensitive endpoints are not explicitly scoped.
4. Client-side read-only UX can be bypassed unless the backend rejects every mutation path.

Required mitigations:

- Role information must be carried in the signed session claims.
- Bearer API key access remains admin-only.
- Guest sessions must be blocked from every mutation endpoint with a clear `403` response.
- Login rate limiting must explicitly cover `/v1/auth/login`.
- Guest password storage must use a password hash, not plaintext system config.
- Settings and other secret-adjacent views must remain admin-only.

## Functional Requirements

- Authentication must support at least two roles: `admin` and `guest`.
- The dashboard session endpoint must expose the authenticated username, role, and read-only capabilities to the UI.
- Guest users must be able to:
  - open `/dashboard`
  - analyze domains
  - inspect telemetry and recent activity
  - inspect read-only policy/group/mapping/report data that is safe to expose
- Guest users must not be able to:
  - create, edit, approve, delete, or trigger anything
  - change overrides, groups, mappings, reports, brands, settings, or analysis config
  - trigger agent tasks
  - view secret-bearing settings screens
- The dashboard must display a persistent read-only banner for guest sessions with this message:
  - `Khách không được quyền thay đổi hoặc áp dụng các chính sách mới vào hệ thống, nếu muốn hãy liên hệ với quản trị viên của Safe Zone DNS tại contact@quorix.io.vn.`
- The UI should stop obvious mutation attempts early and show the same read-only message as a toast or inline notice.
- Admin must have a management surface to:
  - create or enable the guest account with a chosen password
  - disable the guest account without deleting it
  - delete the guest account entirely
  - inspect current guest status

## Non-Goals

- No MFA rollout in this change.
- No multi-user admin directory or third-party identity provider in this change.
- No permission model beyond `admin` vs `guest` in this change.

## Acceptance Criteria

- A guest session can load the dashboard and use read-only analysis workflows.
- Every guest mutation attempt receives `403 Forbidden`, even if the request is forged manually.
- Admin-only settings endpoints remain inaccessible to guest sessions.
- The dashboard shows the required guest warning banner and does not expose the settings tab to guests.
- Admin can enable, disable, and delete the guest account from the control plane.
- Guest credentials are stored hashed.
- Focused auth and dashboard tests pass.
