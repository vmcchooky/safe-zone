# Admin dashboard manual QA checklist

Run this checklist before each release candidate that changes dashboard UI, authentication, overrides, group policy, telemetry, or agent controls.

The primary UI is `/app/*`. Run this checklist there; `/dashboard` is a legacy
compatibility route that will be deprecated after the React UI is stable in
production.

## Test setup

- `core-api` is running locally or in staging.
- SQLite is enabled.
- Use one desktop browser and one mobile-width viewport.
- Have a valid admin password or `SAFE_ZONE_ADMIN_API_KEY`.

Suggested sample domains:

- `example.com`
- `secure-login-wallet-example.com`
- `dichvucong-vn.com`

## 1. Login and session

- [ ] Open `/app/analysis` while logged out and confirm the login form renders.
- [ ] Submit invalid credentials and confirm login is rejected.
- [ ] Submit valid credentials and confirm the dashboard shell loads.
- [ ] Refresh the page and confirm the session remains valid.
- [ ] Click logout and confirm the dashboard returns to the login screen.

## 2. Analysis tab

- [ ] Analyze `example.com` and confirm a result card renders.
- [ ] Analyze `secure-login-wallet-example.com` and confirm a non-safe result renders with reasons.
- [ ] Click `Check public evidence` and confirm the request completes without breaking the page.
- [ ] Confirm `Recent activity` updates after analysis.
- [ ] On a non-safe result, enter a review note in `False-positive review` and click `Allow / whitelist domain`.
- [ ] Re-run the same domain and confirm the result now includes `admin override: allow`.

## 3. Overrides tab

- [ ] Confirm the reviewed domain appears in the override list with action `allow`.
- [ ] Use filters `All`, `Allow only`, and `Block only` and confirm results change correctly.
- [ ] Create a manual `block` override with a reason.
- [ ] Confirm the blocked domain appears in the list with updated timestamp.
- [ ] Delete the test override and confirm it disappears from the list.

## 4. Telemetry tab

- [ ] Confirm stats cards load for the selected period.
- [ ] Confirm the chart renders, or a graceful fallback message appears if Chart.js is unavailable.
- [ ] Confirm recent telemetry rows load.
- [ ] For a non-safe telemetry row, click `Review` and confirm the UI switches back to `Analysis` for that domain.

## 5. Clients and policies tab

- [ ] Confirm policy groups load.
- [ ] Create a non-default group with at least one blocked category.
- [ ] Edit the group description or security flags and save changes.
- [ ] Add a client mapping to that group.
- [ ] Add a group override for a test domain.
- [ ] Delete the test mapping and test group override.
- [ ] Confirm the default group cannot be deleted from the UI.

## 6. Agent trigger and system tab

- [ ] Open `System` and confirm service health cards render.
- [ ] Confirm metrics table loads.
- [ ] If Agent Engine is enabled, confirm task status rows load.
- [ ] Trigger one agent task manually and confirm a success toast or a clear error is shown.

## 7. Mobile-width smoke check

- [ ] At a narrow viewport, confirm tab navigation remains usable.
- [ ] Confirm result cards, override forms, and telemetry rows remain readable without overlapping text.
- [ ] Confirm buttons for review, delete, and trigger remain tappable.

## Release sign-off

- [ ] All checks passed on desktop.
- [ ] All checks passed on mobile-width viewport.
- [ ] Any failed checks are linked to a tracked issue or block the release.
