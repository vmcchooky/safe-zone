/**
 * Whitelist snapshots & rollback UI coverage (OZ-11): the System page card
 * backed by GET /v1/whitelist/snapshots and POST /v1/whitelist/rollback.
 * List data is route-mocked so every state is deterministic; the destructive
 * action requires a reason of at least 8 characters and an explicit
 * confirmation, and the POST payload is asserted.
 */
import { test, expect, type Page } from '@playwright/test';

const ADMIN_SESSION = {
  username: 'admin',
  role: 'admin',
  read_only: false,
  can_mutate: true,
  can_view_settings: true,
};

const GUEST_SESSION = {
  username: 'guest',
  role: 'guest',
  read_only: true,
  can_mutate: false,
  can_view_settings: false,
};

const json = (data: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(data),
});

const SNAPSHOTS = {
  snapshots: [
    {
      id: 3,
      created_at: '2026-10-29T01:00:00Z',
      source: 'https://tranco-list.eu/download/L/1000000',
      entry_count: 1_000_000,
      sha256: 'a'.repeat(64),
    },
    {
      id: 2,
      created_at: '2026-10-22T01:00:00Z',
      source: 'https://tranco-list.eu/download/L/1000000',
      entry_count: 999_500,
      sha256: 'b'.repeat(64),
    },
  ],
  last_rollback: null,
};

async function mockSnapshots(page: Page, payload: unknown) {
  await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
  await page.route('**/v1/whitelist/snapshots', (route) => route.fulfill(json(payload)));
  await page.route('**/v1/**', (route) => {
    const url = route.request().url();
    if (url.includes('/v1/auth/session') || url.includes('/v1/whitelist/snapshots')) return route.fallback();
    return route.fulfill(json({ items: [] }));
  });
}

test.describe('whitelist snapshots card', () => {
  test('lists snapshots with metadata and the last rollback record', async ({ page }) => {
    await mockSnapshots(page, {
      snapshots: SNAPSHOTS.snapshots,
      last_rollback: {
        audit_id: 12,
        created_at: '2026-10-28T09:30:00Z',
        snapshot_id: 2,
        entries: 999_500,
        actor: 'admin',
        reason: 'reverting the bad Tranco import',
        revision: 42,
      },
    });

    await page.goto('/app/system');
    const card = page.getByTestId('whitelist-snapshots-card');
    await expect(card).toBeVisible();

    await expect(card.getByText('#3')).toBeVisible();
    await expect(card.getByText('1,000,000')).toBeVisible();
    await expect(card.getByText(/Last rollback:.*snapshot 2 restored by admin/s)).toBeVisible();
  });

  test('shows the empty state when no snapshots exist', async ({ page }) => {
    await mockSnapshots(page, { snapshots: [], last_rollback: null });

    await page.goto('/app/system');
    await expect(page.getByTestId('whitelist-snapshots-empty')).toBeVisible();
  });

  test('shows the error state with a working retry', async ({ page }) => {
    let failing = true;
    await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
    await page.route('**/v1/whitelist/snapshots', (route) => {
      if (failing) {
        return route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: '{"error":"database not available"}',
        });
      }
      return route.fulfill(json(SNAPSHOTS));
    });
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/whitelist/snapshots'))
        return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/system');
    await expect(page.getByTestId('whitelist-snapshots-error')).toBeVisible();

    failing = false;
    await page.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('whitelist-snapshots-card').getByText('#3')).toBeVisible();
  });

  test('blocks rollback without a sufficient reason, then rolls back with one', async ({ page }) => {
    await mockSnapshots(page, SNAPSHOTS);

    let rollbackRequest: { url: string; body: string } | null = null;
    await page.route('**/v1/whitelist/rollback**', (route) => {
      const request = route.request();
      rollbackRequest = { url: request.url(), body: request.postData() ?? '' };
      return route.fulfill(
        json({
          status: 'ok',
          snapshot: 3,
          entries: 1_000_000,
          revision: 55,
          published: false,
          audit_recorded: true,
        }),
      );
    });

    await page.goto('/app/system');
    const card = page.getByTestId('whitelist-snapshots-card');

    // No reason yet: the confirm flow is refused client-side with guidance.
    // The warning is an alert dialog — assert its text before dismissing it.
    await card.getByRole('button', { name: 'Roll back the whitelist to snapshot 3' }).click();
    await expect(page.getByText(/reason of at least 8 characters is required/i)).toBeVisible();
    await page.getByRole('button', { name: 'OK' }).click();
    expect(rollbackRequest).toBeNull();

    // A short reason is still refused.
    await page.getByLabel(/Rollback reason/i).fill('short');
    await card.getByRole('button', { name: 'Roll back the whitelist to snapshot 3' }).click();
    await expect(page.getByText(/reason of at least 8 characters is required/i)).toBeVisible();
    await page.getByRole('button', { name: 'OK' }).click();
    expect(rollbackRequest).toBeNull();

    // A real reason reaches the confirmation and then the API with the id.
    await page.getByLabel(/Rollback reason/i).fill('reverting the bad Tranco import');
    await card.getByRole('button', { name: 'Roll back the whitelist to snapshot 3' }).click();
    await expect(page.getByText(/Restore the whitelist from snapshot 3/)).toBeVisible();
    await page.getByRole('button', { name: 'Roll Back', exact: true }).click();

    await expect.poll(() => rollbackRequest !== null).toBe(true);
    const request = rollbackRequest as { url: string; body: string };
    expect(request.url).toContain('id=3');
    expect(JSON.parse(request.body).reason).toBe('reverting the bad Tranco import');
    await expect(page.getByText(/Whitelist restored to snapshot 3/)).toBeVisible();
  });

  test('disables rollback controls for a read-only session', async ({ page }) => {
    await page.route('**/v1/auth/session', (route) => route.fulfill(json(GUEST_SESSION)));
    await page.route('**/v1/whitelist/snapshots', (route) => route.fulfill(json(SNAPSHOTS)));
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/whitelist/snapshots'))
        return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/system');
    const rollback = page.getByRole('button', { name: 'Roll back the whitelist to snapshot 3' });
    await expect(rollback).toBeDisabled();
    await expect(rollback).toHaveAttribute('title', /read-only/i);
  });
});
