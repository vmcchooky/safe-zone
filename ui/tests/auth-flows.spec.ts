/**
 * Auth-flow regression specs: session expiry, logout, server-side 403
 * rendering, and the /settings read-only redirect.
 *
 * All state is route-mocked (no arbitrary waits; every wait is a role or
 * response wait), following the extreme-data harness conventions. The real
 * login flow itself is covered by analysis.spec.ts.
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

async function mockSession(page: Page, status: number, body: unknown) {
  await page.route('**/v1/auth/session', (route) =>
    route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }),
  );
}

test.describe('session expiry', () => {
  test('an expired session renders the login screen instead of the workspace', async ({ page }) => {
    await mockSession(page, 401, { error: 'unauthorized' });
    // The provider also probes the analysis feed; abort noise is irrelevant
    // to the assertion because the login card replaces the workspace.
    await page.route('**/v1/**', (route) => {
      if (route.request().url().includes('/v1/auth/session')) return route.fallback();
      return route.abort();
    });

    await page.goto('/app/analysis');

    await expect(page.getByTestId('login-card')).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toHaveCount(0);
  });

  test('a revoked session drops the operator back to login on the next probe', async ({ page }) => {
    // First probe succeeds (operator was logged in), the next one 401s —
    // the shape of a session revoked server-side between polls.
    let probes = 0;
    await page.route('**/v1/auth/session', (route) => {
      probes += 1;
      if (probes === 1) return route.fulfill(json(ADMIN_SESSION));
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: '{"error":"session revoked"}',
      });
    });
    await page.route('**/v1/**', (route) => {
      if (route.request().url().includes('/v1/auth/session')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/analysis');
    await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toBeVisible();

    // Force the provider to re-probe by reloading; the second probe 401s.
    await page.reload();
    await expect(page.getByTestId('login-card')).toBeVisible();
  });
});

test.describe('logout', () => {
  test('sign out clears the session and returns to the login card', async ({ page }) => {
    await mockSession(page, 200, ADMIN_SESSION);
    let logoutCalled = false;
    await page.route('**/v1/auth/logout', (route) => {
      logoutCalled = true;
      return route.fulfill(json({ status: 'ok' }));
    });
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/auth/logout')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/analysis');
    await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toBeVisible();

    await page.getByTitle('Sign Out').click();

    await expect(page.getByTestId('login-card')).toBeVisible();
    expect(logoutCalled).toBe(true);
  });
});

test.describe('server-side authorization', () => {
  test('a 403 mutation response surfaces the server message through the confirm flow', async ({ page }) => {
    // The session says admin (mutation controls enabled), but the server
    // downgrades the request — the shape of a session revoked or downgraded
    // between page load and click. The client must render the server's
    // message instead of assuming success.
    await mockSession(page, 200, ADMIN_SESSION);
    await page.route('**/v1/cache/flush', (route) =>
      route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Khách không được quyền thay đổi cài đặt hệ thống' }),
      }),
    );
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/cache/flush')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/system');
    await page.getByRole('button', { name: 'Flush Cache' }).click();
    // Shared confirm dialog: OK is the confirm action.
    await page.getByRole('button', { name: 'OK' }).click();

    await expect(page.getByText('Khách không được quyền thay đổi cài đặt hệ thống')).toBeVisible();
  });

  test('the settings route redirects a session without settings access', async ({ page }) => {
    await mockSession(page, 200, GUEST_SESSION);
    await page.route('**/v1/**', (route) => {
      if (route.request().url().includes('/v1/auth/session')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/settings');

    await expect(page).toHaveURL(/\/app\/analysis$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Domain Inspection');
  });
});
