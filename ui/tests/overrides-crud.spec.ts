/**
 * Overrides CRUD coverage: list rendering, the empty state, add via the
 * inline form (success and validation-failure paths), and delete through the
 * shared confirm dialog. All API state is route-mocked; no arbitrary waits.
 */
import { test, expect, type Page } from '@playwright/test';

const ADMIN_SESSION = {
  username: 'admin',
  role: 'admin',
  read_only: false,
  can_mutate: true,
  can_view_settings: true,
};

const json = (data: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(data),
});

const OVERRIDE = (domain: string, action: 'allow' | 'block', source = 'manual') => ({
  domain,
  action,
  reason: 'e2e fixture',
  source,
  created_at: '2026-10-29T00:00:00Z',
});

async function mockOverrides(page: Page, items: ReturnType<typeof OVERRIDE>[]) {
  await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
  await page.route('**/v1/overrides**', (route) => {
    const request = route.request();
    if (request.method() === 'GET') return route.fulfill(json({ items }));
    return route.fallback();
  });
  await page.route('**/v1/**', (route) => {
    if (
      route.request().url().includes('/v1/auth/session') ||
      route.request().url().includes('/v1/overrides')
    ) {
      return route.fallback();
    }
    return route.fulfill(json({ items: [] }));
  });
}

test.describe('overrides page', () => {
  test('renders the empty state when no overrides exist', async ({ page }) => {
    await mockOverrides(page, []);
    await page.goto('/app/overrides');

    await expect(page.getByRole('heading', { name: 'No Overrides Found' })).toBeVisible();
  });

  test('renders the failure state when the list request fails', async ({ page }) => {
    await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
    await page.route('**/v1/overrides**', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"store unavailable"}' }),
    );
    await page.route('**/v1/**', (route) => {
      if (
        route.request().url().includes('/v1/auth/session') ||
        route.request().url().includes('/v1/overrides')
      ) {
        return route.fallback();
      }
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/overrides');
    await expect(page.getByRole('heading', { name: 'Failed to load overrides' })).toBeVisible();
    await expect(page.getByText('store unavailable')).toBeVisible();
  });

  test('adds an override through the inline form and shows it in the table', async ({ page }) => {
    const items = [OVERRIDE('existing.example', 'block')];
    await mockOverrides(page, items);

    let created: { body: string } | null = null;
    await page.route('**/v1/overrides**', (route) => {
      const request = route.request();
      if (request.method() === 'POST') {
        created = { body: request.postData() ?? '' };
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(OVERRIDE('new-rule.example', 'allow')),
        });
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    await expect(page.getByText('existing.example')).toBeVisible();
    const overrideForm = page
      .locator('section', { has: page.getByRole('heading', { name: 'Add New Override' }) })
      .first();

    // The action control is a toggle button showing the current action
    // ("Block" by default); click it once to submit an allow override.
    await page.getByPlaceholder('e.g., trusted-domain.com').fill('new-rule.example');
    await page.getByPlaceholder('Reason for override...').fill('allowlisted by ops');
    await page.getByRole('button', { name: 'Block', exact: true }).click();
    await overrideForm.getByRole('button', { name: 'Add', exact: true }).click();

    await expect.poll(() => created !== null).toBe(true);
    const body = JSON.parse((created as { body: string }).body);
    expect(body.domain).toBe('new-rule.example');
    expect(body.action).toBe('allow');
    expect(body.reason).toBe('allowlisted by ops');
  });

  test('surfaces the server error when the create fails', async ({ page }) => {
    await mockOverrides(page, []);
    await page.route('**/v1/overrides**', (route) => {
      if (route.request().method() === 'POST') {
        return route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: '{"error":"invalid domain"}',
        });
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    const overrideForm = page
      .locator('section', { has: page.getByRole('heading', { name: 'Add New Override' }) })
      .first();
    await page.getByPlaceholder('e.g., trusted-domain.com').fill('bad..domain');
    await page.getByPlaceholder('Reason for override...').fill('testing failure path');
    await overrideForm.getByRole('button', { name: 'Add', exact: true }).click();

    await expect(page.getByText('invalid domain')).toBeVisible();
  });

  test('deletes an override through the confirm dialog', async ({ page }) => {
    await mockOverrides(page, [OVERRIDE('doomed.example', 'block')]);

    let deleted = false;
    await page.route('**/v1/overrides**', (route) => {
      if (route.request().method() === 'DELETE') {
        deleted = true;
        return route.fulfill(json({ status: 'deleted' }));
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    await expect(page.getByText('doomed.example')).toBeVisible();

    await page.getByRole('button', { name: 'Delete the override for doomed.example' }).click();
    // The shared confirm dialog quotes the domain before acting.
    await expect(page.getByText('Delete override for doomed.example?')).toBeVisible();
    await page.getByRole('button', { name: 'OK', exact: true }).click();

    await expect.poll(() => deleted).toBe(true);
  });
});
