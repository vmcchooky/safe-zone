/**
 * Trusted Brands CRUD coverage (OZ-12): list, empty and error states, create,
 * edit (PUT), and delete through the shared confirm dialog — plus the
 * client-side validation and read-only gating. All API state is route-mocked.
 */
import { test, expect } from '@playwright/test';

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

const BRAND = (id: number, name: string) => ({
  id,
  name,
  official_domain: `${name}.com.vn`,
  alt_domains: [`${name}.com`],
  created_at: '2026-10-29T00:00:00Z',
  updated_at: '2026-10-29T00:00:00Z',
});

async function mockBrands(page: import('@playwright/test').Page, items: ReturnType<typeof BRAND>[]) {
  await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
  await page.route('**/v1/brands**', (route) => {
    if (route.request().method() === 'GET') return route.fulfill(json({ items }));
    return route.fallback();
  });
  await page.route('**/v1/**', (route) => {
    const url = route.request().url();
    if (url.includes('/v1/auth/session') || url.includes('/v1/brands')) return route.fallback();
    return route.fulfill(json({ items: [] }));
  });
}

test.describe('brands card', () => {
  test('lists brands with metadata', async ({ page }) => {
    await mockBrands(page, [BRAND(1, 'vietcombank'), BRAND(2, 'tinkercad')]);
    await page.goto('/app/overrides');

    const card = page.getByTestId('brands-card');
    await expect(card).toBeVisible();
    await expect(card.getByRole('cell', { name: 'vietcombank', exact: true })).toBeVisible();
    await expect(card.getByRole('cell', { name: 'vietcombank.com.vn' })).toBeVisible();
    await expect(card.getByRole('cell', { name: 'vietcombank.com', exact: true })).toBeVisible();
  });

  test('shows the empty state when no brand rules exist', async ({ page }) => {
    await mockBrands(page, []);
    await page.goto('/app/overrides');
    await expect(page.getByTestId('brands-empty')).toBeVisible();
  });

  test('shows the failure state when the list request fails', async ({ page }) => {
    await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
    await page.route('**/v1/brands**', (route) =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: '{"error":"database not available"}',
      }),
    );
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/brands')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/overrides');
    await expect(page.getByTestId('brands-error')).toBeVisible();
    await expect(page.getByText('database not available')).toBeVisible();
  });

  test('creates a brand with alternates and rejects an invalid domain client-side', async ({ page }) => {
    await mockBrands(page, []);

    let created: { url: string; body: string } | null = null;
    await page.route('**/v1/brands**', (route) => {
      if (route.request().method() === 'POST') {
        created = { url: route.request().url(), body: route.request().postData() ?? '' };
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify(BRAND(9, 'newbank')),
        });
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    const card = page.getByTestId('brands-card');

    await card.getByPlaceholder('Brand name (e.g., vietcombank)').fill('newbank');
    // Invalid official domain: client-side validation, no request.
    await card.getByPlaceholder('Official domain (e.g., vietcombank.com.vn)').fill('not a domain');
    await card.getByRole('button', { name: 'Add', exact: true }).click();
    await expect(page.getByTestId('brands-form-error')).toContainText(
      'Official domain must be a valid domain',
    );
    expect(created).toBeNull();

    await card.getByPlaceholder('Official domain (e.g., vietcombank.com.vn)').fill('newbank.com.vn');
    await card.getByPlaceholder('Alternate domains, comma-separated (optional)').fill('newbank.com, nb.vn');
    await card.getByRole('button', { name: 'Add', exact: true }).click();

    await expect.poll(() => created !== null).toBe(true);
    const request = created as { url: string; body: string };
    expect(request.url).not.toContain('id=');
    const body = JSON.parse(request.body);
    expect(body.name).toBe('newbank');
    expect(body.official_domain).toBe('newbank.com.vn');
    expect(body.alt_domains).toEqual(['newbank.com', 'nb.vn']);
    await expect(page.getByText('Brand "newbank" created.')).toBeVisible();
  });

  test('edits a brand through the PUT path', async ({ page }) => {
    await mockBrands(page, [BRAND(4, 'oldbank')]);

    let updated: { url: string; body: string } | null = null;
    await page.route('**/v1/brands**', (route) => {
      if (route.request().method() === 'PUT') {
        updated = { url: route.request().url(), body: route.request().postData() ?? '' };
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(BRAND(4, 'oldbank')),
        });
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    const card = page.getByTestId('brands-card');
    await expect(card.getByRole('cell', { name: 'oldbank', exact: true })).toBeVisible();

    await card.getByRole('button', { name: 'Edit the brand rule for oldbank' }).click();
    await expect(card.getByRole('button', { name: 'Save', exact: true })).toBeVisible();
    await card.getByPlaceholder('Brand name (e.g., vietcombank)').fill('renamedbank');
    await card.getByRole('button', { name: 'Save', exact: true }).click();

    await expect.poll(() => updated !== null).toBe(true);
    const request = updated as { url: string; body: string };
    expect(request.url).toContain('id=4');
    expect(JSON.parse(request.body).name).toBe('renamedbank');
  });

  test('deletes a brand through the confirm dialog', async ({ page }) => {
    await mockBrands(page, [BRAND(4, 'doomedbank')]);

    let deleted = false;
    await page.route('**/v1/brands**', (route) => {
      if (route.request().method() === 'DELETE') {
        deleted = true;
        return route.fulfill(json({ status: 'deleted', id: 4 }));
      }
      return route.fallback();
    });

    await page.goto('/app/overrides');
    const card = page.getByTestId('brands-card');
    await expect(card.getByRole('cell', { name: 'doomedbank', exact: true })).toBeVisible();

    await card.getByRole('button', { name: 'Delete the brand rule for doomedbank' }).click();
    await expect(page.getByText('Delete the brand rule for doomedbank?')).toBeVisible();
    await page.getByRole('button', { name: 'OK', exact: true }).click();

    await expect.poll(() => deleted).toBe(true);
    await expect(page.getByText('Brand "doomedbank" deleted.')).toBeVisible();
  });

  test('disables mutation controls for a read-only session', async ({ page }) => {
    await page.route('**/v1/auth/session', (route) => route.fulfill(json(GUEST_SESSION)));
    await page.route('**/v1/brands**', (route) => {
      if (route.request().method() === 'GET')
        return route.fulfill(json({ items: [BRAND(1, 'vietcombank')] }));
      return route.fallback();
    });
    await page.route('**/v1/**', (route) => {
      const url = route.request().url();
      if (url.includes('/v1/auth/session') || url.includes('/v1/brands')) return route.fallback();
      return route.fulfill(json({ items: [] }));
    });

    await page.goto('/app/overrides');
    const card = page.getByTestId('brands-card');
    await expect(card.getByPlaceholder('Brand name (e.g., vietcombank)')).toBeDisabled();
    const del = card.getByRole('button', { name: 'Delete the brand rule for vietcombank' });
    await expect(del).toBeDisabled();
    await expect(del).toHaveAttribute('title', /read-only/i);
  });
});
