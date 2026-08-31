import { test, expect } from '@playwright/test';

/**
 * Regression: pressing Next/Previous on the telemetry table used to yank the
 * viewport away from the pagination bar — animated rows mounted/unmounted
 * around the page flip and the browser's scroll anchoring dragged the
 * container up by one page of rows, forcing the user to scroll back down to
 * click Next again. The fix pins the scroll position across a bounded settle
 * window (overflow-anchor disabled on .shell-main) — this test locks that in.
 */

const SEED_DOMAINS = Array.from({ length: 26 }, (_, i) => `telemetry-probe-${String(i).padStart(2, '0')}.example.com`);

async function seedTelemetry(request: import('@playwright/test').APIRequestContext) {
  const login = await request.post('/v1/auth/login', {
    data: { username: 'admin', password: 'playwright_test_password_1234' },
  });
  if (!login.ok()) throw new Error(`seed login failed: ${login.status()}`);
  for (const domain of SEED_DOMAINS) {
    const res = await request.post('/v1/analyze', { data: { domain }, timeout: 30000 });
    if (!res.ok()) throw new Error(`seed analyze ${domain} failed: ${res.status()}`);
  }
}

test('keeps the pagination bar in view when flipping telemetry pages', async ({ page }) => {
  test.setTimeout(120000);
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  await seedTelemetry(page.request);

  // page.request shares the browser context's cookie jar, so the seed login
  // already authenticates the page — no UI login needed.
  await page.goto('/app/telemetry');
  await expect(page.getByRole('heading', { name: 'Network Telemetry' })).toBeVisible({ timeout: 30000 });
  await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 20000 });

  // The telemetry writer persists analyses asynchronously; wait until at
  // least two full pages exist before exercising pagination.
  await expect(async () => {
    const count = await page.evaluate(async () => {
      const res = await fetch('/v1/telemetry/recent?limit=100&offset=0', { credentials: 'same-origin' });
      const body = await res.json();
      return Array.isArray(body?.items) ? body.items.length : 0;
    });
    expect(count).toBeGreaterThanOrEqual(SEED_DOMAINS.length);
  }).toPass({ timeout: 30000 });

  await page.reload();
  await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 20000 });

  // Land on the bottom of page 1, where the pagination bar lives.
  await page.locator('.shell-main').evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await page.waitForTimeout(250);

  const before = await page.locator('.shell-main').evaluate((el) => ({
    scrollTop: Math.round(el.scrollTop),
    scrollHeight: el.scrollHeight,
    clientHeight: el.clientHeight,
    rows: document.querySelectorAll('tbody tr').length,
    firstRow: document.querySelector('tbody tr strong')?.textContent ?? '',
  }));
  expect(before.rows).toBe(12);

  await page.getByRole('button', { name: 'Next' }).click();

  // Page 2 must actually load (the first row changes) and the crossfade must
  // settle back to a single 12-row table before asserting the scroll state.
  await expect.poll(async () => {
    const state = await page.locator('.shell-main').evaluate((el) => ({
      rows: document.querySelectorAll('tbody tr').length,
      scrollHeight: el.scrollHeight,
      firstRow: document.querySelector('tbody tr strong')?.textContent ?? '',
    }));
    return state.rows === 12 && state.scrollHeight === before.scrollHeight && state.firstRow !== before.firstRow
      ? state.firstRow
      : null;
  }, { timeout: 15000 }).toBeTruthy();

  // The viewport must still be pinned at the bottom of the table: the
  // pagination bar stays on screen and the user can click Next again
  // without scrolling. Before the fix, scroll anchoring dragged the
  // container up by a full page of rows here.
  const after = await page.locator('.shell-main').evaluate((el) => ({
    scrollTop: Math.round(el.scrollTop),
    maxScroll: el.scrollHeight - el.clientHeight,
  }));
  expect(Math.abs(after.maxScroll - after.scrollTop)).toBeLessThanOrEqual(8);
  await expect(page.getByRole('button', { name: 'Next' })).toBeVisible();

  expect(pageErrors).toEqual([]);
});
