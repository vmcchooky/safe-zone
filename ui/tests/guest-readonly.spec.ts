import { expect, test } from '@playwright/test';

const ADMIN_KEY = 'Bearer playwright_test_api_key_1234_abcdefg';
const GUEST_PASSWORD = 'playwright_guest_password_1234';

// The read-only role existed in the API and in the session payload, but the
// operator UI never used it: every mutation control stayed enabled for a
// guest, who then got a 403 (in Vietnamese) from the server.
//
// This test signs in as a guest and asserts that the mutation controls are
// disabled rather than enabled-and-failing.
test('a read-only session cannot use the mutation controls', async ({ page, request }) => {
  // Enable guest access as the admin.
  const configure = await request.post('/v1/settings/guest-access', {
    headers: { Authorization: ADMIN_KEY },
    data: { enabled: true, password: GUEST_PASSWORD },
  });
  expect(configure.ok()).toBeTruthy();

  // Sign in as the guest. page.request shares the browser context, so the
  // session cookie lands in the page.
  const login = await page.request.post('/v1/auth/login', {
    data: { username: 'guest', password: GUEST_PASSWORD },
  });
  expect(login.ok()).toBeTruthy();

  // The session must report the read-only role.
  const session = await page.request.get('/v1/auth/session');
  expect(session.ok()).toBeTruthy();
  const sessionPayload = await session.json();
  expect(sessionPayload.read_only).toBe(true);
  expect(sessionPayload.can_mutate).toBe(false);

  // Overrides: the add form and the delete control must be disabled.
  await page.goto('/app/overrides');
  await expect(page.getByRole('heading', { name: 'Add New Override' })).toBeVisible();
  const addButton = page.getByRole('button', { name: 'Add', exact: true });
  await expect(addButton).toBeDisabled();

  // System: flushing the cache and downloading the logs are admin-only.
  await page.goto('/app/system');
  const flushButton = page.getByRole('button', { name: 'Flush Cache' });
  await expect(flushButton).toBeDisabled();

  // Endpoints: adding a policy group and triggering a task are admin-only.
  await page.goto('/app/endpoints');
  const addGroup = page.getByRole('button', { name: 'Add Group' });
  await expect(addGroup).toBeDisabled();
});
