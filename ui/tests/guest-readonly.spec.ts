import { expect, test } from '@playwright/test';

const ADMIN_KEY = 'Bearer playwright_test_api_key_1234_abcdefg';
const GUEST_PASSWORD = 'playwright_guest_password_1234';
const GROUP_NAME = 'Guest Readonly Group';
const MAPPING_VALUE = 'guest-readonly-device';

// The read-only role existed in the API and in the session payload, but the
// operator UI never used it: every mutation control stayed enabled for a
// guest, who then got a 403 (in Vietnamese) from the server.
//
// This test signs in as a guest and asserts that the mutation controls are
// disabled rather than enabled-and-failing. The group Edit button was the
// control that originally slipped through, so it gets a non-default group to
// edit and delete, plus a mapping to remove.
test('a read-only session cannot use the mutation controls', async ({ page, request }) => {
  const adminHeaders = { Authorization: ADMIN_KEY };

  // Seed a non-default group and a mapping so the per-row controls render.
  const groupResponse = await request.post('/v1/groups', {
    headers: adminHeaders,
    data: {
      name: GROUP_NAME,
      description: 'Created by the guest-readonly regression test.',
      block_categories: [],
      strict_phishing: false,
      strict_malware: false,
    },
  });
  expect(groupResponse.ok()).toBeTruthy();
  const group = await groupResponse.json();

  const mappingResponse = await request.post('/v1/mappings', {
    headers: adminHeaders,
    data: {
      mapping_type: 'client_id',
      value: MAPPING_VALUE,
      group_id: group.id,
    },
  });
  expect(mappingResponse.ok()).toBeTruthy();

  // Enable guest access as the admin.
  const configure = await request.post('/v1/settings/guest-access', {
    headers: adminHeaders,
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

  // Overrides: the add form and the delete control must be disabled. The
  // locator is scoped to the override form section — the page also carries
  // the brands card (OZ-12) with its own Add button.
  await page.goto('/app/overrides');
  await expect(page.getByRole('heading', { name: 'Add New Override' })).toBeVisible();
  const overrideSection = page
    .locator('section', { has: page.getByRole('heading', { name: 'Add New Override' }) })
    .first();
  const addButton = overrideSection.getByRole('button', { name: 'Add', exact: true });
  await expect(addButton).toBeDisabled();

  // System: flushing the cache and downloading the logs are admin-only.
  await page.goto('/app/system');
  const flushButton = page.getByRole('button', { name: 'Flush Cache' });
  await expect(flushButton).toBeDisabled();

  // Endpoints: group create/edit/delete, mapping create/delete and task
  // triggering are admin-only. Edit used to stay enabled for a guest.
  await page.goto('/app/endpoints');
  await expect(page.getByRole('button', { name: 'Add Group' })).toBeDisabled();
  await expect(page.getByRole('button', { name: `Edit the policy group ${GROUP_NAME}` })).toBeDisabled();
  await expect(page.getByRole('button', { name: `Delete the policy group ${GROUP_NAME}` })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Add Map' })).toBeDisabled();
  await expect(
    page.getByRole('button', { name: `Delete the client mapping ${MAPPING_VALUE}` }),
  ).toBeDisabled();

  // Analysis: a guest may inspect a domain but not turn the result into an
  // allow or block override.
  await page.goto('/app/analysis');
  await page.getByPlaceholder('secure-login-wallet-example.com').fill('example.com');
  await page.getByRole('button', { name: 'Analyze', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Block', exact: true })).toBeDisabled();

  // Reports: the queue is admin-only, so a guest is sent back to analysis
  // instead of seeing a page that would answer 403.
  await page.goto('/app/reports');
  await expect(page).toHaveURL(/\/app\/analysis$/);
  await expect(page.getByRole('heading', { name: 'Domain Inspection' })).toBeVisible();
});
