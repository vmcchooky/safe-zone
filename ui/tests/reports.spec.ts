import { expect, test } from '@playwright/test';

test('turns a user report into an audited allow decision', async ({ page, request }) => {
  const domain = 'legitimate-partner.example';
  const reportResponse = await request.post('/block/report', {
    form: {
      domain,
      contact: 'support-ticket@example.com',
      note: 'Partner portal was blocked during acceptance testing.',
    },
  });
  expect(reportResponse.ok()).toBeTruthy();

  // Use the admin API key for this operator-flow test so parallel login UI
  // coverage cannot exhaust the authentication rate limit.
  await page.setExtraHTTPHeaders({
    Authorization: 'Bearer playwright_test_api_key_1234_abcdefg',
  });
  await page.goto('/app/reports');

  const reportRow = page.getByRole('row').filter({ hasText: domain });
  await expect(reportRow).toBeVisible();
  await reportRow.getByRole('button', { name: 'Allow' }).click();

  const dialog = page.getByRole('dialog', { name: 'Allow domain as false positive' });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Review reason *').fill(
    'Verified against support ticket FP-101; keep the allow override until classifier retraining is complete.',
  );
  await dialog.getByRole('button', { name: 'Confirm decision' }).click();

  await expect(page.getByText(`Allowed ${domain} and resolved related pending reports.`)).toBeVisible();
  await expect(reportRow).toHaveCount(0);
  await expect(page.getByLabel('Report queue summary')).toContainText('Resolved');
  await expect(page.getByLabel('Report queue summary')).toContainText('1');
});
