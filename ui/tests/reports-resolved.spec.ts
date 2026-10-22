import { expect, test } from '@playwright/test';

// Resolving a report is not a record-only action: the server runs the same
// atomic transaction as the false-positive review path, so it creates a
// global allow override and the domain stops being blocked everywhere.
//
// The dialog used to say "Resolve report without override", which told the
// operator the opposite of what happens. This test pins the wording and the
// observable effect together, so the copy and the behaviour cannot drift
// apart again.
test('resolving a report also allows the domain, and the dialog says so', async ({ page, request }) => {
  const domain = 'resolved-partner.example';
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

  await reportRow
    .getByRole('button', { name: `Resolve the report for ${domain} and stop blocking it` })
    .click();

  const dialog = page.getByRole('dialog', { name: 'Resolve report and allow the domain' });
  await expect(dialog).toBeVisible();

  // The side effect must be stated, not implied.
  await expect(dialog).toContainText('creates a global allow override');

  await dialog
    .getByLabel('Review reason *')
    .fill('Verified against support ticket FP-102; the domain stays allowed afterwards.');
  await dialog.getByRole('button', { name: 'Confirm decision' }).click();

  await expect(
    page.getByText(`Resolved the report and allowed ${domain}. The domain is no longer blocked.`),
  ).toBeVisible();
  await expect(reportRow).toHaveCount(0);
  await expect(page.getByLabel('Report queue summary')).toContainText('Resolved');

  // The allow override must exist: the domain is answered SAFE, not scored.
  const analyze = await request.get(`/v1/analyze?domain=${domain}`);
  expect(analyze.ok()).toBeTruthy();
  const payload = await analyze.json();
  expect(payload.verdict).toBe('SAFE');
  expect(payload.decision?.action).toBe('allow');
});
