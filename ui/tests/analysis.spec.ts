import { test, expect } from '@playwright/test';

test('has title and can perform an analysis', async ({ page }) => {
  await page.goto('/app/analysis');
  await expect(page).toHaveTitle(/Safe Zone/i);

  // Perform login
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  // Expect the analysis deck header to be visible
  await expect(page.getByText('Analysis Deck')).toBeVisible();

  // Find the input and enter a domain
  const searchInput = page.getByPlaceholder('secure-login-wallet-example.com');
  await searchInput.fill('example.com');

  // Click the Analyze button
  const analyzeBtn = page.getByRole('button', { name: /Analyze/i });
  await analyzeBtn.click();

  // Wait for the result to show up (e.g. looking for the score)
  await expect(page.getByText(/Score:/)).toBeVisible({ timeout: 15000 });
});
