import { test, expect } from '@playwright/test';

test('keeps the plain login card elevated without Moody Dog', async ({ page }) => {
  await page.goto('/app/');

  await expect(page.getByTestId('login-moody-dog')).toHaveCount(0);
  await expect(page.locator('body')).toHaveCSS('background-image', 'none');

  const loginCard = page.getByTestId('login-card');
  await expect(loginCard).toBeVisible();
  await expect(loginCard).toHaveCSS('transform', 'none');

  const layout = await page.getByTestId('login-screen').evaluate((screen) => {
    const card = screen.querySelector<HTMLElement>('[data-testid="login-card"]');
    if (!card) {
      throw new Error('Login card was not found');
    }

    const cardRect = card.getBoundingClientRect();
    return {
      cardHeight: cardRect.height,
      offsetFromCentered: cardRect.top - (window.innerHeight - cardRect.height) / 2,
    };
  });
  expect(layout.cardHeight).toBeLessThan(500);
  expect(Math.abs(layout.offsetFromCentered)).toBeLessThanOrEqual(1);
});

test('uses the local Moody Dog only while the bounded loader is active', async ({ page }) => {
  await page.goto('/app/');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await expect(page.getByTestId('moody-dog-loader')).toHaveCount(0);

  let releaseLogin!: () => void;
  const loginGate = new Promise<void>((resolve) => {
    releaseLogin = resolve;
  });
  let markRouteDone!: () => void;
  const routeDone = new Promise<void>((resolve) => {
    markRouteDone = resolve;
  });
  await page.route('**/v1/auth/login', async (route) => {
    try {
      await loginGate;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'test login release' }),
      });
    } finally {
      markRouteDone();
    }
  });

  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('loader_test_password');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  const dog = page.getByTestId('moody-dog-loader');
  try {
    await expect(dog).toBeVisible();
    const source = await dog.evaluate((element) => String(
      (element as HTMLElement & { src?: unknown }).src ?? element.getAttribute('src') ?? '',
    ));
    expect(source).toMatch(/moody-dog(?:-[^/]+)?\.lottie$/);
    expect(source).not.toContain('lottie.host');
    await expect(page.locator('.app-loader-backdrop.is-visible')).toBeVisible();
  } finally {
    releaseLogin();
    await routeDone;
    await page.unroute('**/v1/auth/login');
  }
});

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

test('keeps the compact route dock swipeable without page overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app/analysis');

  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  const dock = page.getByRole('navigation', { name: 'Workspace routes' });
  await expect(dock).toBeVisible();

  const metrics = await dock.evaluate((element) => {
    const dockElement = element as HTMLElement;
    return {
      clientWidth: dockElement.clientWidth,
      scrollWidth: dockElement.scrollWidth,
      overflowX: getComputedStyle(dockElement).overflowX,
      bodyScrollWidth: document.documentElement.scrollWidth,
      viewportWidth: window.innerWidth,
    };
  });

  expect(metrics.overflowX).toBe('auto');
  expect(metrics.scrollWidth).toBeGreaterThan(metrics.clientWidth);
  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth);
});

test('shrinks the Safe Zone brand behind the logo when the header gets crowded', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app/analysis');

  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();
  const brand = page.locator('.shell-brand');
  await expect(brand).toBeVisible();

  const layout = await page.evaluate(() => {
    const brand = document.querySelector<HTMLElement>('.shell-brand');
    const logo = document.querySelector<HTMLElement>('.guest-brand-mark > div');
    const actions = document.querySelector<HTMLElement>('.shell-header-actions');
    if (!brand || !logo || !actions) {
      throw new Error('Floating header elements were not found');
    }

    const brandRect = brand.getBoundingClientRect();
    const logoRect = logo.getBoundingClientRect();
    const actionsRect = actions.getBoundingClientRect();
    return {
      brandWidth: brandRect.width,
      brandLeft: brandRect.left,
      brandRight: brandRect.right,
      brandTop: brandRect.top,
      brandBottom: brandRect.bottom,
      logoLeft: logoRect.left,
      logoRight: logoRect.right,
      logoTop: logoRect.top,
      logoBottom: logoRect.bottom,
      actionsWidth: actionsRect.width,
      actionsPosition: getComputedStyle(actions).position,
    };
  });

  expect(layout.brandWidth).toBeLessThan(240);
  expect(layout.brandLeft).toBeGreaterThanOrEqual(layout.logoLeft - 1);
  expect(layout.brandRight).toBeLessThanOrEqual(layout.logoRight + 1);
  expect(layout.brandTop).toBeGreaterThanOrEqual(layout.logoTop - 1);
  expect(layout.brandBottom).toBeLessThanOrEqual(layout.logoBottom + 1);
  expect(layout.actionsWidth).toBeGreaterThan(0);
  expect(layout.actionsPosition).toBe('static');
});
