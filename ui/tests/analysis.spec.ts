import { test, expect, type Page } from '@playwright/test';

/**
 * Loader transition probe: samples the overlay's visibility class every
 * animation frame and records every hidden<->visible flip so tests can
 * assert on the number of loader episodes (no blind sleeps, no screenshots).
 */
async function trackLoaderTransitions(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as {
      __loaderLog: { v: boolean; t: number }[];
      __loaderLogIdle: boolean;
    };
    w.__loaderLog = [];
    (function sample() {
      const el = document.querySelector('.app-loader-backdrop');
      const visible = !!el && el.classList.contains('is-visible');
      const log = w.__loaderLog;
      const last = log[log.length - 1];
      if (!last || last.v !== visible) log.push({ v: visible, t: Math.round(performance.now()) });
      requestAnimationFrame(sample);
    })();
  });
}

async function readLoaderLog(page: Page): Promise<{ v: boolean; t: number }[]> {
  return page.evaluate(() => (window as unknown as { __loaderLog: { v: boolean; t: number }[] }).__loaderLog);
}

/** Number of separate hidden -> visible loader episodes in the log. */
function countVisibleEpisodes(log: { v: boolean; t: number }[]): number {
  return log.filter((entry) => entry.v).length;
}

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

  // Idle state: no loader overlay, no Moody Dog, no static fallback.
  await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);
  await expect(page.getByTestId('moody-dog-loader')).toHaveCount(0);
  await expect(page.getByTestId('moody-dog-fallback')).toHaveCount(0);
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
    // While the animation plays, the fallback must be fully absent: one
    // backdrop, no fallback element, and no always-on ::before disc behind
    // the animation.
    await expect(page.getByTestId('moody-dog-fallback')).toHaveCount(0);
    await expect(page.locator('.app-loader-backdrop')).toHaveCount(1);
    await expect(page.locator('.app-loader.is-fallback')).toHaveCount(0);
    const pseudo = await page.locator('.app-loader').evaluate((el) => getComputedStyle(el, '::before').content);
    expect(pseudo).toBe('none');
  } finally {
    releaseLogin();
    await routeDone;
    await page.unroute('**/v1/auth/login');
  }
});

test('shows the static fallback only when the animation player fails', async ({ page }) => {
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  let releaseLogin!: () => void;
  const loginGate = new Promise<void>((resolve) => {
    releaseLogin = resolve;
  });
  await page.route('**/v1/auth/login', async (route) => {
    await loginGate;
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'test login release' }),
    });
  });
  // Make the local animation asset fetch fail for real: the dotLottie
  // player reports 'loadError' and the loader must swap to its fallback.
  await page.route(/\/moody-dog[^?]*\.lottie$/, (route) => route.abort());

  await page.goto('/app/');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('loader_test_password');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  try {
    await expect(page.getByTestId('moody-dog-fallback')).toBeVisible({ timeout: 10000 });
    // The animation must be gone entirely — nothing stacked on top of the
    // fallback — and the loader still releases normally afterwards.
    await expect(page.getByTestId('moody-dog-loader')).toHaveCount(0);
    await expect(page.locator('.app-loader.is-fallback')).toHaveCount(1);
    await expect(page.locator('.app-loader-backdrop.is-visible')).toBeVisible();
    expect(pageErrors).toEqual([]);
  } finally {
    releaseLogin();
    await page.waitForTimeout(100);
    await page.unroute('**/v1/auth/login');
    await page.unroute(/\/moody-dog[^?]*\.lottie$/);
  }
});

test('prefers-reduced-motion renders the static fallback without any animation', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });

  let releaseLogin!: () => void;
  const loginGate = new Promise<void>((resolve) => {
    releaseLogin = resolve;
  });
  await page.route('**/v1/auth/login', async (route) => {
    await loginGate;
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'test login release' }),
    });
  });

  const lottieRequests: string[] = [];
  page.on('request', (request) => {
    // Anchored: the static "?import" module request for the asset URL is
    // part of the app bundle, not a player mount.
    if (/moody-dog[^?]*\.lottie$/.test(request.url())) lottieRequests.push(request.url());
  });

  await page.goto('/app/');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('loader_test_password');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  try {
    await expect(page.getByTestId('moody-dog-fallback')).toBeVisible();
    // The animation is never mounted at all, so nothing animates behind it.
    await expect(page.getByTestId('moody-dog-loader')).toHaveCount(0);
    await expect(page.locator('.app-loader.is-fallback dotlottie-wc')).toHaveCount(0);
    expect(lottieRequests).toEqual([]);
  } finally {
    releaseLogin();
    await page.waitForTimeout(100);
    await page.unroute('**/v1/auth/login');
  }
});

test('keeps one continuous loader from login through the Analysis deck', async ({ page }) => {
  test.setTimeout(30000);
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  // Protected data must only be requested after the login round-trip.
  let loginRespondedAt = 0;
  let firstAnalysisRequestAt = 0;
  page.on('response', (response) => {
    if (response.url().includes('/v1/auth/login')) loginRespondedAt = Date.now();
  });
  page.on('request', (request) => {
    if (request.url().includes('/v1/analysis') && !firstAnalysisRequestAt) {
      firstAnalysisRequestAt = Date.now();
    }
  });

  await trackLoaderTransitions(page);
  // Timestamp (page clock) of the login request so the .lottie fetches can
  // be proven to happen before the login submit, not at the route handoff.
  await page.route('**/v1/auth/login', async (route) => {
    await page.evaluate(() => {
      (window as unknown as { __loginRequestAt?: number }).__loginRequestAt = Math.round(performance.now());
    });
    await route.continue();
  });
  await page.goto('/app/analysis');
  await expect(page.getByTestId('login-card')).toBeVisible();

  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  const deck = page.getByText('Analysis Deck');
  await expect(deck).toBeVisible({ timeout: 20000 });
  await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);

  const log = await readLoaderLog(page);
  // Exactly two loader episodes in the whole session: the initial session
  // check and the login itself. Crucially, the login episode must run
  // continuously until the Analysis chunk is ready — no hide/re-show.
  expect(countVisibleEpisodes(log)).toBe(2);
  expect(log[log.length - 1]?.v).toBe(false);

  // The animation must not be remounted at the handoff (a remount would
  // fetch the .lottie asset again): every player mount happens at the start
  // of a loader episode, i.e. before the login round-trip begins. A fetch
  // after that point means the overlay blinked mid-handoff.
  const loginRequestAt = await page.evaluate(() => (
    (window as unknown as { __loginRequestAt?: number }).__loginRequestAt ?? 0
  ));
  expect(loginRequestAt).toBeGreaterThan(0);
  const lottieTimestamps = await page.evaluate(() => (
    performance
      .getEntriesByType('resource')
      .map((entry) => ({ url: entry.name, t: Math.round(entry.startTime) }))
      .filter((entry) => /moody-dog[^?]*\.lottie$/.test(entry.url))
  ));
  for (const entry of lottieTimestamps) {
    expect(entry.t).toBeLessThan(loginRequestAt);
    expect(entry.url).not.toContain('lottie.host');
  }

  // Protected analysis data is only requested after the server accepted
  // the login, never before.
  expect(firstAnalysisRequestAt).toBeGreaterThanOrEqual(loginRespondedAt);
  expect(pageErrors).toEqual([]);
});

test('does not flash a second loader while the Analysis chunk is slow', async ({ page }) => {
  test.setTimeout(30000);
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  await trackLoaderTransitions(page);
  // Hold the Analysis route module so the loader must stay up well past
  // the auth phase — the overlay must remain continuous, never blink.
  let releaseChunk!: () => void;
  const chunkGate = new Promise<void>((resolve) => {
    releaseChunk = resolve;
  });
  let chunkServed = 0;
  await page.route(/\/src\/routes\/analysis\/AnalysisPage\./, async (route) => {
    chunkServed += 1;
    await chunkGate;
    await route.continue().catch(() => {});
  });

  await page.goto('/app/analysis');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  try {
    await expect(page.locator('.app-loader-backdrop.is-visible')).toBeVisible({ timeout: 10000 });
    await expect(page.getByTestId('moody-dog-loader')).toBeVisible();
    // Still gated: the module has been requested exactly once (the login
    // preload) and the loader is holding continuously.
    expect(chunkServed).toBe(1);

    releaseChunk();
    await expect(page.getByText('Analysis Deck')).toBeVisible({ timeout: 20000 });
    await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);

    const log = await readLoaderLog(page);
    // One episode after login submit (plus the initial session check);
    // no hidden -> visible flip once the overlay appeared.
    expect(countVisibleEpisodes(log)).toBe(2);
    expect(log[log.length - 1]?.v).toBe(false);
    expect(pageErrors).toEqual([]);
  } finally {
    releaseChunk();
    await page.unroute(/\/src\/routes\/analysis\/AnalysisPage\./);
  }
});

test('returns to the login card with a generic error when authentication fails', async ({ page }) => {
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  let releaseLogin!: () => void;
  const loginGate = new Promise<void>((resolve) => {
    releaseLogin = resolve;
  });
  await page.route('**/v1/auth/login', async (route) => {
    await loginGate;
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'Authentication service unavailable' }),
    });
  });

  await page.goto('/app/analysis');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('wrong_password');
  await page.getByRole('button', { name: /Authenticate/i }).click();

  try {
    await expect(page.locator('.app-loader-backdrop.is-visible')).toBeVisible({ timeout: 10000 });
    releaseLogin();

    // Loader fully released, login card back with the error, and the
    // protected shell never mounted.
    await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);
    await expect(page.getByTestId('login-card')).toBeVisible();
    await expect(page.getByTestId('login-card')).toContainText('Authentication service unavailable');
    await expect(page.getByText('Analysis Deck')).toHaveCount(0);
    await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toHaveCount(0);
    expect(pageErrors).toEqual([]);
  } finally {
    releaseLogin();
    await page.unroute('**/v1/auth/login');
  }
});

test('serves an already-authenticated reload without a double loader', async ({ page }) => {
  test.setTimeout(40000);
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  await page.goto('/app/analysis');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();
  await expect(page.getByText('Analysis Deck')).toBeVisible({ timeout: 20000 });

  const sessionResponses: number[] = [];
  page.on('response', (response) => {
    if (response.url().includes('/v1/auth/session')) sessionResponses.push(response.status());
  });

  await trackLoaderTransitions(page);
  await page.reload();
  await expect(page.getByText('Analysis Deck')).toBeVisible({ timeout: 20000 });
  await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);

  // The server verified the session on reload.
  expect(sessionResponses).toContain(200);
  expect(sessionResponses).not.toContain(401);

  const log = await readLoaderLog(page);
  // Reload flow: exactly one loader episode, from first paint until the
  // deck is ready — no second re-show.
  expect(countVisibleEpisodes(log)).toBe(1);
  expect(log[log.length - 1]?.v).toBe(false);
  expect(pageErrors).toEqual([]);
});

test('keeps the loader bounded and recoverable for an uncached route', async ({ page }) => {
  test.setTimeout(40000);
  const pageErrors: Error[] = [];
  page.on('pageerror', (error) => pageErrors.push(error));

  await page.goto('/app/analysis');
  await expect(page.getByTestId('login-card')).toBeVisible();
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('Enter your access secret').fill('playwright_test_password_1234');
  await page.getByRole('button', { name: /Authenticate/i }).click();
  await expect(page.getByText('Analysis Deck')).toBeVisible({ timeout: 20000 });

  // Break the System route module: the route loader must surface a
  // controlled error and release the overlay — never spin forever.
  await page.route(/\/src\/routes\/SystemPage\./, (route) => route.abort());

  await page.getByRole('link', { name: 'System' }).click();
  try {
    await expect(page.getByRole('alert')).toContainText('could not be loaded', { timeout: 15000 });
    await expect(page.locator('.app-loader-backdrop')).toHaveCount(0);
    await expect(page.getByTestId('moody-dog-loader')).toHaveCount(0);
    expect(pageErrors).toEqual([]);

    // Recovery: unbreak the module and retry. The browser memoizes failed
    // dynamic imports per document, so the Retry control performs a full
    // reload; the session cookie survives and the server re-verifies it.
    await page.unroute(/\/src\/routes\/SystemPage\./);
    await page.getByRole('button', { name: /Retry/i }).click();
    await expect(page.locator('.app-loader-backdrop')).toHaveCount(0, { timeout: 20000 });
    await expect(page.locator('h1', { hasText: /^System/ }).or(page.getByText('Failed to load system status'))).toBeVisible({ timeout: 20000 });
    expect(pageErrors).toEqual([]);
  } finally {
    await page.unroute(/\/src\/routes\/SystemPage\./);
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
