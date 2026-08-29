/**
 * Extreme data fixture — Layer 1 layout/robustness audit.
 *
 * Intercepts every /v1/* API call and feeds the REAL UI adversarial data:
 * 10k-char strings, unbreakable tokens, combining-character spam, negative
 * and astronomically large numbers, invalid dates, empty fields, unknown
 * enum values. Then asserts, per route and viewport:
 *
 *   1. The app does not crash (no ErrorBoundary exists in main.tsx, so any
 *      null-unsafe render path white-screens the whole app).
 *   2. No content sticks outside the viewport when it is not inside an
 *      intentionally scrollable container.
 *   3. Total API failure degrades to error/empty states instead of a dead UI.
 *   4. The analyze flow survives a 500 error and an extreme result payload.
 */
import { test, expect, type Page } from '@playwright/test';

const ADMIN_USER = 'admin';
const ADMIN_PASS = 'playwright_test_password_1234';

const LONG_TEXT = 'A'.repeat(10_000);
const LONG_UNBREAKABLE = 'X'.repeat(2_000);
const COMBINING_SPAM = 'q' + '\u0301\u0323\u0317\u0334'.repeat(150) + '.com';
const LONG_DOMAIN = `${'subdomain-very-long-label.'.repeat(20)}example-tld-that-is-way-too-long.com`;
const LONG_URL = `https://example.com/${'path/segment/'.repeat(50)}file?query=${'q'.repeat(500)}`;
const ISO = '2026-08-28T03:00:00Z';

const ADMIN_SESSION = {
  username: ADMIN_USER,
  role: 'admin',
  read_only: false,
  can_mutate: true,
  can_view_settings: true,
};

const EXTREME_STATS = {
  total: Number.MAX_SAFE_INTEGER,
  safe: 9_007_199_254_740_991,
  suspicious: 123_456_789,
  malicious: 0,
  cache_hits: -42,
  period: '7d',
  score_bands: [
    { label: LONG_UNBREAKABLE.slice(0, 300), value: 999_999 },
    { label: '', value: 0 },
    { label: 'negative-band', value: -5 },
  ],
  trend: Array.from({ length: 60 }, (_, i) => ({
    timestamp: new Date(Date.UTC(2026, 7, 28, 0, i)).toISOString(),
    safe: i % 2 === 0 ? Number.MAX_SAFE_INTEGER : 0,
    suspicious: i % 3 === 0 ? -1 : 5,
    malicious: 1e15,
    threats: i,
  })),
};

const EXTREME_ENTRIES = [
  {
    id: 1,
    domain: LONG_DOMAIN,
    verdict: 'MALICIOUS',
    score: 100,
    confidence: 0.999999,
    reasons: [LONG_TEXT],
    cache_hit: false,
    source: LONG_UNBREAKABLE.slice(0, 400),
    analyzed_at: ISO,
    client_ip: '2001:db8::1:2:3:4:5:6:7:8:9:a:b:c',
    client_id: LONG_UNBREAKABLE.slice(0, 200),
  },
  {
    id: 2,
    domain: 'a',
    verdict: 'SAFE',
    score: 0,
    confidence: 0,
    reasons: [],
    cache_hit: true,
    source: '',
    analyzed_at: ISO,
  },
  {
    id: 3,
    domain: LONG_UNBREAKABLE,
    verdict: 'SUSPICIOUS',
    score: 55.555555,
    confidence: 0.5,
    reasons: ['ok'],
    cache_hit: false,
    source: 'osint',
    analyzed_at: ISO,
  },
  {
    id: 4,
    domain: COMBINING_SPAM,
    verdict: 'INVALID',
    score: -5,
    confidence: -1,
    reasons: [''],
    cache_hit: false,
    source: 'grid',
    analyzed_at: 'not-a-date',
  },
  {
    id: 5,
    domain: 'xn--80ak6aa92e.com',
    verdict: 'TOTALLY_UNKNOWN_VERDICT_VALUE',
    score: 1e308,
    confidence: 1e308,
    reasons: [LONG_UNBREAKABLE.slice(0, 300)],
    cache_hit: false,
    source: 'punycode',
    analyzed_at: '2999-12-31T23:59:59Z',
  },
];

const EXTREME_AGENT_STATUS = {
  enabled: true,
  tasks: [
    {
      name: LONG_UNBREAKABLE.slice(0, 300),
      state: 'failed',
      interval: 'every 1ms',
      last_run: '2999-12-31T23:59:59Z',
      next_run: 'invalid-date',
      run_count: Number.MAX_SAFE_INTEGER,
      error_count: -99,
      last_error: LONG_TEXT.slice(0, 2_000),
    },
    {
      name: '',
      state: 'running',
      interval: '',
      last_run: '',
      next_run: '',
      run_count: 0,
      error_count: 0,
      last_error: '',
    },
  ],
  whitelist_stats: {
    loaded_domains: 1e15,
    bloom_size_ram_kb: -1,
    bloom_hashes: 0,
    bloom_bits: 0,
    fpr: 99.99,
  },
  database_stats: { file_size_mb: 1e9, disk_free_gb: 0 },
  telemetry_retention_days: -1,
};

const EXTREME_CORE_STATUS = {
  service: 'core-api',
  status: LONG_TEXT.slice(0, 120),
  mode: 'unknown-mode',
  deployment_tier: LONG_UNBREAKABLE.slice(0, 400),
  redis: { configured: true, status: 'ERROR', error: LONG_TEXT.slice(0, 800) },
  feed_sync: {
    status: 'failed',
    total_domains: -42,
    last_sync: 'not-a-date',
    error: LONG_UNBREAKABLE.slice(0, 500),
  },
  adblock: { enabled: true, loaded_rules: 999_999_999, status: LONG_UNBREAKABLE.slice(0, 300) },
  analysis_config_reload: {
    enabled: true,
    channel: LONG_UNBREAKABLE.slice(0, 250),
    poll_interval: '0s',
    node_role: 'ghost',
    revision: 'r'.repeat(400),
    last_reload_source: '',
    last_reload_at: 'invalid',
  },
};

const EXTREME_ANALYZE_RESULT = {
  domain: LONG_DOMAIN,
  verdict: 'SUSPICIOUS',
  score: 87.5,
  confidence: 12.5,
  reasons: [LONG_TEXT, LONG_UNBREAKABLE.slice(0, 500), ''],
  evidence: [
    {
      source_title: LONG_UNBREAKABLE.slice(0, 300),
      source_type: LONG_UNBREAKABLE.slice(0, 100),
      source_url: LONG_URL,
      matched_terms: [LONG_UNBREAKABLE.slice(0, 200), 'a'],
    },
    { source_title: '', source_url: '' },
  ],
  url_ml: { sampled: false },
};

const ROUTES = [
  '/app/analysis',
  '/app/telemetry',
  '/app/endpoints',
  '/app/overrides',
  '/app/system',
  '/app/settings',
  '/app/reports',
];

/** Heading that proves each route rendered its real content. */
const ROUTE_H1: Record<string, string> = {
  '/app/analysis': 'Domain Inspection',
  '/app/telemetry': 'Network Telemetry',
  '/app/endpoints': 'Endpoints',
  '/app/overrides': 'Domain Overrides',
  '/app/system': 'System',
  '/app/settings': 'Settings',
  '/app/reports': 'User Reports',
};

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'narrow', width: 390, height: 844 },
];

const json = (data: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(data),
});

async function installExtremeMocks(page: Page) {
  await page.route('**/v1/auth/session', (route) => route.fulfill(json(ADMIN_SESSION)));
  await page.route(/\/v1\/telemetry\/stats/, (route) => route.fulfill(json(EXTREME_STATS)));
  await page.route(/\/v1\/telemetry\/recent/, (route) =>
    route.fulfill(json({ items: EXTREME_ENTRIES })),
  );
  await page.route(/\/v1\/agent\/status/, (route) => route.fulfill(json(EXTREME_AGENT_STATUS)));
  await page.route(/\/v1\/status$/, (route) => route.fulfill(json(EXTREME_CORE_STATUS)));
  await page.route(/\/v1\/groups$/, (route) =>
    route.fulfill(
      json({
        items: [
          {
            id: 1,
            name: LONG_UNBREAKABLE.slice(0, 300),
            description: LONG_TEXT,
            block_categories: [LONG_UNBREAKABLE.slice(0, 100), ''],
            strict_phishing: true,
            strict_malware: false,
          },
          { id: 2, name: '', description: '', block_categories: [], strict_phishing: false, strict_malware: false },
        ],
      }),
    ),
  );
  await page.route(/\/v1\/mappings$/, (route) =>
    route.fulfill(
      json({
        items: [
          {
            id: 1,
            mapping_type: 'cidr',
            value: '2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128',
            group_id: 1,
            group_name: LONG_UNBREAKABLE.slice(0, 300),
            created_at: 'not-a-date',
          },
          { id: 2, mapping_type: 'ip', value: '1.2.3.4', group_id: 999, group_name: '', created_at: ISO },
        ],
      }),
    ),
  );
  await page.route(/\/v1\/overrides(\?|$)/, (route) =>
    route.fulfill(
      json({
        items: [
          {
            domain: LONG_DOMAIN,
            action: 'block',
            reason: LONG_TEXT,
            source: LONG_UNBREAKABLE.slice(0, 200),
            created_at: 'not-a-date',
          },
          { domain: 'ok.example', action: 'allow', reason: '', source: '', created_at: ISO },
        ],
      }),
    ),
  );
  await page.route(/\/v1\/reports/, (route) =>
    route.fulfill(
      json({
        reports: [
          {
            id: 1,
            domain: LONG_DOMAIN,
            contact: `${LONG_UNBREAKABLE.slice(0, 100)}@example.com`,
            note: LONG_TEXT,
            status: 'pending',
            created_at: 'invalid-date',
            review_reason: '',
            reviewed_by: '',
            reviewed_at: '',
            resolution_action: '',
          },
          {
            id: 2,
            domain: 'short.io',
            contact: '',
            note: '',
            status: 'WEIRD_STATUS',
            created_at: ISO,
            review_reason: 'r'.repeat(500),
            reviewed_by: LONG_UNBREAKABLE.slice(0, 100),
            reviewed_at: '2999-01-01T00:00:00Z',
            resolution_action: 'unknown-action',
          },
        ],
        total: Number.MAX_SAFE_INTEGER,
        counts: { pending: -1, resolved: Number.MAX_SAFE_INTEGER, rejected: 0 },
      }),
    ),
  );
  await page.route('**/v1/settings/bundle', (route) =>
    route.fulfill(
      json({
        settings: {
          gemini_api_key: LONG_UNBREAKABLE.slice(0, 500),
          agent_webhook_url: 'ht!tp://not a url',
          telemetry_retention_days: -1,
        },
        analysis_config: {
          keyword_base_score: -999,
          keyword_match_score: 1e9,
          keyword_multiple_bonus: 0,
          brand_spoofing_score: 1e308,
          entropy_threshold: -1,
          entropy_score: 1e15,
        },
        guest_access: { username: 'guest', exists: true, enabled: true },
      }),
    ),
  );
  await page.route(/\/v1\/analysis\/recent/, (route) =>
    route.fulfill(
      json({
        items: EXTREME_ENTRIES.map((e, i) => ({ ...e, id: i + 1 })),
      }),
    ),
  );
  await page.route(/\/v1\/analyze/, (route) => route.fulfill(json(EXTREME_ANALYZE_RESULT)));
}

interface LayoutIssue {
  element: string;
  detail: string;
}

async function collectLayoutIssues(page: Page): Promise<LayoutIssue[]> {
  return page.evaluate(() => {
    const issues: LayoutIssue[] = [];
    const vw = window.innerWidth;
    const doc = document.documentElement;
    if (doc.scrollWidth > vw + 1) {
      issues.push({
        element: 'document',
        detail: `page-level horizontal overflow: scrollWidth ${doc.scrollWidth} > viewport ${vw}`,
      });
    }

    const hasOwnText = (el: Element): boolean => {
      for (const node of Array.from(el.childNodes)) {
        if (node.nodeType === Node.TEXT_NODE && (node.textContent || '').trim()) return true;
      }
      return false;
    };

    const clippedByIntentionalContainer = (el: Element): boolean => {
      let cur: Element | null = el.parentElement;
      while (cur) {
        const isPageMask = cur === document.body || cur === document.documentElement;
        const s = getComputedStyle(cur);
        if (!isPageMask && /(auto|scroll|hidden|clip)/.test(s.overflowX)) {
          const r = cur.getBoundingClientRect();
          if (r.right <= vw + 2 && r.left >= -2) return true;
        }
        cur = cur.parentElement;
      }
      return false;
    };

    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue;
      const style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.display === 'none') continue;
      if (!(r.right > vw + 2 || r.left < -2)) continue;
      if (clippedByIntentionalContainer(el)) continue;
      const isContentful =
        hasOwnText(el) ||
        ['INPUT', 'TEXTAREA', 'SELECT', 'IMG', 'SVG', 'CANVAS', 'BUTTON', 'A'].includes(el.tagName);
      if (!isContentful) continue;
      const cls = typeof el.className === 'string' ? el.className.split(/\s+/).slice(0, 2).join('.') : '';
      const text = (el.textContent || '').trim().slice(0, 40);
      issues.push({
        element: `${el.tagName.toLowerCase()}${cls ? `.${cls}` : ''}`,
        detail: `"${text}" rect(left=${Math.round(r.left)}, width=${Math.round(r.width)}) vs viewport ${vw}`,
      });
      if (issues.length >= 15) break;
    }
    return issues;
  });
}

test.describe('Extreme data fixtures', () => {
  let context: any;
  let page: Page;
  let pageErrors: string[];
  let consoleWarnings: string[];

  test.beforeEach(async ({ browser }) => {
    context = await browser.newContext();
    page = await context.newPage();
    pageErrors = [];
    consoleWarnings = [];
    page.on('pageerror', (err) => pageErrors.push(`${err.name}: ${err.message}`));
    page.on('console', (msg) => {
      if (msg.type() === 'warning') consoleWarnings.push(msg.text());
    });
    await installExtremeMocks(page);
  });

  test.afterEach(async () => {
    // Release the browser context (and any extra page opened inside it)
    // after every test so headless Chrome processes do not accumulate.
    await context?.close();
    context = null;
    page = null as unknown as Page;
  });

  async function visitRoute(route: string) {
    await page.goto(route);
    await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toBeVisible({
      timeout: 20_000,
    });
    await page.waitForLoadState('networkidle').catch(() => undefined);
    await page.waitForTimeout(700);
  }

  function assertHealthy(route: string, issues: LayoutIssue[]) {
    expect(pageErrors, `uncaught render errors on ${route}`).toEqual([]);
    // The telemetry table used to log this warning on every render because an
    // AnimatePresence mode="wait" wrapped several motion.tr children — the
    // sweep visits /app/telemetry, so any regression re-introducing it fails.
    expect(
      consoleWarnings.filter((w) => w.includes('AnimatePresence')),
      `AnimatePresence misuse warnings on ${route}`,
    ).toEqual([]);
    if (issues.length > 0) {
      const detail = issues.map((i) => `${i.element}: ${i.detail}`).join('\n');
      throw new Error(`Layout breakage on ${route}:\n${detail}`);
    }
    expect(issues).toEqual([]);
  }

  for (const vp of VIEWPORTS) {
    test(`extreme data renders without breakage [${vp.name}]`, async () => {
      test.setTimeout(180_000);
      await page.setViewportSize({ width: vp.width, height: vp.height });

      for (const route of ROUTES) {
        await visitRoute(route);
        const issues = await collectLayoutIssues(page);
        assertHealthy(route, issues);
      }
    });
  }

  test('analyze flow survives a 500 error', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.unroute(/\/v1\/analyze/);
    await page.route(/\/v1\/analyze/, (route) =>
      route.fulfill({ status: 500, contentType: 'text/html', body: '<html>boom</html>' }),
    );

    await visitRoute('/app/analysis');
    await page.getByPlaceholder('secure-login-wallet-example.com').fill('example.com');
    await page.getByRole('button', { name: /Analyze/i }).click();

    // The failure must surface as the dedicated alert (role="alert",
    // data-testid="analyze-error") with the real error message — not just any
    // text matching /failed|error/ (which also matches the "Analysis" title).
    const alertBox = page.getByTestId('analyze-error');
    await expect(alertBox).toBeVisible({ timeout: 15_000 });
    await expect(alertBox).toHaveAttribute('role', 'alert');
    await expect(alertBox).toContainText('Analysis failed:');
    expect(pageErrors).toEqual([]);
    // The page must remain interactive after the failure.
    await page.getByPlaceholder('secure-login-wallet-example.com').fill('retry.example');
    expect(await page.getByRole('button', { name: /Analyze/i }).isEnabled()).toBe(true);
  });

  test('analyze flow renders an extreme result payload', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });

    await visitRoute('/app/analysis');
    await page.getByPlaceholder('secure-login-wallet-example.com').fill('extreme.example');
    await page.getByRole('button', { name: /Analyze/i }).click();
    await expect(page.getByText(/Score:/).first()).toBeVisible({ timeout: 15_000 });
    await page.waitForTimeout(500);

    const issues = await collectLayoutIssues(page);
    assertHealthy('/app/analysis (extreme result)', issues);
  });

  test('total API failure degrades to error/empty states, not a dead app', async () => {
    test.setTimeout(180_000);
    // The auth session must succeed so we exercise the AUTHENTICATED app
    // shell; only the data APIs fail. Aborting /v1/auth/session too would
    // reduce this test to "the LoginScreen renders".
    const failingContext = page.context();
    const fresh = await failingContext.newPage();
    fresh.on('pageerror', (err) => pageErrors.push(`${err.name}: ${err.message}`));
    await fresh.route('**/v1/**', (route) => {
      if (route.request().url().includes('/v1/auth/session')) {
        return route.fulfill(json(ADMIN_SESSION));
      }
      return route.abort('connectionfailed');
    });

    for (const route of ROUTES) {
      await fresh.goto(route);
      // The loader must clear (never spin forever) and the route's real
      // heading must render — this proves the authenticated shell renders
      // the page content, not a login screen, not a white-screen.
      await expect(fresh.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
        timeout: 30_000,
      });
      await expect(
        fresh.getByRole('heading', { level: 1, name: ROUTE_H1[route] }),
        `route ${route} should render its h1 under total API failure`,
      ).toBeVisible({ timeout: 20_000 });
      const childCount = await fresh.locator('#root > *').count();
      expect(childCount, `dead UI on ${route} under total API failure`).toBeGreaterThan(0);
    }

    // Strict: not even ONE JavaScript pageerror may escape anywhere in the
    // sweep. Aborted fetches are expected and must be handled by SWR/the
    // routes' catch paths — they never justify an unhandled rejection.
    expect(pageErrors).toEqual([]);
    await fresh.close();
  });

  test('agent status payload with tasks:null renders the tasks empty state', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.unroute(/\/v1\/agent\/status/);
    await page.route(/\/v1\/agent\/status/, (route) => route.fulfill(json({ enabled: true, tasks: null })));

    await page.goto('/app/endpoints');
    await expect(page.getByRole('heading', { level: 1, name: 'Endpoints' })).toBeVisible({
      timeout: 20_000,
    });
    // Legacy agent payloads can ship `tasks: null`; the table must degrade to
    // its empty state instead of crashing on .length/.map of null.
    await expect(page.getByText('No background tasks registered.')).toBeVisible();
    expect(pageErrors).toEqual([]);
  });

  test('settings page locks mutation controls while the bundle load is failing', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.unroute('**/v1/settings/bundle');
    await page.route('**/v1/settings/bundle', (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'settings store unavailable' }),
      }),
    );

    await page.goto('/app/settings');

    // Loading must end — no infinite spinner.
    await expect(page.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
      timeout: 30_000,
    });
    // The page shell still renders its content…
    await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible({
      timeout: 20_000,
    });
    // …with explicit, persistent error feedback and a Retry control.
    const alertBox = page.getByTestId('settings-load-error');
    await expect(alertBox).toBeVisible();
    await expect(alertBox).toHaveAttribute('role', 'alert');
    await expect(alertBox).toContainText('Failed to load settings (HTTP 500)');

    // Every mutating control must be REALLY disabled (not just aria-disabled):
    // saving defaults from an unloaded form would clobber the operator's
    // configuration.
    for (const selector of [
      '#gemini-key-input',
      '#webhook-url-input',
      '#retention-days-input',
      '#guest-password-input',
      '#new-keyword-input',
      '[data-testid="guest-mode-toggle"]',
    ]) {
      await expect(page.locator(selector), `${selector} must be disabled`).toBeDisabled();
    }
    for (const name of [
      'Save Integrations',
      'Test API',
      'Test Webhook',
      'Save Access Control',
      'Reset Defaults',
      'Apply Config',
    ]) {
      await expect(page.getByRole('button', { name, exact: true }), `${name} must be disabled`).toBeDisabled();
    }

    // Retrying while the API keeps failing keeps the lock engaged.
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await expect(page.getByTestId('settings-load-error')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save Integrations', exact: true })).toBeDisabled();
    expect(pageErrors).toEqual([]);
  });

  test('settings retry loads real values, unlocks mutation, and clears the alert', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.unroute('**/v1/settings/bundle');

    const RETRY_BUNDLE = {
      settings: {
        gemini_api_key: 'sk-retry-loaded-key-42',
        agent_webhook_url: 'https://retry.example/hook',
        telemetry_retention_days: 42,
      },
      analysis_config: { punycode_score: 77, keywords: ['retrykw'] },
      guest_access: { username: 'guest', exists: true, enabled: true },
    };
    let bundleCalls = 0;
    let retried = false;
    await page.route('**/v1/settings/bundle', (route) => {
      bundleCalls += 1;
      // Every pre-retry call fails (React StrictMode in dev fires the mount
      // effect twice); only requests issued after the Retry click succeed.
      if (!retried) {
        return route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'settings store unavailable' }),
        });
      }
      return route.fulfill(json(RETRY_BUNDLE));
    });

    await page.goto('/app/settings');
    await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByTestId('settings-load-error')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save Integrations', exact: true })).toBeDisabled();

    // Retry must issue a NEW request that actually succeeds.
    const callsBeforeRetry = bundleCalls;
    retried = true;
    await page.getByRole('button', { name: 'Retry', exact: true }).click();

    await expect(page.getByTestId('settings-load-error')).toHaveCount(0);
    await expect(page.getByLabel('Gemini API Key', { exact: true })).toHaveValue(
      'sk-retry-loaded-key-42',
    );
    await expect(page.getByLabel('Log Retention', { exact: true })).toHaveValue('42');
    await expect(page.getByLabel('Punycode Penalty', { exact: true })).toHaveValue('77');
    await expect(page.getByRole('button', { name: 'Remove keyword retrykw' })).toBeVisible();
    const toggle = page.getByRole('switch', { name: 'Enable Guest Mode' });
    await expect(toggle).toBeEnabled();
    await expect(toggle).toHaveAttribute('aria-checked', 'true');
    await expect(page.getByRole('button', { name: 'Save Integrations', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: 'Reset Defaults', exact: true })).toBeEnabled();
    expect(bundleCalls, 'Retry must trigger a new bundle request').toBe(callsBeforeRetry + 1);
    expect(pageErrors).toEqual([]);
  });

  test('reset scoring updates both the numeric inputs and the keyword chips', async () => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.route('**/v1/config/analysis/reset', (route) =>
      route.fulfill(
        json({
          punycode_score: 91,
          keywords: ['resetkw-a', 'resetkw-b'],
        }),
      ),
    );

    await visitRoute('/app/settings');

    // User edits a scoring input first…
    const punycode = page.getByLabel('Punycode Penalty', { exact: true });
    await punycode.fill('12');
    // …then Reset Defaults must overwrite BOTH the RHF-registered numeric
    // inputs and the keyword chips (component state) with the response.
    await page.getByRole('button', { name: 'Reset Defaults', exact: true }).click();
    await page.getByRole('button', { name: 'OK', exact: true }).click();

    await expect(punycode).toHaveValue('91', { timeout: 10_000 });
    await expect(page.getByRole('button', { name: 'Remove keyword resetkw-a' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Remove keyword resetkw-b' })).toBeVisible();
    expect(pageErrors).toEqual([]);
  });
});
