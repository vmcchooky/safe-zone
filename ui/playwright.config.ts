import { defineConfig, devices } from '@playwright/test';

const host = '127.0.0.1';

function portFromEnv(name: string, fallback: number) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : fallback;
}

const uiPort = portFromEnv('SAFE_ZONE_E2E_UI_PORT', 15173);
const apiPort = portFromEnv('SAFE_ZONE_E2E_API_PORT', 18080);
const uiOrigin = `http://${host}:${uiPort}`;
const apiOrigin = `http://${host}:${apiPort}`;

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: './tests',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: 'html',
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: uiOrigin,

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  /*
   * Run an isolated React/API pair. These intentionally do not reuse the
   * normal development ports (5173/8080), which may host a legacy dashboard
   * or a developer's active session.
   */
  webServer: [
    {
      command: `npm run dev -- --port ${uiPort}`,
      url: `${uiOrigin}/app/`,
      reuseExistingServer: false,
      timeout: 120 * 1000,
      env: {
        ...process.env,
        SAFE_ZONE_UI_API_ORIGIN: apiOrigin,
        SAFE_ZONE_UI_BASE_PATH: '/app/',
      },
    },
    {
      command: 'go run ./cmd/core-api',
      cwd: '../',
      env: {
        ...process.env,
        SAFE_ZONE_CORE_API_ADDR: `${host}:${apiPort}`,
        SAFE_ZONE_ADMIN_PASSWORD: 'playwright_test_password_1234',
        SAFE_ZONE_ADMIN_API_KEY: 'playwright_test_api_key_1234_abcdefg',
        SAFE_ZONE_SQLITE_PATH: ':memory:',
        SAFE_ZONE_REDIS_ADDR: '',
        SAFE_ZONE_ADBLOCK_ENABLED: 'false',
        SAFE_ZONE_AGENT_ENABLED: 'false',
        SAFE_ZONE_OSINT_ENABLED: 'false',
        SAFE_ZONE_GEMINI_API_KEY: '',
      },
      url: `${apiOrigin}/healthz`,
      reuseExistingServer: false,
      timeout: 120 * 1000,
    },
  ],
});
