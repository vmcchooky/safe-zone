/**
 * Regression tests for the a11y fixes from the UI/UX audit:
 *   1. GroupModal exposes dialog semantics (role/aria-modal/labelledby),
 *      moves focus into the panel on open, traps Tab, closes on Escape,
 *      restores focus to its opener, and keeps the backdrop out of the
 *      accessibility tree.
 *   2. Button classes that strip the outline keep a visible :focus-visible
 *      indicator for keyboard users.
 *   3. Settings controls (guest toggle, password reveals, keyword chips)
 *      expose accessible names, states, and label associations.
 */
import { test, expect, type Page } from '@playwright/test';

const ADMIN_USER = 'admin';
const ADMIN_PASS = 'playwright_test_password_1234';

test.describe('Dialog and keyboard a11y regressions', () => {
  let context: any;
  let page: Page;
  let storageState: string;

  test.beforeAll(async ({ browser }) => {
    const loginContext = await browser.newContext();
    const loginPage = await loginContext.newPage();
    await loginPage.goto('/app/analysis');
    await loginPage.getByTestId('login-card').waitFor({ state: 'visible', timeout: 20_000 });
    await loginPage.getByPlaceholder('Enter your username').fill(ADMIN_USER);
    await loginPage.getByPlaceholder('Enter your access secret').fill(ADMIN_PASS);
    await loginPage.getByRole('button', { name: /Authenticate/i }).click();
    await expect(
      loginPage.getByRole('navigation', { name: 'Workspace routes' }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(loginPage.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
      timeout: 30_000,
    });
    storageState = JSON.stringify(await loginContext.storageState());
    await loginContext.close();
  });

  test.beforeEach(async ({ browser }) => {
    context = await browser.newContext({ storageState: JSON.parse(storageState) });
    page = await context.newPage();
  });

  test.afterEach(async () => {
    await context?.close();
    context = null;
    page = null as unknown as Page;
  });

  test('group modal exposes dialog semantics and manages focus', async () => {
    await page.goto('/app/endpoints');
    await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });
    await page.getByRole('button', { name: /Add Group/i }).first().click();

    const dialog = page.locator('[role="dialog"][aria-modal="true"]');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute('aria-labelledby', 'group-modal-title');

    // Focus must move into the dialog when it opens.
    expect(await dialog.evaluate((el) => el.contains(document.activeElement))).toBe(true);

    // The icon-only close control must have an accessible name.
    await expect(dialog.getByRole('button', { name: 'Close' })).toBeVisible();

    // Tab must cycle inside the dialog, never escape to the background page.
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press('Tab');
    }
    expect(await dialog.evaluate((el) => el.contains(document.activeElement))).toBe(true);

    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
  });

  test('group modal restores focus to its opener and hides its backdrop', async () => {
    await page.goto('/app/endpoints');
    await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });

    const opener = page.getByRole('button', { name: /Add Group/i }).first();
    await opener.click();
    const dialog = page.locator('[role="dialog"][aria-modal="true"]');
    await expect(dialog).toBeVisible();

    // The decorative backdrop must not be independent screen-reader content.
    await expect(dialog.locator('xpath=preceding-sibling::*[1]')).toHaveAttribute(
      'aria-hidden',
      'true',
    );

    // Form errors must be wired to their inputs via aria-describedby.
    await dialog.getByRole('button', { name: /Create Group/i }).click();
    const nameInput = dialog.locator('#group-name-input');
    await expect(nameInput).toHaveAttribute('aria-invalid', 'true');
    await expect(nameInput).toHaveAttribute('aria-describedby', 'group-name-error');
    await expect(dialog.locator('#group-name-error')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    // Focus must land back on the button that opened the modal.
    await expect(opener).toBeFocused();
  });

  test('settings controls expose accessible names, states, and label associations', async () => {
    await page.goto('/app/settings');
    await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
      timeout: 30_000,
    });

    // Key fields must be associated with their visible labels.
    // exact:true — substring matching would also hit the eye buttons whose
    // aria-labels contain the field name (e.g. "Show Gemini API key").
    await expect(page.getByLabel('Gemini API Key', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Agent Webhook URL', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Log Retention', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Suspicious Keywords Dictionary', { exact: true })).toBeVisible();

    // Guest mode toggle: named switch with an exposed state.
    const toggle = page.getByRole('switch', { name: 'Enable Guest Mode' });
    await expect(toggle).toBeVisible();
    const before = await toggle.getAttribute('aria-checked');
    expect(before === 'true' || before === 'false').toBe(true);
    // Toggling is client-side state only (no save), so this is safe to flip.
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-checked', before === 'true' ? 'false' : 'true');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-checked', before ?? 'false');

    // Show/hide guest password: type="button" and a stateful accessible name.
    const reveal = page.getByRole('button', { name: 'Show guest password' });
    await expect(reveal).toHaveAttribute('type', 'button');
    await reveal.click();
    await expect(page.getByRole('button', { name: 'Hide guest password' })).toHaveAttribute(
      'type',
      'button',
    );
    await page.getByRole('button', { name: 'Hide guest password' }).click();

    // Same contract on the Gemini key reveal.
    await page.getByRole('button', { name: 'Show Gemini API key' }).click();
    await expect(page.getByRole('button', { name: 'Hide Gemini API key' })).toBeVisible();

    // Remove-keyword buttons must be typed, named, and functional.
    const keywordInput = page.getByLabel('Suspicious Keywords Dictionary', { exact: true });
    await keywordInput.fill('audit-a11y-kw');
    await keywordInput.press('Enter');
    const removeBtn = page.getByRole('button', { name: 'Remove keyword audit-a11y-kw' });
    await expect(removeBtn).toHaveAttribute('type', 'button');
    await removeBtn.click();
    await expect(page.getByRole('button', { name: 'Remove keyword audit-a11y-kw' })).toHaveCount(0);
  });

  test('settings keyboard focus shows a visible ring on stripped-outline controls', async () => {
    await page.goto('/app/settings');
    await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
      timeout: 30_000,
    });

    const visibleFocus = (el: HTMLElement) => {
      const s = getComputedStyle(el);
      return { shadow: s.boxShadow, outline: s.outlineStyle };
    };

    // Guest mode switch: Shift+Tab from the password field (keyboard
    // interaction) must land on the switch WITH a :focus-visible ring.
    const pwInput = page.locator('#guest-password-input');
    await pwInput.click();
    await pwInput.press('Shift+Tab');
    const toggle = page.getByRole('switch', { name: 'Enable Guest Mode' });
    const toggleFocus = await toggle.evaluate(visibleFocus);
    expect(
      toggleFocus.shadow !== 'none' || toggleFocus.outline !== 'none',
      `guest switch needs a visible focus indicator (got ${JSON.stringify(toggleFocus)})`,
    ).toBe(true);

    // Remove-keyword chip button: Shift+Tab from the keyword input lands on
    // the last chip's remove button — its outline must not be stripped bare.
    const keywordInput = page.getByLabel('Suspicious Keywords Dictionary', { exact: true });
    await keywordInput.fill('ring-check-kw');
    await keywordInput.press('Enter');
    const removeBtn = page.getByRole('button', { name: 'Remove keyword ring-check-kw' });
    await expect(removeBtn).toBeVisible();
    await keywordInput.press('Shift+Tab');
    const removeFocus = await removeBtn.evaluate(visibleFocus);
    expect(
      removeFocus.shadow !== 'none' || removeFocus.outline !== 'none',
      `remove-keyword button needs a visible focus indicator (got ${JSON.stringify(removeFocus)})`,
    ).toBe(true);
  });

  test('group modal toggles expose aria-pressed state', async () => {
    await page.goto('/app/endpoints');
    await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });
    await page.getByRole('button', { name: /Add Group/i }).first().click();
    const dialog = page.locator('[role="dialog"][aria-modal="true"]');
    await expect(dialog).toBeVisible();

    // Category button: a name (from its visible text) and a pressed state.
    const category = dialog.getByRole('button', { name: /Adult Content/ });
    await expect(category).toBeVisible();
    await expect(category).toHaveAttribute('aria-pressed', 'false');
    await category.click();
    await expect(category).toHaveAttribute('aria-pressed', 'true');
    await category.click();
    await expect(category).toHaveAttribute('aria-pressed', 'false');

    // Security toggles expose the same state contract.
    const phishing = dialog.getByRole('button', { name: /Strict Phishing Protection/ });
    await expect(phishing).toHaveAttribute('aria-pressed', 'false');
    await phishing.click();
    await expect(phishing).toHaveAttribute('aria-pressed', 'true');
    const malware = dialog.getByRole('button', { name: /Strict Malware Filtering/ });
    await expect(malware).toHaveAttribute('aria-pressed', 'false');
    await malware.click();
    await expect(malware).toHaveAttribute('aria-pressed', 'true');

    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
  });

  test('group modal restores focus after a successful save', async () => {
    await page.goto('/app/endpoints');
    await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });

    // Mock only the POST; the GET list request keeps hitting the real API.
    await page.route('**/v1/groups', (route) => {
      if (route.request().method() === 'POST') {
        return route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 991,
            name: 'Focus Restore Group',
            description: '',
            block_categories: [],
            strict_phishing: false,
            strict_malware: false,
          }),
        });
      }
      return route.continue();
    });

    const opener = page.getByRole('button', { name: /Add Group/i }).first();
    await opener.click();
    const dialog = page.locator('[role="dialog"][aria-modal="true"]');
    await expect(dialog).toBeVisible();

    await page.getByLabel('Group Name', { exact: true }).fill('Focus Restore Group');
    await dialog.getByRole('button', { name: /Create Group/i }).click();

    await expect(dialog).toHaveCount(0);
    // The success close path must restore focus to the opener too.
    await expect(opener).toBeFocused();
  });

  test('group modal survives Escape during pending validation', async () => {
    await page.goto('/app/endpoints');
    await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });

    const opener = page.getByRole('button', { name: /Add Group/i }).first();
    await opener.click();
    const dialog = page.locator('[role="dialog"][aria-modal="true"]');
    await expect(dialog).toBeVisible();

    // Submit with an empty name — the zod resolver settles asynchronously…
    await dialog.getByRole('button', { name: /Create Group/i }).click();
    // …and dismiss BEFORE the validation result arrives.
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    // The dialog is gone; give any late async work (resolver promise, exit
    // animation) ample time to misbehave, then require focus to STILL be on
    // the opener — react-hook-form must not pull it back into the exiting
    // input, and nothing else may park it on <body>.
    await page.waitForTimeout(700);
    await expect(dialog).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  test('danger buttons keep a visible keyboard focus indicator', async () => {
    await page.goto('/app/analysis');
    await expect(page.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
      timeout: 30_000,
    });

    // Walk the tab order until a danger button receives keyboard focus.
    let indicator: { cls: string; shadow: string } | null = null;
    for (let i = 0; i < 15 && !indicator; i++) {
      await page.keyboard.press('Tab');
      indicator = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || !el.classList.contains('button-danger')) return null;
        const s = getComputedStyle(el);
        return { cls: el.className, shadow: s.boxShadow };
      });
    }
    expect(indicator, 'a .button-danger element should be reachable via Tab').not.toBeNull();
    expect(indicator!.shadow, 'focused danger button must show a focus ring').not.toBe('none');
  });
});
