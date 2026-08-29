/**
 * UX Overlap Probe — Layer 1 hitbox audit.
 *
 * Detects interactive elements whose clickable area is covered by a foreign
 * layer (oversized container, negative margin, z-index stacking). For every
 * sampled point of each interactive element we ask the browser which element
 * would actually receive the click (document.elementsFromPoint):
 *
 *   - target is NOT in the point's stack  -> invisible cover (the bug class:
 *     a big transparent box blocking clicks around a small visible widget)
 *   - target is in the stack but not on top -> something paints over it
 *
 * Known-good patterns explicitly filtered out:
 *   - Loader/backdrop overlays: we wait for `.app-loader-backdrop` to hide
 *     before probing; a loader stuck >30s fails as its own assertion.
 *   - Content clipped away by a scrollport or rounded corner (dock swipe
 *     strips, glass pills): points outside the visible clip region or inside
 *     a border-radius cut — of an ancestor OR of the element itself — are
 *     skipped, and candidates are centered in their scrollport first.
 *   - The floating dock deliberately overlays scrolled content; probing with
 *     the dock forced visible and every element centered means a hit is only
 *     reported when the element cannot be brought clear of the dock by
 *     scrolling — i.e. a permanent, user-reachable occlusion.
 *
 * Runs against the REAL dev UI + REAL core API (same stack as CI e2e).
 * Login happens once per worker and is reused via storageState so the API
 * login rate limiter is never exhausted.
 */
import { test, expect, type Page } from '@playwright/test';

const ADMIN_USER = 'admin';
const ADMIN_PASS = 'playwright_test_password_1234';

/** Routes reachable for an admin session. */
const ROUTES = [
  '/app/analysis',
  '/app/telemetry',
  '/app/endpoints',
  '/app/overrides',
  '/app/system',
  '/app/settings',
  '/app/reports',
];

/** Viewports: desktop + narrow phone-ish size where crowding happens. */
const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'narrow', width: 390, height: 844 },
];

interface OverlapHit {
  x: number;
  y: number;
  kind: 'covers' | 'paints-over';
  blocker: string;
}

interface ElementReport {
  selector: string;
  rect: { x: number; y: number; w: number; h: number };
  hits: OverlapHit[];
}

async function waitLoaderGone(page: Page) {
  await expect(page.locator('.app-loader-backdrop.is-visible')).toHaveCount(0, {
    timeout: 30_000,
  });
}

/** Wait until the lazy route has actually rendered its content. */
async function waitForRouteSettled(page: Page) {
  await waitLoaderGone(page);
  await expect(page.locator('.shell-content h1').first()).toBeVisible({ timeout: 20_000 });
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await page.waitForTimeout(500); // framer-motion transitions settle
}

async function loginForStorageState(browser: any): Promise<string> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/app/analysis');
  // AuthProvider enforces a min 1.2s session check before rendering anything,
  // so the login card appears late — wait for it explicitly.
  await page.getByTestId('login-card').waitFor({ state: 'visible', timeout: 20_000 });
  await page.getByPlaceholder('Enter your username').fill(ADMIN_USER);
  await page.getByPlaceholder('Enter your access secret').fill(ADMIN_PASS);
  await page.getByRole('button', { name: /Authenticate/i }).click();
  await expect(page.getByRole('navigation', { name: 'Workspace routes' })).toBeVisible({
    timeout: 20_000,
  });
  await waitLoaderGone(page);
  const state = await context.storageState();
  await context.close();
  return JSON.stringify(state);
}

/**
 * The dock auto-hides 2.5s after mount and re-appears when the pointer
 * enters the bottom 160px of the window (AppShell mousemove handler). Force
 * the visible state — without a real pointer move, so no :hover transform
 * pollutes the measured geometry — so every probe samples the worst case:
 * the dock floating over the content.
 */
async function showDock(page: Page) {
  await page.evaluate(() => {
    window.dispatchEvent(
      new MouseEvent('mousemove', { clientX: 12, clientY: window.innerHeight - 8 }),
    );
  });
  await expect(page.locator('.shell-floating-dock-inner')).toBeVisible({ timeout: 5_000 });
  await page.waitForTimeout(700); // dock spring transition settles
}

/**
 * Executed in the page: samples edge + center points of every interactive
 * element and returns entries where a foreign element would take the click.
 */
async function probeInPage(page: Page): Promise<ElementReport[]> {
  return page.evaluate(() => {
    const INTERACTIVE_TAGS = new Set(['button', 'a', 'input', 'select', 'textarea']);
    const INTERACTIVE_ROLES = new Set(['button', 'tab', 'link', 'checkbox', 'menuitem']);

    const isInteractive = (el: Element): boolean => {
      const tag = el.tagName.toLowerCase();
      if (INTERACTIVE_TAGS.has(tag)) return true;
      const role = el.getAttribute('role');
      return role !== null && INTERACTIVE_ROLES.has(role);
    };

    const isClickable = (el: Element): boolean =>
      // pointer-events is inherited: the element's own computed value already
      // accounts for a pe:none ancestor re-enabled by a closer pe:auto wrapper.
      getComputedStyle(el).pointerEvents !== 'none';

    const described = new Set<string>();
    const describe = (el: Element, withRect = false): string => {
      const tag = el.tagName.toLowerCase();
      const id = el.id ? `#${el.id}` : '';
      const cls =
        typeof el.className === 'string' && el.className
          ? `.${el.className.split(/\s+/).slice(0, 3).join('.')}`
          : '';
      let desc = `${tag}${id}${cls}`;
      if (described.has(desc)) desc = `${desc} <<#${described.size}>>`;
      described.add(desc);
      if (withRect) {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        desc += ` [rect(${Math.round(r.left)},${Math.round(r.top)}, ${Math.round(r.width)}x${Math.round(
          r.height,
        )}) pos=${s.position} z=${s.zIndex}]`;
      }
      const text = (el.textContent || '').trim().slice(0, 30);
      return text ? `${desc} "${text}"` : desc;
    };

    /**
     * Corner circles of a border-radius box. Radii are clamped to half the
     * box size — "rounded-full" pills compute to 9999px but the actual arc
     * is an ellipse capped at min(w,h)/2, and unclamped centers would fall
     * outside the box and never match any sampled point.
     */
    const cornerCutsFor = (
      r: DOMRect,
      style: CSSStyleDeclaration,
    ): Array<{ cx: number; cy: number; r: number; qx: number; qy: number }> => {
      const halfW = r.width / 2;
      const halfH = r.height / 2;
      const clamp = (v: string) => Math.min(parseFloat(v) || 0, halfW, halfH);
      const radii = [
        clamp(style.borderTopLeftRadius),
        clamp(style.borderTopRightRadius),
        clamp(style.borderBottomLeftRadius),
        clamp(style.borderBottomRightRadius),
      ];
      const corners: Array<{ cx: number; cy: number; r: number; qx: number; qy: number }> = [];
      if (radii[0] > 2) corners.push({ cx: r.left + radii[0], cy: r.top + radii[0], r: radii[0], qx: -1, qy: -1 });
      if (radii[1] > 2) corners.push({ cx: r.right - radii[1], cy: r.top + radii[1], r: radii[1], qx: 1, qy: -1 });
      if (radii[2] > 2) corners.push({ cx: r.left + radii[2], cy: r.bottom - radii[2], r: radii[2], qx: -1, qy: 1 });
      if (radii[3] > 2) corners.push({ cx: r.right - radii[3], cy: r.bottom - radii[3], r: radii[3], qx: 1, qy: 1 });
      return corners;
    };

    /** Clip regions of every scroll/clip ancestor plus the viewport. */
    const clipRegions = (el: Element): {
      rects: DOMRect[];
      corners: Array<{ cx: number; cy: number; r: number; qx: number; qy: number }>;
    } => {
      const rects: DOMRect[] = [new DOMRect(0, 0, window.innerWidth, window.innerHeight)];
      const corners: Array<{ cx: number; cy: number; r: number; qx: number; qy: number }> = [];
      let cur: Element | null = el.parentElement;
      while (cur) {
        const s = getComputedStyle(cur);
        const clipsX = s.overflowX !== 'visible';
        const clipsY = s.overflowY !== 'visible';
        if (clipsX || clipsY) {
          const r = cur.getBoundingClientRect();
          rects.push(r);
          corners.push(...cornerCutsFor(r, s));
        }
        cur = cur.parentElement;
      }
      return { rects, corners };
    };

    const insideAll = (x: number, y: number, rects: DOMRect[]): boolean =>
      rects.every((r) => x >= r.left && x <= r.right && y >= r.top && y <= r.bottom);

    const inCornerCut = (
      x: number,
      y: number,
      corners: Array<{ cx: number; cy: number; r: number; qx: number; qy: number }>,
    ): boolean =>
      corners.some((c) => {
        // Inside the corner's r×r square, on the outward quadrant, and beyond
        // the rounded arc -> the point is visually clipped away.
        const dx = (x - c.cx) * c.qx;
        const dy = (y - c.cy) * c.qy;
        if (dx < 0 || dy < 0 || dx > c.r || dy > c.r) return false;
        return Math.hypot(x - c.cx, y - c.cy) > c.r - 1.5;
      });

    const edgePoints = (rect: DOMRect): Array<{ x: number; y: number }> => {
      const pts: Array<{ x: number; y: number }> = [];
      const inset = 3;
      const xs = [rect.left + inset, rect.left + rect.width / 2, rect.right - inset];
      const ys = [rect.top + inset, rect.top + rect.height / 2, rect.bottom - inset];
      for (const x of xs) pts.push({ x, y: rect.top + inset });
      for (const x of xs) pts.push({ x, y: rect.bottom - inset });
      for (const y of ys) pts.push({ x: rect.left + inset, y });
      for (const y of ys) pts.push({ x: rect.right - inset, y });
      pts.push({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
      const seen = new Set<string>();
      return pts.filter((p) => {
        const k = `${Math.round(p.x)}:${Math.round(p.y)}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    };

    const reports: ElementReport[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      if (!isInteractive(el) || !isClickable(el)) continue;
      const htmlEl = el as HTMLElement;
      const pre = htmlEl.getBoundingClientRect();
      if (pre.width < 4 || pre.height < 4) continue;
      const preStyle = getComputedStyle(el);
      if (preStyle.visibility === 'hidden' || preStyle.display === 'none') continue;

      // Center candidates in their scrollport before measuring. "nearest"
      // would park elements scrolled into view exactly at the bottom edge —
      // under the floating dock — even though scrolling further clears them;
      // an element still occluded after centering is permanently blocked.
      htmlEl.scrollIntoView({ block: 'center', inline: 'nearest' });
      const rect = htmlEl.getBoundingClientRect();
      if (rect.bottom < 0 || rect.top > window.innerHeight) continue;
      if (rect.right < 0 || rect.left > window.innerWidth) continue;

      const { rects, corners } = clipRegions(el);
      // The element's own rounded corners clip its hit region the same way an
      // ancestor's do: a point past the arc misses the element entirely
      // (elementsFromPoint omits it) and must not read as an occluder.
      corners.push(...cornerCutsFor(rect, preStyle));

      const hits: OverlapHit[] = [];
      for (const pt of edgePoints(rect)) {
        if (!insideAll(pt.x, pt.y, rects)) continue; // clipped-away: not clickable by design
        if (inCornerCut(pt.x, pt.y, corners)) continue; // rounded-corner cut
        const stack = document.elementsFromPoint(pt.x, pt.y);
        if (stack.length === 0) continue;
        const top = stack[0];
        if (top === el || top.contains(el) || el.contains(top)) continue;
        const idx = stack.indexOf(el);
        if (idx === -1) {
          hits.push({ x: pt.x, y: pt.y, kind: 'covers', blocker: describe(top, true) });
        } else if (idx > 0) {
          hits.push({ x: pt.x, y: pt.y, kind: 'paints-over', blocker: describe(top, true) });
        }
        if (hits.length >= 6) break;
      }

      if (hits.length > 0) {
        reports.push({
          selector: describe(el, true),
          rect: { x: rect.x, y: rect.y, w: rect.width, h: rect.height },
          hits,
        });
      }
    }
    return reports;
  });
}

test.describe('UX overlap probe', () => {
  let context: any;
  let page: Page;
  let storageState: string;

  test.setTimeout(120_000);

  test.beforeAll(async ({ browser }) => {
    storageState = await loginForStorageState(browser);
  });

  test.beforeEach(async ({ browser }) => {
    context = await browser.newContext({ storageState: JSON.parse(storageState) });
    page = await context.newPage();
  });

  test.afterEach(async () => {
    // Every BrowserContext must be released after its test, or headless
    // Chrome processes pile up across the 14 route×viewport combinations.
    await context?.close();
    context = null;
    page = null as unknown as Page;
  });

  for (const vp of VIEWPORTS) {
    for (const route of ROUTES) {
      test(`no invisible occluder on ${route} [${vp.name}]`, async ({}, testInfo) => {
        await page.setViewportSize({ width: vp.width, height: vp.height });
        await page.goto(route);
        await waitForRouteSettled(page);
        await showDock(page);

        const reports = await probeInPage(page);
        if (reports.length > 0) {
          const shot = testInfo.outputPath(`overlap-${vp.name}.png`);
          await page.screenshot({ path: shot, fullPage: false });
          const detail = reports
            .map(
              (r) =>
                `${r.selector}\n    blocked at ${r.hits
                  .map((h) => `(${Math.round(h.x)},${Math.round(h.y)}) ${h.kind} by ${h.blocker}`)
                  .join('\n                 ')}`,
            )
            .join('\n');
          throw new Error(
            `Interactive elements occluded on ${route} [${vp.name}] (${reports.length} elements, screenshot: ${shot}):\n${detail}`,
          );
        }
        expect(reports).toHaveLength(0);
      });
    }
  }

  /**
   * Positive control for the probe itself: if someone later loosens the probe
   * (over-filtering elements or hits), these assertions fail and expose a
   * green-but-blind audit. A fixed, fully transparent, full-viewport occluder
   * is injected; the probe MUST report it as a blocker while it is present
   * and MUST report a clean page once it is removed. Full-viewport coverage
   * keeps the control immune to the probe's own scrollIntoView calls.
   */
  test('probe positive control: catches an injected fixed occluder', async () => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/app/analysis');
    await waitForRouteSettled(page);

    const occluderClass = 'overlap-probe-positive-control';

    const reportsForTarget = () =>
      probeInPage(page).then((reports) =>
        reports.filter((r) => r.selector.startsWith('button') && r.selector.includes('"Analyze"')),
      );

    // Sanity: the Analyze control is clean before any occluder is injected.
    expect(await reportsForTarget()).toHaveLength(0);

    await page.evaluate((cls) => {
      const btn = Array.from(document.querySelectorAll('button')).find((b) =>
        (b.textContent || '').includes('Analyze'),
      );
      if (!btn) throw new Error('Analyze button not found');
      const r = btn.getBoundingClientRect();
      const occluder = document.createElement('div');
      occluder.className = cls;
      // Cover the whole viewport from the button's position so the probe
      // cannot dodge the occluder by centering elements in a scrollport.
      occluder.style.cssText = [
        'position:fixed',
        `left:${Math.min(0, r.left)}px`,
        `top:${Math.min(0, r.top)}px`,
        `width:${Math.max(window.innerWidth, r.right)}px`,
        `height:${Math.max(window.innerHeight, r.bottom)}px`,
        'background:transparent',
        'z-index:2147483647',
        'pointer-events:auto',
      ].join(';');
      document.body.appendChild(occluder);
    }, occluderClass);

    const hits = await reportsForTarget();
    expect(hits.length, 'probe must fail while a fixed occluder covers the control').toBeGreaterThan(0);
    expect(
      hits.some((r) => r.hits.some((h) => h.blocker.includes(occluderClass))),
      'the reported blocker must be the injected occluder itself',
    ).toBe(true);

    await page.evaluate((cls) => {
      document.querySelector(`.${cls}`)?.remove();
    }, occluderClass);

    expect(await reportsForTarget()).toHaveLength(0);
  });
});
