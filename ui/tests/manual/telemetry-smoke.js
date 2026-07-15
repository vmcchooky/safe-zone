const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('console', msg => { if(msg.type()==='error') console.log('BROWSER_ERR:', msg.text()) });
  page.on('pageerror', err => console.log('PAGE_ERR:', err.message));
  await page.goto('http://localhost:5173/app/login');
  await page.fill('#auth-username', 'admin');
  await page.fill('#auth-password', 'admin');
  await Promise.all([ page.waitForNavigation(), page.click('.button-primary') ]);
  await page.goto('http://localhost:5173/app/telemetry');
  await page.waitForTimeout(2000);
  console.log('HTML:', await page.content());
  await browser.close();
})();
