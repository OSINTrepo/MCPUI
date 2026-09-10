// Запуск: NODE_PATH=<каталог модулей> node tests/browser_diagrams.cjs report.html fixture.html [before.html]
// Fixture: две корректные mermaid-схемы, одна некорректная и обычный блок python.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
    const external = [];
    await context.route(/^https?:/, route => {
      external.push(route.request().url());
      return route.abort();
    });
    const page = await context.newPage();
    if (process.argv[4]) {
      await page.goto(pathToFileURL(path.resolve(process.argv[4])).href);
      assert.ok(await page.locator('pre.mermaid').count());
      assert.equal(await page.locator('pre.mermaid svg').count(), 0);
      console.log('Воспроизведено: старый HTML показывает исходник вместо схем.');
    }
    external.length = 0;
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await context.setOffline(true);
    await page.goto(pathToFileURL(path.resolve(process.argv[2])).href);
    await page.waitForFunction(() => document.querySelectorAll('.report-diagram').length > 0 &&
      [...document.querySelectorAll('.report-diagram')].every(d => d.dataset.state === 'rendered'));
    assert.equal(external.length, 0, 'Отчёт не должен запрашивать CDN');
    assert.equal(await page.locator('pre.mermaid').count(), 0);
    const first = page.locator('.report-diagram').first();
    const oldId = await first.locator('svg').getAttribute('id');
    await page.locator('#theme-btn').click();
    await page.waitForFunction(id => document.querySelector('.report-diagram svg').id !== id, oldId);
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
    const fitted = (await first.locator('svg').boundingBox()).width;
    await first.getByRole('button', {name: 'Исходный масштаб', exact: true}).click();
    assert.ok((await first.locator('svg').boundingBox()).width >= fitted);
    await first.getByRole('button', {name: 'По ширине', exact: true}).click();
    await page.locator('#theme-btn').click();
    await page.waitForFunction(() => document.querySelector('.report-diagram svg').id.startsWith('report-diagram-3-'));
    await first.screenshot({path: '/tmp/indra-diagram-fixed.png'});
    console.log('Отчёт: схемы построены без сети, тема и масштаб работают.');
    await page.goto(pathToFileURL(path.resolve(process.argv[3])).href);
    await page.waitForFunction(() => document.querySelectorAll('.report-diagram[data-state]').length === 3);
    assert.equal(await page.locator('.report-diagram[data-state="rendered"]').count(), 2);
    assert.equal(await page.locator('.report-diagram[data-state="error"]').count(), 1);
    assert.equal(await page.locator('code.language-python').textContent(), 'print(123)\n');
    assert.ok((await page.locator('.report-diagram').first().textContent()).includes('Компания & партнёры'));
    assert.deepEqual(errors, []);
    console.log('Регрессии: ошибка изолирована, кириллица/акценты и обычный код сохранены.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
