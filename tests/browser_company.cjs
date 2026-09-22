// Настоящий UI-прогон: расходует баланс API и собирает открытые сведения о компании.
// OSINT_UI_CREDENTIALS — путь к JSON {email,password}; секреты не выводятся.
// NODE_PATH=... PLAYWRIGHT_BROWSERS_PATH=... node tests/browser_company.cjs [--login-only]
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  assert.ok(process.env.OSINT_UI_CREDENTIALS, 'Задайте OSINT_UI_CREDENTIALS');
  const credentials = JSON.parse(fs.readFileSync(process.env.OSINT_UI_CREDENTIALS, 'utf8'));
  const origin = process.env.OSINT_UI_URL || 'http://localhost:3080';
  const reportsOrigin = new URL(process.env.REPORTS_URL_BASE || 'http://localhost:8899').origin;
  const output = path.resolve(process.env.OSINT_UI_OUTPUT || 'scratchpad/ui-e2e');
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  const browser = await chromium.launch({ headless: true });
  const result = { started: new Date().toISOString(), requests: [], login: false, status: 'running' };
  const save = () => fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
  save();
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    let chatFailure;
    page.on('response', response => {
      const url = new URL(response.url());
      if (response.request().method() === 'POST' && url.pathname.startsWith('/api/agents/chat/')) {
        const body = response.request().postDataJSON();
        result.requests.push({ path: url.pathname, status: response.status(), model: body?.model, spec: body?.spec });
        if (response.status() >= 400) chatFailure = 'Chat HTTP ' + response.status();
      }
    });
    await page.goto(origin + '/login', { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.locator('input[name=email]').fill(credentials.email);
    await page.locator('input[name=password]').fill(credentials.password);
    await page.locator('button[type=submit]').click();
    await page.waitForURL('**/c/new', { timeout: 60000 });
    await page.locator('#prompt-textarea').waitFor({ timeout: 30000 });
    // Первый вход тестового пользователя может показывать условия платформы.
    const accept = page.getByRole('button', { name: /^(Принимаю|I agree|Accept)$/ });
    if (await accept.count()) await accept.click();
    assert.ok((await page.locator('body').innerText()).includes('DeepSeek · OSINT Авто'));
    result.login = true;
    if (process.argv.includes('--login-only')) {
      result.status = 'passed';
      console.log('Вход и выбор пресета: OK');
      return;
    }
    const task = process.env.OSINT_UI_TASK || 'Собери подробное досье по компании Microsoft Corporation, США, тикер MSFT, CIK 0000789019, официальный сайт microsoft.com. Нужны юридическая идентификация, корпоративная структура и руководство, годовые финансовые показатели, проекты и география, инфраструктура домена, источники и ограничения. Сохрани полный отчёт HTML, Markdown и PDF.';
    await page.locator('#prompt-textarea').fill(task);
    await page.locator('#prompt-textarea').press('Enter');
    result.submitted = new Date().toISOString();
    const deadline = Date.now() + 18 * 60000;
    while (Date.now() < deadline) {
      await page.waitForTimeout(5000);
      assert.ok(!chatFailure, chatFailure);
      result.elapsedSeconds = Math.round((Date.now() - Date.parse(result.started)) / 1000);
      save();
      const body = await page.locator('body').innerText();
      assert.ok(!body.includes('Something went wrong'), 'Ошибка чата');
      const links = await page.locator('a[href]').evaluateAll(elements => elements.map(e => e.href));
      const reportLinks = [...new Set(links.filter(url => {
        const parsed = new URL(url);
        return parsed.origin === reportsOrigin && /\.(html|md|pdf)$/.test(parsed.pathname);
      }))];
      if (!['html', 'md', 'pdf'].every(ext => reportLinks.some(url => url.endsWith('.' + ext)))) continue;
      result.links = reportLinks;
      result.conversation = page.url();
      result.files = [];
      for (const url of reportLinks) {
        const response = await context.request.get(url);
        assert.equal(response.status(), 200, url);
        const bytes = await response.body();
        assert.ok(bytes.length > 100, url);
        if (url.endsWith('.pdf')) assert.equal(bytes.subarray(0, 5).toString(), '%PDF-');
        if (new URL(url).pathname.includes('/download/')) {
          assert.match(response.headers()['content-disposition'] || '', /attachment/);
        }
        result.files.push({ url, bytes: bytes.length });
      }
      assert.ok(result.requests.some(r => r.status === 200 && r.model === 'deepseek-flash'));
      await page.screenshot({ path: path.join(output, 'chat.png'), fullPage: true });
      fs.writeFileSync(path.join(output, 'chat.txt'), body);
      result.status = 'passed';
      console.log('Вход → запрос компании → HTML/Markdown/PDF: OK');
      return;
    }
    throw new Error('Досье не появилось за 18 минут');
  } catch (error) {
    result.status = 'failed';
    result.error = error.message;
    throw error;
  } finally {
    result.finished = new Date().toISOString();
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
