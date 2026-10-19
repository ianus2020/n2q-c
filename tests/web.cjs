const {chromium} = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage();
  const errors = [], requests = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('request', r => requests.push(r.url()));
  try {
    await page.goto(process.env.N2Q_WEB_URL || 'http://127.0.0.1:8765');
    await page.waitForFunction(() => document.querySelector('#engine').textContent === 'WASM готов');
    for (const suite of ['128','256']) {
      await page.selectOption('#suite',suite);
      await page.click('#btn-key');
      await page.waitForFunction(n => document.querySelector('#key').value.length === n, Number(suite)/4);
      const key = await page.inputValue('#key');
      for (const profile of ['secure','fast']) {
        await page.selectOption('#profile',profile);
        await page.fill('#pt','<img src=x onerror=alert(1)> привет 🌍');
        await page.fill('#aad','ctx');
        await page.click('#btn-enc');
        await page.waitForFunction(() => document.querySelector('#out-ct').textContent.startsWith('nqc.'));
        const nonce = await page.inputValue('#nonce');
        await page.click('#btn-copy');await page.click('#btn-dec');
        await page.waitForFunction(() => document.querySelector('#out-pt').textContent.includes('привет 🌍'));
        assert.equal(await page.locator('#out-pt img').count(),0);
        await page.click('#btn-enc');
        await page.waitForFunction(n => document.querySelector('#nonce').value !== n,nonce);
      }
      await page.selectOption('#suite',suite==='128'?'256':'128');
      assert.equal(await page.inputValue('#key'),key);
    }
    await page.fill('#key','aжb');await page.click('#btn-enc');
    await page.waitForFunction(() => document.querySelector('#out-ct').textContent.startsWith('Ошибка:'));
    assert.equal(await page.isDisabled('#btn-copy'),true);
    await page.fill('#ct','n');await page.click('#btn-dec');
    await page.waitForFunction(() => document.querySelector('#out-pt').textContent.startsWith('Ошибка:'));
    await page.click('#btn-test');
    await page.waitForFunction(() => document.querySelector('#out-test').textContent.startsWith('PASS:'));
    // Terminating an active request must not repopulate cleared fields.
    await page.fill('#hval','x'.repeat(100000));await page.click('#btn-hash');await page.click('#btn-clear');
    await page.waitForFunction(() => document.querySelector('#engine').textContent === 'WASM готов');
    for (const id of ['key','nonce','aad','pt','aad2','ct','hval']) assert.equal(await page.inputValue('#'+id),'');
    for (const id of ['out-ct','out-pt','out-h','out-test']) assert.equal(await page.textContent('#'+id),'');
    assert.equal(await page.evaluate(() => localStorage.length+sessionStorage.length),0);
    assert.deepEqual(errors,[]);
    assert(requests.every(u => u.startsWith('http://127.0.0.1:8765/')), 'unexpected network request');
    console.log('Browser security scenarios PASS');
  } finally { await browser.close(); }
})().catch(e => {console.error(e);process.exit(1);});
