const {chromium} = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({headless: true});
  // Only the explicit ephemeral local-CA integration run bypasses browser CA
  // trust. Certificate/hostname checks are tested separately without bypasses.
  const context = await browser.newContext({ignoreHTTPSErrors:process.env.N2Q_LOCAL_TEST_CA==='1'});
  const page = await context.newPage();
  const errors = [], requests = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('request', r => requests.push(r.url()));
  try {
    const base=process.env.N2Q_WEB_URL || 'http://127.0.0.1:8765';
    const response=await page.goto(base);
    if(base.startsWith('https:'))assert.equal(await page.evaluate(()=>isSecureContext),true);
    const headers=response.headers();
    assert(headers['content-security-policy'].includes("frame-ancestors 'none'"));
    assert.equal(headers['x-content-type-options'],'nosniff');
    assert.equal(headers['referrer-policy'],'no-referrer');
    assert.equal(headers['cross-origin-opener-policy'],'same-origin');
    assert.equal(headers['cross-origin-embedder-policy'],'require-corp');
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
    // Replacing a key must invalidate the displayed results produced with the
    // previous key, just like editing the key field manually does.
    await page.selectOption('#suite','128');
    await page.click('#btn-key');
    await page.waitForFunction(()=>document.querySelector('#key').value.length===32);
    const previousKey=await page.inputValue('#key');
    await page.fill('#pt','key replacement fixture');await page.fill('#aad','ctx');
    await page.click('#btn-enc');
    await page.waitForFunction(()=>document.querySelector('#out-ct').textContent.startsWith('nqc.'));
    await page.click('#btn-copy');await page.click('#btn-dec');
    await page.waitForFunction(()=>document.querySelector('#out-pt').textContent==='key replacement fixture');
    await page.fill('#hval','index fixture');await page.click('#btn-bi');
    await page.waitForFunction(()=>/^[0-9a-f]+$/i.test(document.querySelector('#out-h').textContent));
    await page.click('#btn-key');
    await page.waitForFunction(old=>document.querySelector('#key').value!==old,previousKey);
    assert.equal(await page.textContent('#out-pt'),'','new key retained the previous decrypted output');
    assert.equal(await page.textContent('#out-h'),'','new key retained the previous blind index');
    assert.equal(await page.textContent('#out-ct'),'');
    assert.equal(await page.inputValue('#nonce'),'');
    assert.equal(await page.isDisabled('#btn-copy'),true);
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
    const origin=new URL(base).origin;
    assert(requests.every(u => u.startsWith(origin+'/') || u.startsWith('blob:'+origin+'/')), 'unexpected network request');
    // UTF-8 byte limits apply even when browser maxlength counts characters.
    await page.fill('#hval','🌍'.repeat(262145));await page.click('#btn-hash');
    await page.waitForFunction(()=>document.querySelector('#out-h').textContent.startsWith('Ошибка:'));
    assert.equal(await page.isDisabled('#btn-hash'),false);
    // A mismatched public JS/WASM pair must never enable crypto controls.
    for(const asset of ['n2q_c_wasm.js','n2q_c_wasm_bg.wasm']) {
      const bad=await context.newPage();
      await bad.route('**/pkg/'+asset,async route=>{
        const response=await route.fetch(),body=Buffer.from(await response.body());
        body[body.length-1]^=1;await route.fulfill({response,body});
      });
      await bad.goto(base);
      await bad.waitForFunction(()=>document.querySelector('#engine').textContent.includes('Не удалось проверить'));
      assert.equal(await bad.isDisabled('#btn-key'),true);await bad.close();
    }
    // Real worker failure while a request is pending must reject it and unlock
    // Clear. No response is allowed to revive the crashed worker.
    console.log('Browser normal flows, headers, UTF-8 limits and mixed assets PASS');
    const stubWorker=body=>async route=>{
      const response=await route.fetch();
      await route.fulfill({response,body,contentType:'text/javascript'});
    };
    const crash=await context.newPage();
    await crash.route('**/crypto-worker.js',stubWorker("self.postMessage({ready:true});self.onmessage=()=>{throw new Error('injected worker failure')}"));
    await crash.goto(base);await crash.waitForFunction(()=>document.querySelector('#engine').textContent==='WASM готов');
    await crash.fill('#hval','data');await crash.click('#btn-hash');
    await crash.waitForFunction(()=>document.querySelector('#out-h').textContent.startsWith('Ошибка:'));
    assert.equal(await crash.isDisabled('#btn-hash'),true);
    assert.equal(await crash.isDisabled('#btn-clear'),false);
    await crash.unrouteAll({behavior:'wait'});await crash.close();
    // Virtual clock exercises deadlines without sleeping for 30 seconds.
    const hung=await context.newPage();await hung.clock.install();
    await hung.route('**/crypto-worker.js',stubWorker('self.postMessage({ready:true})'));
    await hung.goto(base);await hung.waitForFunction(()=>document.querySelector('#engine').textContent==='WASM готов');
    await hung.fill('#hval','data');await hung.click('#btn-hash');await hung.clock.fastForward(31000);
    await hung.waitForFunction(()=>document.querySelector('#engine').textContent.includes('Превышено время операции'));
    assert.equal(await hung.isDisabled('#btn-key'),true);
    await hung.unrouteAll({behavior:'wait'});await hung.close();
    const startup=await context.newPage();await startup.clock.install();
    await startup.route('**/crypto-worker.js',stubWorker('// intentionally never ready'));
    await startup.goto(base);await startup.clock.fastForward(16000);
    await startup.waitForFunction(()=>document.querySelector('#engine').textContent.includes('Превышено время загрузки'));
    await startup.unrouteAll({behavior:'wait'});await startup.close();
    const blocked=await context.newPage();
    await blocked.addInitScript(()=>{window.Worker=class{constructor(){throw new Error('blocked')}}});
    await blocked.goto(base);
    await blocked.waitForFunction(()=>document.querySelector('#engine').textContent.includes('Worker недоступен'));
    assert.equal(await blocked.isDisabled('#btn-key'),true);await blocked.close();
    console.log('Browser security scenarios PASS');
  } finally {
    for(const active of context.pages())await active.unrouteAll({behavior:'wait'});
    await browser.close();
  }
})().catch(e => {console.error(e);process.exit(1);});
