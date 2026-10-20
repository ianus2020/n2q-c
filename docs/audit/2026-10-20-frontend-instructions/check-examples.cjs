const assert = require('node:assert/strict');
const fs = require('node:fs');
const {createRequire} = require('node:module');
const projectRequire = createRequire(process.cwd() + '/package.json');
const {chromium} = projectRequire('playwright');

(async () => {
  const base = process.env.N2Q_WEB_URL;
  const output = process.env.N2Q_EXAMPLES_OUTPUT;
  assert(base && output);
  const readme = fs.readFileSync('impl/n2q-c-wasm/README.md', 'utf8');
  const code = readme.match(/```js\n([\s\S]*?)\n```/)[1];
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({ignoreHTTPSErrors: process.env.N2Q_LOCAL_TEST_CA === '1'});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base);
    await page.waitForFunction(() => document.querySelector('#engine').textContent === 'WASM готов');
    const defaults = {suite: await page.inputValue('#suite'), profile: await page.inputValue('#profile')};
    assert.deepEqual(defaults, {suite: '128', profile: 'secure'});
    const exampleURL = new URL('./doc-example-check.js', page.url()).href;
    // Serve the exact README code as a same-origin module, with exports added
    // only for observation. No public release or application source is changed.
    await page.route(exampleURL, route => route.fulfill({contentType: 'text/javascript',
      body: code + '\nexport {keyHex, nonceHex, token, plaintext};\n'}));
    const api = await page.evaluate(async url => {
      const example = await import(url);
      return {key_hex_length: example.keyHex.length, nonce_hex_length: example.nonceHex.length,
        prefix: example.token.slice(0, 4), roundtrip: example.plaintext === 'Привет 🌍'};
    }, exampleURL);
    assert.deepEqual(api, {key_hex_length: 32, nonce_hex_length: 32, prefix: 'nqc.', roundtrip: true});
    const rows = [];
    for (const suite of ['128', '256']) {
      await page.selectOption('#suite', suite);
      await page.click('#btn-key');
      await page.waitForFunction(length => document.querySelector('#key').value.length === length, Number(suite) / 4);
      for (const profile of ['secure', 'fast']) {
        await page.selectOption('#suite', suite);
        await page.selectOption('#profile', profile);
        await page.fill('#aad', 'demo:v1');
        await page.fill('#pt', 'Привет 🌍');
        await page.click('#btn-enc');
        await page.waitForFunction(() => document.querySelector('#out-ct').textContent.startsWith('nqc.'));
        const token = await page.textContent('#out-ct');
        const raw = Buffer.from(token.slice(4), 'base64url');
        const expectedCode = (suite === '128' ? 1 : 2) | (profile === 'fast' ? 32 : 0);
        assert.equal(raw[0], 1);
        assert.equal(raw[1], expectedCode);
        assert.equal(raw.subarray(2, 18).toString('hex'), await page.inputValue('#nonce'));
        assert.equal(await page.getAttribute('#nonce', 'readonly'), '');
        await page.click('#btn-copy');
        assert.equal(await page.inputValue('#ct'), token);
        assert.equal(await page.inputValue('#aad2'), 'demo:v1');
        // Decryption reads its size/profile from the token, independently of
        // the selectors used for subsequent encryption/hash/index operations.
        await page.selectOption('#suite', suite === '128' ? '256' : '128');
        await page.selectOption('#profile', profile === 'secure' ? 'fast' : 'secure');
        await page.click('#btn-dec');
        await page.waitForFunction(() => document.querySelector('#out-pt').textContent === 'Привет 🌍');
        await page.fill('#aad2', 'different context');
        await page.click('#btn-dec');
        await page.waitForFunction(() => document.querySelector('#out-pt').textContent.startsWith('Ошибка:'));
        await page.selectOption('#suite', suite);
        await page.selectOption('#profile', profile);
        await page.fill('#hval', 'example:value');
        await page.click('#btn-hash');
        const hashLength = suite === '128' ? 64 : 128;
        await page.waitForFunction(length => {
          const value = document.querySelector('#out-h').textContent;
          return value.length === length && /^[a-f0-9]+$/.test(value);
        }, hashLength);
        await page.click('#btn-bi');
        const indexLength = suite === '128' ? 32 : 64;
        await page.waitForFunction(length => {
          const value = document.querySelector('#out-h').textContent;
          return value.length === length && /^[a-f0-9]+$/.test(value);
        }, indexLength);
        const index = await page.textContent('#out-h');
        await page.click('#btn-bi');
        await page.waitForFunction(value => document.querySelector('#out-h').textContent === value, index);
        rows.push({suite, profile, key_hex_length: Number(suite) / 4, nonce_hex_length: 32,
          token_version: raw[0], suite_byte: raw[1], hash_hex_length: hashLength,
          index_hex_length: indexLength, copied_aad: true, auto_dispatch: true,
          wrong_aad_rejected: true, index_deterministic: true});
      }
    }
    await page.click('#btn-clear');
    await page.waitForFunction(() => document.querySelector('#engine').textContent === 'WASM готов');
    assert.equal(await page.inputValue('#key'), '');
    await page.fill('#hval', 'example:value');
    await page.click('#btn-hash');
    await page.waitForFunction(() => /^[a-f0-9]+$/.test(document.querySelector('#out-h').textContent));
    await page.click('#btn-clear');
    await page.waitForFunction(() => document.querySelector('#engine').textContent === 'WASM готов');
    const layout = [];
    for (const width of [1100, 390]) {
      await page.setViewportSize({width, height: 900});
      const fits = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
      assert.equal(fits, true);
      layout.push({width, fits});
    }
    await page.setViewportSize({width: 1100, height: 1000});
    await page.screenshot({path: output + '.png', fullPage: true});
    assert.deepEqual(errors, []);
    const result = {base, defaults, readme_example: api, scenarios: rows, keyless_hash: true, layout,
      limits: await page.evaluate(() => Object.fromEntries(['key', 'pt', 'aad', 'aad2', 'ct', 'hval']
        .map(id => [id, document.getElementById(id).maxLength]))), page_errors: errors};
    fs.writeFileSync(output + '.json', JSON.stringify(result, null, 2) + '\n');
    console.log('Documented example and 4 UI combinations PASS: ' + base);
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exit(1);});
