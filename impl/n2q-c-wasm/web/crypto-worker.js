import init, * as n2q from './pkg/n2q_c_wasm.js';
const ready = init();
const utf8 = new TextEncoder();
function bounded(value, max = 1048576) {
  if (typeof value !== 'string' || value.length > max || utf8.encode(value).length > max) throw new Error('Превышен лимит размера');
  return value;
}
function key(value, suite) {
  if (typeof value !== 'string' || !(suite === '128' ? /^[0-9a-fA-F]{32}$/ : /^[0-9a-fA-F]{64}$/).test(value)) throw new Error('Неверная длина или формат ключа');
  return value;
}
function dispatch(op, a) {
  const suite = a.suite;
  if (!['128', '256'].includes(suite)) throw new Error('Неизвестный размер ключа');
  switch (op) {
    case 'key': return n2q['keygen' + suite]();
    case 'seal': {
      const k = key(a.key, suite), nonce = n2q.gen_nonce();
      return {nonce, token: n2q['seal' + suite](a.fast === true, k, nonce, bounded(a.ad, 262144), bounded(a.pt))};
    }
    case 'open': {
      const token = bounded(a.token, 2097152);
      // Dispatch only; the Rust frame parser verifies the entire canonical frame.
      if (!/^nqc\.[A-Za-z0-9_-]+$/.test(token)) throw new Error('Неверный формат токена');
      const raw = atob(token.slice(4, 8).replace(/-/g, '+').replace(/_/g, '/'));
      const code = raw.charCodeAt(1);
      if (![1, 2, 33, 34].includes(code)) throw new Error('Неизвестная схема токена');
      const size = (code & 15) === 1 ? '128' : '256';
      return n2q['open' + size](key(a.key, size), bounded(a.ad, 262144), token);
    }
    case 'hash': return n2q['hash' + suite](a.fast === true, bounded(a.value));
    case 'index': return n2q['blind_index' + suite](a.fast === true, key(a.key, suite), bounded(a.value));
    case 'test': {
      for (const size of ['128', '256']) {
        const k = n2q['keygen' + size](), nonce = n2q.gen_nonce();
        for (const fast of [false, true]) {
          const token = n2q['seal' + size](fast, k, nonce, 'ctx', 'привет 🌍');
          if (n2q['open' + size](k, 'ctx', token) !== 'привет 🌍') throw new Error('Ошибка round-trip');
          let rejected = false;
          try { n2q['open' + size](k, 'wrong', token); } catch { rejected = true; }
          if (!rejected) throw new Error('Неверный AAD принят');
        }
      }
      return 'PASS: оба размера, оба профиля, UTF-8, отказ при неверном AAD';
    }
    default: throw new Error('Неизвестная операция');
  }
}
self.onmessage = async ({data: {id, op, args}}) => {
  try { await ready; self.postMessage({id, ok: true, result: dispatch(op, args)}); }
  catch (e) { self.postMessage({id, ok: false, error: e instanceof Error ? e.message : 'Ошибка криптооперации'}); }
};
ready.then(() => self.postMessage({ready: true}), () => self.postMessage({ready: false}));
