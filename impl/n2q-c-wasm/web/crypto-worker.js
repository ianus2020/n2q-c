// Load exactly the public JS/WASM bytes described by the build manifest.
// This detects an incomplete/mixed deployment, not a compromised origin.
let n2q;
async function fetchBounded(path,max) {
  const response=await fetch(path,{cache:'no-store'});
  if(!response.ok || !response.body) throw new Error('Не удалось получить файлы сборки');
  const reader=response.body.getReader(), chunks=[];let size=0;
  try {
    while(true) {
      const {value,done}=await reader.read();if(done)break;
      size+=value.byteLength;if(size>max) throw new Error('Файл сборки превышает лимит');
      chunks.push(value);
    }
  } finally {await reader.cancel();}
  const bytes=new Uint8Array(size);let offset=0;
  for(const part of chunks){bytes.set(part,offset);offset+=part.length;}
  return bytes;
}
async function verifiedAsset(path,expected) {
  if(!expected || !Number.isSafeInteger(expected.bytes) || expected.bytes<1 ||
     expected.bytes>4194304 || !/^[a-f0-9]{64}$/.test(expected.sha256)) throw new Error('Неверный манифест сборки');
  const bytes=await fetchBounded(path,expected.bytes);
  const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
  if(bytes.length!==expected.bytes || digest!==expected.sha256) throw new Error('Несогласованный комплект JS/WASM');
  return bytes;
}
async function bootstrap() {
  const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await fetchBounded('./pkg/build-manifest.json',65536)));
  if(manifest.version!==1)throw new Error('Неизвестная версия сборки');
  const [js,wasm]=await Promise.all([
    verifiedAsset('./pkg/n2q_c_wasm.js',manifest.js),
    verifiedAsset('./pkg/n2q_c_wasm_bg.wasm',manifest.wasm)
  ]);
  const url=URL.createObjectURL(new Blob([js],{type:'text/javascript'}));
  try {
    n2q=await import(url);
    await n2q.default({module_or_path:wasm});
  } finally {URL.revokeObjectURL(url);}
}
const ready=bootstrap();
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
      const k = key(a.key, suite), ad = bounded(a.ad,262144), pt = bounded(a.pt);
      const nonce = n2q.gen_nonce();
      return {nonce, token: n2q['seal' + suite](a.fast === true, k, nonce, ad, pt)};
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
let running=false;
self.onmessage = async ({data}) => {
  const {id,op,args}=data || {};
  if(!Number.isSafeInteger(id) || id<1 || typeof op!=='string' || !args || typeof args!=='object')return;
  if(running){self.postMessage({id,ok:false,error:'Операция уже выполняется'});return;}
  running=true;
  try { await ready; self.postMessage({id, ok: true, result: dispatch(op, args)}); }
  catch (e) { self.postMessage({id, ok: false, error: e instanceof Error ? e.message : 'Ошибка криптооперации'}); }
  finally {running=false;}
};
ready.then(() => self.postMessage({ready: true}), () => self.postMessage({ready: false}));
