const $ = id => document.getElementById(id);
let worker, epoch = 0, nextId = 0, available = false, busy = false, lastToken = '', lastAAD = '';
const pending = new Map();
function controls() {
  document.querySelectorAll('[data-crypto]').forEach(b => { b.disabled = !available || busy; });
  $('btn-copy').disabled = busy || !lastToken;
  ['suite', 'profile', 'key', 'aad', 'pt', 'aad2', 'ct', 'hval'].forEach(id => { $(id).disabled = busy; });
}
function start() {
  const generation = ++epoch;
  available = false; controls();
  worker = new Worker('./crypto-worker.js', {type: 'module'});
  worker.onmessage = ({data}) => {
    if (generation !== epoch) return;
    if ('ready' in data) { available = data.ready; $('engine').textContent = available ? 'WASM готов' : 'Не удалось загрузить WASM'; controls(); return; }
    const request = pending.get(data.id);
    if (!request) return;
    pending.delete(data.id);
    if (data.ok) request.resolve(data.result); else request.reject(new Error(data.error));
  };
  worker.onerror = () => {
    if (generation !== epoch) return;
    available = false; $('engine').textContent = 'Ошибка WASM. Нажмите «Очистить всё» для перезапуска.';
    pending.forEach(p => p.reject(new Error('Worker недоступен'))); pending.clear(); controls();
  };
}
function call(op, args) {
  if (!available) return Promise.reject(new Error('WASM недоступен'));
  return new Promise((resolve, reject) => { const id = ++nextId; pending.set(id, {resolve, reject}); worker.postMessage({id, op, args}); });
}
function invalidate() { lastToken = ''; lastAAD = ''; $('btn-copy').disabled = true; $('out-ct').textContent = ''; }
function bind(id, output, op, args, success) {
  $(id).onclick = async () => {
    const generation = epoch;
    busy = true; if (op === 'seal') invalidate(); controls();
    $(output).textContent = 'Выполняется…';
    try {
      const result = await call(op, args());
      if (generation !== epoch) return;
      if (success) success(result); else $(output).textContent = result;
    } catch (e) { if (generation === epoch) $(output).textContent = 'Ошибка: ' + e.message; }
    finally { if (generation === epoch) { busy = false; controls(); } }
  };
}
const params = () => ({suite: $('suite').value, fast: $('profile').value === 'fast', key: $('key').value});
bind('btn-key', 'engine', 'key', params, result => { invalidate(); $('key').value = result; $('engine').textContent = 'Новый ключ создан. Сохраните его самостоятельно.'; });
bind('btn-enc', 'out-ct', 'seal', () => ({...params(), ad: $('aad').value, pt: $('pt').value}), result => {
  lastToken = result.token; lastAAD = $('aad').value; $('nonce').value = result.nonce; $('out-ct').textContent = result.token;
});
bind('btn-dec', 'out-pt', 'open', () => ({...params(), ad: $('aad2').value, token: $('ct').value}));
bind('btn-hash', 'out-h', 'hash', () => ({...params(), value: $('hval').value}));
bind('btn-bi', 'out-h', 'index', () => ({...params(), value: $('hval').value}));
bind('btn-test', 'out-test', 'test', params);
$('btn-copy').onclick = () => { if (!lastToken) return; $('ct').value = lastToken; $('aad2').value = lastAAD; };
['suite', 'profile', 'key', 'aad', 'pt'].forEach(id => $(id).addEventListener('input', invalidate));
$('btn-show').onclick = () => { const show = $('key').type === 'password'; $('key').type = show ? 'text' : 'password'; $('btn-show').textContent = show ? 'Скрыть ключ' : 'Показать ключ'; $('btn-show').setAttribute('aria-pressed', String(show)); };
$('btn-clear').onclick = () => {
  ++epoch; worker.terminate(); pending.forEach(p => p.reject(new Error('Очищено'))); pending.clear(); busy = false;
  ['key', 'nonce', 'aad', 'pt', 'aad2', 'ct', 'hval'].forEach(id => { $(id).value = ''; });
  ['out-ct', 'out-pt', 'out-h', 'out-test'].forEach(id => { $(id).textContent = ''; });
  $('key').type = 'password'; $('btn-show').textContent = 'Показать ключ'; $('btn-show').setAttribute('aria-pressed', 'false');
  invalidate(); $('engine').textContent = 'Перезапуск WASM…'; start();
};
start();
