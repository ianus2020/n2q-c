const $ = id => document.getElementById(id);
let worker, epoch = 0, nextId = 0, available = false, busy = false, lastToken = '', lastAAD = '';
const pending = new Map();
let startupTimer;
const START_TIMEOUT_MS=15000, CALL_TIMEOUT_MS=30000;
function rejectPending(message) {
  pending.forEach(p=>{clearTimeout(p.timer);p.reject(new Error(message));});pending.clear();
}
function failWorker(message) {
  clearTimeout(startupTimer);available=false;busy=false;
  if(worker){worker.onmessage=null;worker.onerror=null;worker.onmessageerror=null;worker.terminate();}
  rejectPending(message);$('engine').textContent=message+' Нажмите «Очистить всё» для перезапуска.';controls();
}
function controls() {
  document.querySelectorAll('[data-crypto]').forEach(b => { b.disabled = !available || busy; });
  $('btn-copy').disabled = busy || !lastToken;
  ['suite', 'profile', 'key', 'aad', 'pt', 'aad2', 'ct', 'hval'].forEach(id => { $(id).disabled = busy; });
}
function start() {
  const generation = ++epoch;
  available = false; controls();
  try {worker = new Worker('./crypto-worker.js', {type: 'module'});}
  catch {failWorker('Worker недоступен.');return;}
  startupTimer=setTimeout(()=>{if(generation===epoch)failWorker('Превышено время загрузки WASM.');},START_TIMEOUT_MS);
  worker.onmessage = ({data}) => {
    if (generation !== epoch) return;
    if(!data || typeof data!=='object'){failWorker('Некорректный ответ worker.');return;}
    if ('ready' in data) { clearTimeout(startupTimer);if(data.ready!==true){failWorker('Не удалось проверить и загрузить JS/WASM.');return;}available=true;$('engine').textContent='WASM готов';controls();return; }
    const request = pending.get(data.id);
    if (!request) return;
    clearTimeout(request.timer);pending.delete(data.id);
    if (data.ok) request.resolve(data.result); else request.reject(new Error(data.error));
  };
  worker.onerror = () => {if(generation===epoch)failWorker('Ошибка WASM.');};
  worker.onmessageerror = () => {if(generation===epoch)failWorker('Не удалось прочитать ответ worker.');};
}
function call(op, args) {
  if (!available) return Promise.reject(new Error('WASM недоступен'));
  return new Promise((resolve,reject)=>{
    const id=++nextId;
    const timer=setTimeout(()=>failWorker('Превышено время операции.'),CALL_TIMEOUT_MS);
    pending.set(id,{resolve,reject,timer});
    try {worker.postMessage({id,op,args});}catch {failWorker('Не удалось отправить запрос worker.');}
  });
}
function invalidate() { $('nonce').value='';lastToken = ''; lastAAD = ''; $('btn-copy').disabled = true; $('out-ct').textContent = ''; }
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
bind('btn-key', 'engine', 'key', params, result => {
  invalidate(); $('key').value = result;
  $('out-pt').textContent = ''; $('out-h').textContent = '';
  $('engine').textContent = 'Новый ключ создан. Сохраните его самостоятельно.';
});
bind('btn-enc', 'out-ct', 'seal', () => ({...params(), ad: $('aad').value, pt: $('pt').value}), result => {
  lastToken = result.token; lastAAD = $('aad').value; $('nonce').value = result.nonce; $('out-ct').textContent = result.token;
});
bind('btn-dec', 'out-pt', 'open', () => ({...params(), ad: $('aad2').value, token: $('ct').value}));
bind('btn-hash', 'out-h', 'hash', () => ({...params(), value: $('hval').value}));
bind('btn-bi', 'out-h', 'index', () => ({...params(), value: $('hval').value}));
bind('btn-test', 'out-test', 'test', params);
$('btn-copy').onclick = () => { if (!lastToken) return; $('ct').value = lastToken; $('aad2').value = lastAAD; $('out-pt').textContent = ''; };
['suite', 'profile', 'key', 'aad', 'pt'].forEach(id => $(id).addEventListener('input', invalidate));
$('btn-show').onclick = () => { const show = $('key').type === 'password'; $('key').type = show ? 'text' : 'password'; $('btn-show').textContent = show ? 'Скрыть ключ' : 'Показать ключ'; $('btn-show').setAttribute('aria-pressed', String(show)); };
$('btn-clear').onclick = () => {
  ++epoch;clearTimeout(startupTimer);if(worker)worker.terminate();rejectPending('Очищено');busy=false;
  ['key', 'nonce', 'aad', 'pt', 'aad2', 'ct', 'hval'].forEach(id => { $(id).value = ''; });
  ['out-ct', 'out-pt', 'out-h', 'out-test'].forEach(id => { $(id).textContent = ''; });
  $('key').type = 'password'; $('btn-show').textContent = 'Показать ключ'; $('btn-show').setAttribute('aria-pressed', 'false');
  invalidate(); $('engine').textContent = 'Перезапуск WASM…'; start();
};
['key','suite','aad2','ct'].forEach(id=>$(id).addEventListener('input',()=>{$('out-pt').textContent='';}));
['hval','key','suite','profile'].forEach(id=>$(id).addEventListener('input',()=>{$('out-h').textContent='';}));
start();
