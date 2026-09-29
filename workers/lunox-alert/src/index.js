// Worker lunox-alert. Переменные: TG_ALERT_BOT_TOKEN, TG_ALERT_CHAT_ID, FIREBASE_API_KEY (опц.).
// Перенесено с netlify/functions/tg-alert.js.
//
// ВАЖНО про rate-limit в памяти (hits Map): как и в Netlify Functions, это
// best-effort — изолят Worker'а может быть переиспользован для следующих
// запросов, а может быть создан заново в любой момент (например, при
// деплое или по решению рантайма). Не гарантия, а просто снижение спама.

const ALLOWED_ORIGINS = [
  'https://lunoxapp.online',
  'https://www.lunoxapp.online',
  'https://lunoxapp.netlify.app'
];
function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT_USER = 30;
const LIMIT_ANON = 5;
const hits = new Map();

function tooMany(key, limit) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < WINDOW_MS);
  if (arr.length >= limit) { hits.set(key, arr); return true; }
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 2000) hits.clear();
  return false;
}
const reply = (obj, status, CORS) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS } });

// Проверка Firebase idToken ЛОКАЛЬНО (RS256 по публичным сертификатам Google), как в lunox-upload.
// Раньше проверка шла через identitytoolkit accounts:lookup с Web API key: если ключ ограничен по HTTP-referrer/API
// (или лимитирован), Google отвечает 403 на запрос из Worker'а (у него нет Referer) -> Worker считал токен невалидным.
// Локальная проверка от ключа не зависит и не делает лишний сетевой запрос на каждый вызов.
const FIREBASE_PROJECT_ID = 'lunoh-5453a';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
let _certMem = null;
async function getGoogleCerts(force) {
  const now = Date.now();
  if (!force && _certMem && _certMem.exp > now) return _certMem.certs;
  const r = await fetch(GOOGLE_CERTS_URL);
  if (!r.ok) throw new Error('certs_http_' + r.status);
  const certs = await r.json();
  const m = /max-age=(\d+)/.exec(r.headers.get('Cache-Control') || '');
  _certMem = { certs, exp: now + Math.min(m ? +m[1] : 3600, 21600) * 1000 };
  return certs;
}
function b64uBytes(s) {
  const b = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
function b64uJson(s) { return JSON.parse(new TextDecoder().decode(b64uBytes(s))); }
function spkiFromCert(der) {
  let pos = 0;
  const readLen = () => { let l = der[pos++]; if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = (l << 8) | der[pos++]; } return l; };
  const skip = () => { pos++; const l = readLen(); pos += l; }; // NB: не `pos += readLen()` — левая часть читается ДО вызова
  if (der[pos++] !== 0x30) throw new Error('cert'); readLen();
  if (der[pos++] !== 0x30) throw new Error('tbs'); readLen();
  if (der[pos] === 0xa0) skip();
  skip(); skip(); skip(); skip(); skip(); // serial, sigAlg, issuer, validity, subject
  const start = pos;
  if (der[pos++] !== 0x30) throw new Error('spki');
  const len = readLen();
  return der.slice(start, pos + len);
}
async function certToKey(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64); const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return crypto.subtle.importKey('spki', spkiFromCert(der), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
}
// -> { ok: true, uid, email } | { ok: false, reason }
async function verifyToken(idToken) {
  try {
    const parts = String(idToken || '').split('.');
    if (parts.length !== 3) return { ok: false, reason: 'bad_format' };
    const header = b64uJson(parts[0]), p = b64uJson(parts[1]);
    if (header.alg !== 'RS256' || !header.kid) return { ok: false, reason: 'bad_header' };
    const now = Math.floor(Date.now() / 1000);
    if (typeof p.exp !== 'number' || p.exp <= now) return { ok: false, reason: 'expired' };
    if (typeof p.iat !== 'number' || p.iat > now + 300) return { ok: false, reason: 'bad_iat' };
    if (p.aud !== FIREBASE_PROJECT_ID) return { ok: false, reason: 'bad_aud' };
    if (p.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT_ID) return { ok: false, reason: 'bad_iss' };
    if (!p.sub || typeof p.sub !== 'string') return { ok: false, reason: 'no_sub' };
    let certs = await getGoogleCerts(false);
    if (!certs[header.kid]) certs = await getGoogleCerts(true);
    if (!certs[header.kid]) return { ok: false, reason: 'unknown_kid' };
    const key = await certToKey(certs[header.kid]);
    const okSig = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, b64uBytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
    if (!okSig) return { ok: false, reason: 'bad_signature' };
    return { ok: true, uid: p.sub, email: p.email || '' };
  } catch (e) {
    console.error('verifyToken error:', e && e.message);
    return { ok: false, reason: 'verify_error' };
  }
}
async function verifyIdToken(request) {
  const m = /^Bearer\s+(.+)$/i.exec(request.headers.get('Authorization') || '');
  if (!m) return { ok: false, reason: 'no_token' };
  return verifyToken(m[1].trim());
}
async function lookupUser(env, idToken) {
  const r = await verifyToken(idToken);
  return r.ok ? { uid: r.uid, email: r.email } : null;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const CORS = corsHeaders(origin);
    if (request.method === 'OPTIONS') {
      if (!ALLOWED_ORIGINS.includes(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: CORS });
    }
    if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: 'Forbidden origin' }, 403, CORS);
    if (request.method !== 'POST') return reply({ error: 'Только POST' }, 405, CORS);

    const token = env.TG_ALERT_BOT_TOKEN;
    const chatId = env.TG_ALERT_CHAT_ID;
    if (!token || !chatId) return reply({ error: 'Функция не настроена (TG_ALERT_BOT_TOKEN / TG_ALERT_CHAT_ID)' }, 500, CORS);

    let body;
    try { body = await request.json(); } catch (e) { return reply({ error: 'Некорректный JSON' }, 400, CORS); }
    const text = String(body.text || '').slice(0, 1500).trim();
    if (!text) return reply({ error: 'Пустой текст' }, 400, CORS);

    let sender = null;
    if (body.idToken && typeof body.idToken === 'string') sender = await lookupUser(env, body.idToken);

    let footer;
    if (sender) {
      if (tooMany('u:' + sender.uid, LIMIT_USER)) return reply({ error: 'Слишком часто' }, 429, CORS);
      footer = `\n\n[от: ${sender.email || sender.uid}]`;
    } else {
      if (body.kind !== 'bruteforce') return reply({ error: 'Нужен вход в аккаунт' }, 401, CORS);
      const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || 'unknown';
      if (tooMany('a:' + ip, LIMIT_ANON)) return reply({ error: 'Слишком часто' }, 429, CORS);
      footer = '\n\n[от: аноним, без входа]';
    }

    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: text + footer })
      });
      if (!r.ok) {
        const t = await r.text().catch(() => '');
        console.error('Telegram отклонил сообщение', r.status, t);
        return reply({ error: 'Telegram HTTP ' + r.status }, 502, CORS);
      }
      return reply({ ok: true }, 200, CORS);
    } catch (e) {
      console.error('tg-alert ошибка:', e);
      return reply({ error: 'Не удалось связаться с Telegram' }, 502, CORS);
    }
  }
};
