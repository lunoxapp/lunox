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
const FIREBASE_API_KEY_DEFAULT = 'AIzaSyCQL-Jk4WHAoECmdz0povAcZilOvvtQPR4';
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

async function lookupUser(env, idToken) {
  try {
    const key = env.FIREBASE_API_KEY || FIREBASE_API_KEY_DEFAULT;
    const r = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(key), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken })
    });
    if (!r.ok) return null;
    const data = await r.json();
    const u = data && data.users && data.users[0];
    return u ? { uid: u.localId, email: u.email || '' } : null;
  } catch (e) { return null; }
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
