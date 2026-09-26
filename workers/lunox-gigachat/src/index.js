// Worker lunox-gigachat. Переменные: GIGACHAT_AUTH_KEY, (опц.) GIGACHAT_SCOPE,
// GIGACHAT_MODEL, GIGACHAT_IMAGE_MODEL.
//
// ⚠️ ВАЖНОЕ ОГРАНИЧЕНИЕ, ПРОЧТИ ПЕРЕД ДЕПЛОЕМ ⚠️
// Cloudflare Workers Runtime физически не даёт подключить кастомный
// корневой сертификат для исходящего fetch() — там нет ни аналога
// https.Agent{ca}, ни настройки доверенных CA через параметр cf у fetch()
// (cf.tlsClientAuth относится к mTLS для ВХОДЯЩИХ запросов к самому Worker,
// а не к исходящим запросам от Worker наружу). Раньше в netlify/functions/
// gigachat.js это решалось через https.Agent с зашитым корневым
// сертификатом Минцифры (Russian Trusted Root CA) — на Cloudflare такой
// возможности нет вообще, ни через официальный, ни через недокументированный
// API.
//
// Поэтому запрос к https://api.giga.chat (сертификат которого подписан
// именно этим корневым CA) из Cloudflare Workers либо:
//   (а) сработает "как есть", если Cloudflare edge уже доверяет цепочке
//       (некоторые edge-провайдеры используют системный доверенный список
//       ОС/Mozilla, куда Russian Trusted Root CA НЕ входит) — то есть,
//       скорее всего, НЕ сработает и вернёт ошибку TLS/fetch failed;
//   (б) либо сработает, если сертификат api.giga.chat на самом деле выпущен
//       публичным CA (это стоит проверить отдельно — если Сбер для
//       api.giga.chat использует не тот же self-signed CA, что был для
//       ngw.devices.sberbank.ru, то и проблемы может не быть).
//
// Я не могу это протестировать из этой среды (нет доступа к сети/GigaChat).
// Код ниже написан как обычный порт на fetch() — это единственный способ
// сделать исходящий запрос в Workers. Если после деплоя увидишь ошибку
// "TLS handshake failed" / "unable to verify the first certificate" —
// это точно она, обходов на стороне Workers нет. Единственные варианты:
//   1. Оставить эту функцию на Netlify (она особенная именно из-за CA —
//      остальные две спокойно переезжают на Cloudflare), а на Cloudflare
//      держать только gemini/alert/upload.
//   2. Поставить между Worker'ом и GigaChat промежуточный сервер (VPS/
//      Cloud Function на платформе, которая даёт Node https.Agent), и
//      обращаться туда.
// Заменять серверный сертификат на что-то вида rejectUnauthorized:false
// нельзя — это не костыль "работает то же самое", а выключение проверки
// подлинности сервера, на которое я не подставляю значения по умолчанию.

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
const json = (obj, status, CORS) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS } });

const ALLOWED_MODELS = ['GigaChat-2', 'GigaChat-2-Pro', 'GigaChat-2-Max', 'GigaChat-3-Ultra'];

async function request(url, options, body) {
  const res = await fetch(url, { ...options, body });
  const text = await res.text();
  console.log(`[GigaChat] ${options.method} ${url} -> HTTP ${res.status}`);
  if (res.status !== 200) console.error(`[GigaChat] Тело ответа с ошибкой (${url}):`, text);
  return { statusCode: res.status, body: text };
}
async function requestBinary(url, options) {
  const res = await fetch(url, options);
  const buf = new Uint8Array(await res.arrayBuffer());
  console.log(`[GigaChat] ${options.method} ${url} -> HTTP ${res.status} (${buf.length} байт)`);
  if (res.status !== 200) console.error(`[GigaChat] Ошибка (${url}):`, new TextDecoder().decode(buf).slice(0, 500));
  return { statusCode: res.status, body: buf };
}

let cachedToken = null;
async function getAccessToken(env) {
  if (cachedToken && cachedToken.expires_at > Date.now() + 5000) return cachedToken.access_token;
  const AUTH_KEY = env.GIGACHAT_AUTH_KEY;
  const SCOPE = env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS';
  if (!AUTH_KEY) throw new Error('Не задана переменная окружения GIGACHAT_AUTH_KEY');
  const body = 'scope=' + encodeURIComponent(SCOPE);
  const tokenUrl = 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth';
  const res = await request(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'RqUID': crypto.randomUUID(),
      'Authorization': `Basic ${AUTH_KEY}`
    }
  }, body);
  if (res.statusCode !== 200) throw new Error(`Не удалось получить токен GigaChat (${tokenUrl}, HTTP ${res.statusCode}): ${res.body}`);
  const data = JSON.parse(res.body);
  cachedToken = { access_token: data.access_token, expires_at: data.expires_at * 1000 };
  return cachedToken.access_token;
}

async function uploadFileToStorage(env, base64Data, mimeType, filename) {
  const token = await getAccessToken(env);
  const bin = atob(base64Data);
  const fileBuffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) fileBuffer[i] = bin.charCodeAt(i);
  const MAX_IMAGE_BYTES = 15 * 1024 * 1024;
  if (fileBuffer.length > MAX_IMAGE_BYTES) throw new Error('Фото слишком большое для отправки в GigaChat (максимум 15 МБ)');

  const boundary = `LunoxBoundary${crypto.randomUUID().replace(/-/g, '')}`;
  const safeFilename = (filename || 'photo.jpg').replace(/["\r\n]/g, '_');
  const enc = new TextEncoder();
  const head = enc.encode(
    `--${boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\ngeneral\r\n` +
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeFilename}"\r\nContent-Type: ${mimeType}\r\n\r\n`
  );
  const tail = enc.encode(`\r\n--${boundary}--\r\n`);
  const bodyBuf = new Uint8Array(head.length + fileBuffer.length + tail.length);
  bodyBuf.set(head, 0);
  bodyBuf.set(fileBuffer, head.length);
  bodyBuf.set(tail, head.length + fileBuffer.length);

  const fileUrl = 'https://api.giga.chat/v1/files';
  const res = await request(fileUrl, {
    method: 'POST',
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  }, bodyBuf);
  if (res.statusCode !== 200) throw new Error(`Не удалось загрузить фото в GigaChat (${fileUrl}, HTTP ${res.statusCode}): ${res.body}`);
  const data = JSON.parse(res.body);
  if (!data || !data.id) throw new Error('GigaChat не вернул идентификатор загруженного файла');
  return data.id;
}

async function generateImage(env, prompt, model) {
  const token = await getAccessToken(env);
  const MODEL = env.GIGACHAT_IMAGE_MODEL || model || 'GigaChat-2-Max';
  const payload = JSON.stringify({
    model: MODEL,
    messages: [
      { role: 'system', content: 'Ты — художник внутри мессенджера Lunox. На любой запрос пользователя рисуй именно то, что он описал, вызывая функцию генерации изображения.' },
      { role: 'user', content: prompt }
    ],
    function_call: { name: 'text2image' }
  });
  const chatUrl = 'https://api.giga.chat/v1/chat/completions';
  const res = await request(chatUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token}` }
  }, payload);
  if (res.statusCode !== 200) throw new Error(`GigaChat вернул ошибку при генерации изображения (${chatUrl}, HTTP ${res.statusCode}): ${res.body}`);

  const data = JSON.parse(res.body);
  const content = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!content) throw new Error('GigaChat вернул пустой ответ на запрос изображения');

  const match = content.match(/<img\s+src="([0-9a-f-]{36})"/i);
  if (!match) {
    const err = new Error(`GigaChat не сгенерировал изображение: ${content}`);
    err.modelCantDraw = true;
    err.modelReply = content;
    throw err;
  }
  const fileId = match[1];
  const fileUrl = `https://api.giga.chat/v1/files/${fileId}/content`;
  const fileRes = await requestBinary(fileUrl, {
    method: 'GET',
    headers: { 'Accept': 'application/jpg', 'Authorization': `Bearer ${token}` }
  });
  if (fileRes.statusCode !== 200) throw new Error(`Не удалось скачать сгенерированное изображение (${fileUrl}, HTTP ${fileRes.statusCode})`);

  let binary = '';
  for (let i = 0; i < fileRes.body.length; i++) binary += String.fromCharCode(fileRes.body[i]);
  return {
    imageBase64: btoa(binary),
    mimeType: 'image/jpeg',
    caption: content.replace(/<img[^>]*>/i, '').trim()
  };
}

export default {
  async fetch(request_, env) {
    const origin = request_.headers.get('Origin');
    const CORS = corsHeaders(origin);
    if (request_.method === 'OPTIONS') {
      if (!ALLOWED_ORIGINS.includes(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: CORS });
    }
    if (!ALLOWED_ORIGINS.includes(origin)) return json({ error: 'Forbidden origin' }, 403, CORS);
    if (request_.method !== 'POST') return json({ error: 'Method not allowed' }, 405, CORS);

    let body;
    try { body = await request_.json(); }
    catch { return json({ error: 'Некорректный JSON в теле запроса' }, 400, CORS); }

    if (body.mode === 'image') {
      const prompt = String(body.prompt || '').trim();
      const model = body.model && ALLOWED_MODELS.includes(body.model) ? body.model : null;
      if (!prompt) return json({ error: 'Поле prompt обязательно для генерации изображения' }, 400, CORS);
      try {
        const result = await generateImage(env, prompt, model);
        return json({ image: `data:${result.mimeType};base64,${result.imageBase64}`, caption: result.caption }, 200, CORS);
      } catch (err) {
        if (err.modelCantDraw) {
          return json({ modelCantDraw: true, model: model || 'GigaChat-2-Max', modelReply: err.modelReply || '' }, 200, CORS);
        }
        return json({ error: err.message || 'Внутренняя ошибка при генерации изображения' }, 500, CORS);
      }
    }

    const { messages, model, attachment } = body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return json({ error: 'Поле messages обязательно и должно быть непустым массивом' }, 400, CORS);
    }
    if (model && !ALLOWED_MODELS.includes(model)) return json({ error: `Неизвестная модель: ${model}` }, 400, CORS);

    try {
      const token = await getAccessToken(env);
      const MODEL = model || env.GIGACHAT_MODEL || 'GigaChat-2';

      let messagesToSend = messages;
      if (attachment && attachment.data && attachment.mimeType) {
        const fileId = await uploadFileToStorage(env, attachment.data, attachment.mimeType, attachment.filename || 'photo.jpg');
        const lastUserIdx = messagesToSend.length - 1;
        messagesToSend = messagesToSend.map((m, i) =>
          i === lastUserIdx && m.role === 'user' ? { ...m, attachments: [fileId] } : m
        );
      }

      const payload = JSON.stringify({ model: MODEL, messages: messagesToSend });
      const chatUrl = 'https://api.giga.chat/v1/chat/completions';
      const res = await request(chatUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token}` }
      }, payload);

      if (res.statusCode !== 200) return json({ error: `GigaChat вернул ошибку (${chatUrl}, HTTP ${res.statusCode}): ${res.body}` }, 502, CORS);

      const data = JSON.parse(res.body);
      const replyText = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
      if (!replyText) return json({ error: 'GigaChat вернул пустой ответ' }, 502, CORS);
      return json({ reply: replyText }, 200, CORS);
    } catch (err) {
      return json({ error: err.message || 'Внутренняя ошибка функции' }, 500, CORS);
    }
  }
};
