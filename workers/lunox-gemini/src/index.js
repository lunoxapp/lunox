// Worker lunox-gemini. Переменные: GEMINI_API_KEYS (или GEMINI_API_KEY).
// Перенесено с netlify/functions/gemini.js — та функция уже использовала
// fetch(), поэтому логика 1:1, изменена только обвязка запроса/ответа.

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

const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';
const ALLOWED_GEMINI_MODELS = ['gemini-3.6-flash', 'gemini-3.8-flash', 'gemini-3.1-flash-lite'];
const GEMINI_IMAGE_MODEL = 'gemini-3.1-flash-image';
const GEMINI_SYSTEM_PROMPT = 'Ты — ИИ-помощник в мессенджере Lunox. Отвечай дружелюбно, кратко, на русском.';
const GEMINI_GENERATION_CONFIG = { maxOutputTokens: 2048, thinkingConfig: { thinkingLevel: 'low' } };

function toGeminiContents(messages) {
  return messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: String(m.content || '') }]
    }));
}
function extractTextAndImage(candidateParts) {
  let text = '';
  let imageBase64 = null;
  let mimeType = 'image/png';
  for (const part of candidateParts || []) {
    const inline = part.inlineData || part.inline_data;
    if (inline && inline.data) {
      imageBase64 = inline.data;
      mimeType = inline.mimeType || inline.mime_type || mimeType;
    } else if (typeof part.text === 'string') {
      text += part.text;
    }
  }
  return { text, imageBase64, mimeType };
}

const RETRYABLE_HTTP_STATUSES = new Set([503, 429]);
const RETRY_DELAYS_MS = [800, 2000];
const KEY_ROTATE_STATUSES = new Set([429, 401, 403]);
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function callGeminiApi(env, model, payload) {
  const GEMINI_API_KEYS = (env.GEMINI_API_KEYS || env.GEMINI_API_KEY || '')
    .split(',').map((k) => k.trim()).filter(Boolean);
  if (GEMINI_API_KEYS.length === 0) {
    throw new Error('Не задана ни одна переменная окружения с ключом Gemini (GEMINI_API_KEYS или GEMINI_API_KEY)');
  }
  const url = `${GEMINI_BASE}/${model}:generateContent`;
  let lastError = null;
  for (let keyIndex = 0; keyIndex < GEMINI_API_KEYS.length; keyIndex++) {
    const apiKey = GEMINI_API_KEYS[keyIndex];
    for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify(payload)
      });
      const bodyText = await res.text();
      console.log(`[Gemini] POST ${url} -> HTTP ${res.status}`);
      if (res.ok) {
        try { return JSON.parse(bodyText); }
        catch { throw new Error(`Gemini вернул не-JSON ответ (${url}): ${bodyText.slice(0, 300)}`); }
      }
      console.error(`[Gemini] Тело ответа с ошибкой (${url}):`, bodyText);
      lastError = new Error(`Gemini вернул ошибку (${url}, HTTP ${res.status}): ${bodyText}`);
      lastError.httpStatus = res.status;
      if (!RETRYABLE_HTTP_STATUSES.has(res.status) || attempt === RETRY_DELAYS_MS.length) break;
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
    if (KEY_ROTATE_STATUSES.has(lastError.httpStatus) && keyIndex < GEMINI_API_KEYS.length - 1) {
      console.warn(`[Gemini] ключ #${keyIndex + 1} вернул HTTP ${lastError.httpStatus} — пробуем следующий ключ`);
      continue;
    }
    break;
  }
  if (lastError.httpStatus === 503) {
    lastError.overloaded = true;
    lastError.message = `Gemini сейчас перегружен (HTTP 503) — временная проблема на стороне Google, попробуйте через минуту-две.`;
  } else if (lastError.httpStatus === 429) {
    lastError.message = `Gemini упёрся в лимит запросов (HTTP 429) — подождите сброса квоты или добавьте резервный ключ в GEMINI_API_KEYS.`;
  }
  throw lastError;
}

async function generateGeminiImage(env, prompt) {
  const data = await callGeminiApi(env, GEMINI_IMAGE_MODEL, {
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
  });
  const parts = data && data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts;
  const { text, imageBase64, mimeType } = extractTextAndImage(parts);
  if (!imageBase64) {
    const err = new Error(`Gemini не сгенерировал изображение: ${text || '(пустой ответ)'}`);
    err.modelCantDraw = true;
    err.modelReply = text;
    throw err;
  }
  return { imageBase64, mimeType, caption: text.trim() };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const CORS = corsHeaders(origin);
    if (request.method === 'OPTIONS') {
      if (!ALLOWED_ORIGINS.includes(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: CORS });
    }
    if (!ALLOWED_ORIGINS.includes(origin)) return json({ error: 'Forbidden origin' }, 403, CORS);
    if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, CORS);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Некорректный JSON в теле запроса' }, 400, CORS); }

    if (body.mode === 'image') {
      const prompt = String(body.prompt || '').trim();
      if (!prompt) return json({ error: 'Поле prompt обязательно для генерации изображения' }, 400, CORS);
      try {
        const result = await generateGeminiImage(env, prompt);
        return json({ image: `data:${result.mimeType};base64,${result.imageBase64}`, caption: result.caption }, 200, CORS);
      } catch (err) {
        if (err.modelCantDraw) {
          return json({ modelCantDraw: true, model: 'gemini-3.6-flash', modelReply: err.modelReply || '' }, 200, CORS);
        }
        return json({ error: err.message || 'Внутренняя ошибка при генерации изображения' }, 500, CORS);
      }
    }

    const { messages, model, attachment } = body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return json({ error: 'Поле messages обязательно и должно быть непустым массивом' }, 400, CORS);
    }
    const MODEL = ALLOWED_GEMINI_MODELS.includes(model) ? model : 'gemini-3.6-flash';

    try {
      const contents = toGeminiContents(messages);
      if (attachment && attachment.data && attachment.mimeType) {
        const last = contents[contents.length - 1];
        if (last && last.role === 'user') {
          last.parts.push({ inline_data: { mime_type: attachment.mimeType, data: attachment.data } });
        }
      }
      const requestPayload = {
        system_instruction: { parts: [{ text: GEMINI_SYSTEM_PROMPT }] },
        contents,
        generationConfig: GEMINI_GENERATION_CONFIG
      };

      let data;
      try {
        data = await callGeminiApi(env, MODEL, requestPayload);
      } catch (err) {
        const fallbackModel = ALLOWED_GEMINI_MODELS.find((m) => m !== MODEL);
        if (err.overloaded && fallbackModel) {
          console.warn(`[Gemini] ${MODEL} перегружена (503), пробуем резервную модель ${fallbackModel}`);
          data = await callGeminiApi(env, fallbackModel, requestPayload);
        } else {
          throw err;
        }
      }

      const parts = data && data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts;
      const { text } = extractTextAndImage(parts);
      if (!text) {
        const finishReason = data && data.candidates && data.candidates[0] && data.candidates[0].finishReason;
        const message = finishReason === 'MAX_TOKENS'
          ? 'Gemini не уложилась в лимит токенов и не успела дать видимый ответ — попробуйте задать вопрос короче или повторить запрос'
          : `Gemini вернул пустой ответ${finishReason ? ` (finishReason: ${finishReason})` : ''}`;
        return json({ error: message }, 502, CORS);
      }
      return json({ reply: text }, 200, CORS);
    } catch (err) {
      return json({ error: err.message || 'Внутренняя ошибка функции' }, 500, CORS);
    }
  }
};
