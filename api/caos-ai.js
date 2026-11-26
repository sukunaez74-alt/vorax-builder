import { neon } from "@neondatabase/serverless";

const CHAT_MODEL = "nvidia/nemotron-3.5-lightning-free";
const IMAGE_MODEL = "bfl/flux-3-image-klein";
const DISCORD_ME = "https://discord.com/api/v10/users/@me";
const GATEWAY = "https://ai-gateway.vercel.sh/v1";

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(body));
}

function safeText(value, max) {
  return String(value ?? "").replace(/\u0000/g, "").trim().slice(0, max);
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw || raw.length > 18000) throw new Error("Corpo vazio ou muito grande.");
  return JSON.parse(raw);
}

async function verifyBot(req, sql) {
  const header = String(req.headers.authorization || "");
  const token = header.replace(/^Bot\s+/i, "").trim();
  if (token.length < 30 || token.length > 512 || /\s/.test(token)) return null;

  let response;
  try {
    response = await fetch(DISCORD_ME, {
      headers: { authorization: "Bot " + token, accept: "application/json" },
      signal: AbortSignal.timeout(10000)
    });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  const identity = await response.json().catch(() => ({}));
  if (!identity?.id || identity.bot !== true) return null;

  const rows = await sql.query(
    "SELECT bot_id FROM admin_caos_settings WHERE id='main' AND bot_id=$1 AND package_uploaded_at IS NOT NULL AND hosting_deployment_id IS NOT NULL LIMIT 1",
    [String(identity.id)]
  );
  return rows?.length ? String(identity.id) : null;
}

async function useQuota(sql, guildId, userId, kind) {
  await sql.query(
    "CREATE TABLE IF NOT EXISTS caos_ai_usage (id BIGSERIAL PRIMARY KEY, guild_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, created_at BIGINT NOT NULL)"
  );
  const now = Date.now();
  const minuteAgo = now - 60_000;
  const recent = await sql.query(
    "SELECT COUNT(*)::int AS total FROM caos_ai_usage WHERE user_id=$1 AND kind=$2 AND created_at>$3",
    [userId, kind, minuteAgo]
  );
  const perMinute = Number(recent?.[0]?.total || 0);
  if (perMinute >= (kind === "image" ? 1 : 8)) return { ok: false, message: "Você atingiu o limite temporário. Aguarde um minuto e tente novamente." };

  const dayStart = new Date(now);
  dayStart.setUTCHours(0, 0, 0, 0);
  if (kind === "image") {
    const day = await sql.query(
      "SELECT COUNT(*)::int AS total FROM caos_ai_usage WHERE guild_id=$1 AND kind='image' AND created_at>=$2",
      [guildId, dayStart.getTime()]
    );
    const month = await sql.query(
      "SELECT COUNT(*)::int AS total FROM caos_ai_usage WHERE guild_id=$1 AND kind='image' AND created_at>=$2",
      [guildId, Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), 1)]
    );
    if (Number(day?.[0]?.total || 0) >= 5) return { ok: false, message: "O limite gratuito de imagens deste servidor hoje foi atingido (5 por dia). Tente novamente amanhã." };
    if (Number(month?.[0]?.total || 0) >= 100) return { ok: false, message: "A cota mensal de imagens deste servidor foi atingida. Ela será liberada no próximo mês." };
  } else {
    const day = await sql.query(
      "SELECT COUNT(*)::int AS total FROM caos_ai_usage WHERE guild_id=$1 AND kind='chat' AND created_at>=$2",
      [guildId, dayStart.getTime()]
    );
    if (Number(day?.[0]?.total || 0) >= 500) return { ok: false, message: "O limite diário de perguntas deste servidor foi atingido. Tente novamente amanhã." };
  }

  await sql.query(
    "INSERT INTO caos_ai_usage (guild_id,user_id,kind,created_at) VALUES ($1,$2,$3,$4)",
    [guildId, userId, kind, now]
  );
  // Keeps the usage table small without affecting current quotas.
  await sql.query("DELETE FROM caos_ai_usage WHERE created_at<$1", [now - 45 * 86400_000]);
  return { ok: true };
}

async function gatewayRequest(path, payload) {
  const key = process.env.AI_GATEWAY_API_KEY;
  if (!key) throw Object.assign(new Error("A chave privada da IA não está configurada no servidor."), { status: 503 });
  let response;
  try {
    response = await fetch(GATEWAY + path, {
      method: "POST",
      headers: { authorization: "Bearer " + key, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(70000)
    });
  } catch {
    throw Object.assign(new Error("O serviço de IA não respondeu a tempo. Tente novamente."), { status: 502 });
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = safeText(data?.error?.message || data?.message || "O serviço de IA recusou a solicitação.", 400);
    const status = response.status === 402 ? 402 : response.status === 429 ? 429 : 502;
    throw Object.assign(new Error(message), { status });
  }
  return data;
}

async function chat(req, res, sql, body) {
  const guildId = safeText(body.guildId, 24);
  const userId = safeText(body.userId, 24);
  const prompt = safeText(body.prompt, 1400);
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(userId) || !prompt) {
    return send(res, 400, { error: "Pergunta ou identificador inválido." });
  }
  const quota = await useQuota(sql, guildId, userId, "chat");
  if (!quota.ok) return send(res, 429, { error: quota.message });

  const history = Array.isArray(body.history) ? body.history.slice(-8).map(item => ({
    role: item?.role === "assistant" ? "assistant" : "user",
    content: safeText(item?.content, 900)
  })).filter(item => item.content) : [];
  const messages = [
    {
      role: "system",
      content: "Você é a IA oficial do servidor Discord CAOS. Responda sempre em português brasileiro, de forma respeitosa, clara e objetiva. Ajude com dúvidas gerais, explique termos de RP e regras apenas quando tiver certeza. Não invente decisões, vagas, aprovações, punições, cargos ou informações internas do servidor. Encaminhe dúvidas administrativas específicas à equipe. Se a pergunta for sobre recrutamento, REC, inscrição ou formulário, diga que o canal de recrutamento é o local correto; as regras automáticas de recrutamento são tratadas pelo próprio bot. Não peça senhas, tokens, cookies ou dados pessoais. Respostas curtas, adequadas ao Discord."
    },
    ...history,
    { role: "user", content: prompt }
  ];
  const data = await gatewayRequest("/chat/completions", {
    model: CHAT_MODEL,
    messages,
    temperature: 0.55,
    max_tokens: 450
  });
  const answer = data?.choices?.[0]?.message?.content;
  const text = Array.isArray(answer) ? answer.map(part => part?.text || "").join("") : String(answer || "");
  if (!text.trim()) return send(res, 502, { error: "A IA não retornou uma resposta. Tente novamente." });
  return send(res, 200, { ok: true, text: text.trim().slice(0, 1800), model: CHAT_MODEL });
}

async function image(req, res, sql, body) {
  const guildId = safeText(body.guildId, 24);
  const userId = safeText(body.userId, 24);
  const prompt = safeText(body.prompt, 1000);
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(userId) || prompt.length < 3) {
    return send(res, 400, { error: "Descreva a imagem com pelo menos três caracteres." });
  }
  const quota = await useQuota(sql, guildId, userId, "image");
  if (!quota.ok) return send(res, 429, { error: quota.message });

  const data = await gatewayRequest("/images/generations", {
    model: IMAGE_MODEL,
    prompt,
    size: "768x768",
    n: 1,
    response_format: "b64_json"
  });
  const item = data?.data?.[0] || data?.images?.[0] || {};
  let imageBase64 = item.b64_json || item.base64 || null;
  let mimeType = "image/png";
  if (!imageBase64 && item.url) {
    const imageResponse = await fetch(item.url, { signal: AbortSignal.timeout(30000) });
    if (!imageResponse.ok) return send(res, 502, { error: "O serviço gerou a imagem, mas não foi possível baixá-la." });
    const bytes = Buffer.from(await imageResponse.arrayBuffer());
    if (bytes.length > 7 * 1024 * 1024) return send(res, 413, { error: "A imagem gerada ficou grande demais para enviar ao Discord." });
    mimeType = imageResponse.headers.get("content-type") || mimeType;
    imageBase64 = bytes.toString("base64");
  }
  if (!imageBase64) return send(res, 502, { error: "O serviço não retornou a imagem em um formato compatível." });
  const bytes = Buffer.from(imageBase64, "base64");
  if (!bytes.length || bytes.length > 7 * 1024 * 1024) return send(res, 413, { error: "A imagem gerada ficou grande demais para enviar ao Discord." });
  if (mimeType === "image/jpeg") mimeType = "image/jpeg";
  else mimeType = "image/png";
  return send(res, 200, { ok: true, imageBase64: bytes.toString("base64"), mimeType, model: IMAGE_MODEL });
}

export default async function handler(req, res) {
  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method !== "POST") return send(res, 405, { error: "Método não permitido." });
  if (!process.env.DATABASE_URL || !process.env.AI_GATEWAY_API_KEY) {
    return send(res, 503, { error: "A conexão segura da IA ainda não está configurada no servidor." });
  }
  try {
    const body = await readBody(req);
    const sql = neon(process.env.DATABASE_URL);
    const botId = await verifyBot(req, sql);
    if (!botId) return send(res, 401, { error: "Este bot não está autorizado a usar a IA do CAOS. Confira a configuração no ADM." });
    const kind = body.action === "image" ? "image" : body.action === "chat" ? "chat" : "";
    if (!kind) return send(res, 400, { error: "Ação de IA inválida." });
    if (kind === "chat") return await chat(req, res, sql, body);
    return await image(req, res, sql, body);
  } catch (error) {
    const status = Number(error?.status || 500);
    const allowed = [400, 402, 429, 502, 503];
    return send(res, allowed.includes(status) ? status : 500, {
      error: safeText(error?.message || "Falha interna no serviço de IA.", 400)
    });
  }
}
