const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const HOST = "https://bot-hosting.net/api/v1";

function reply(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function cookieMap(request) {
  return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf("="); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}
function setCookie(name, value, maxAge) {
  return name + "=" + encodeURIComponent(value) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}
function clearCookie(name) { return name + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"; }
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function unb64(value) { return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)), c => c.charCodeAt(0)); }
function randomToken(size = 32) { const a = new Uint8Array(size); crypto.getRandomValues(a); return b64(a); }
async function sha(text) { const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)); return b64(d); }
async function mac(text, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text)));
}
function same(a, b) {
  const x = new TextEncoder().encode(String(a)); const y = new TextEncoder().encode(String(b));
  if (x.length !== y.length) return false; let v = 0; for (let i = 0; i < x.length; i++) v |= x[i] ^ y[i]; return v === 0;
}
async function gateOk(request, env) {
  const value = cookieMap(request).bz_gate || ""; const [exp, signature] = value.split(".");
  if (!exp || !signature || Number(exp) < Date.now() / 1000 || !env.APP_SESSION_SECRET) return false;
  return same(signature, await mac(exp, env.APP_SESSION_SECRET));
}
async function gateCookie(env) {
  const exp = String(Math.floor(Date.now() / 1000) + 43200);
  return setCookie("bz_gate", exp + "." + await mac(exp, env.APP_SESSION_SECRET), 43200);
}
async function hashPassword(password) {
  const salt = new Uint8Array(16); crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return b64(salt) + "." + b64(bits);
}
async function verifyPassword(password, stored) {
  const [saltText, digest] = String(stored || "").split(".");
  if (!saltText || !digest) return false;
  const salt = unb64(saltText);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return same(b64(bits), digest);
}
async function encryptSecret(value, env) {
  if (!env.APP_ENCRYPTION_KEY) throw new Error("Configure APP_ENCRYPTION_KEY nos secrets do Cloudflare.");
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env.APP_ENCRYPTION_KEY));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return b64(iv) + "." + b64(data);
}
async function decryptSecret(value, env) {
  const parts = String(value || "").split("."); if (parts.length !== 2 || !env.APP_ENCRYPTION_KEY) return null;
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env.APP_ENCRYPTION_KEY));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(parts[0]) }, key, unb64(parts[1]));
  return new TextDecoder().decode(data);
}
async function createSession(userId, env) {
  const token = randomToken(); const hash = await sha(token);
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)")
    .bind(hash, userId, Date.now() + 30 * 86400000, Date.now()).run();
  return setCookie("bz_session", token, 30 * 86400);
}
async function currentUser(request, env) {
  const token = cookieMap(request).bz_session; if (!token) return null;
  const row = await env.DB.prepare("SELECT users.id,users.name,users.username,users.email,users.role,users.discord_id FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?")
    .bind(await sha(token), Date.now()).first();
  return row || null;
}
function publicUser(user) { return { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role, discordLinked: !!user.discord_id }; }
async function body(request) {
  const len = Number(request.headers.get("content-length") || 0); if (len > 30 * 1024 * 1024) throw new Error("Requisição muito grande.");
  try { return await request.json(); } catch { throw new Error("Corpo JSON inválido."); }
}
async function requireUser(request, env) {
  if (!(await gateOk(request, env))) return { error: reply({ error: "Acesso bloqueado. Informe a chave de entrada." }, 403) };
  const user = await currentUser(request, env);
  if (!user) return { error: reply({ error: "Faça login para continuar." }, 401) };
  return { user };
}
async function hostingKey(userId, env) {
  const row = await env.DB.prepare("SELECT encrypted_key FROM hosting_keys WHERE user_id=?").bind(userId).first();
  if (!row) throw new Error("Conecte sua chave do Bot-Hosting nas Configurações.");
  return decryptSecret(row.encrypted_key, env);
}
async function hostRequest(userId, env, path, method = "GET", data = null) {
  const key = await hostingKey(userId, env);
  const response = await fetch(HOST + path, {
    method, headers: { "authorization": "Bearer " + key, ...(data ? { "content-type": "application/json" } : {}) },
    body: data ? JSON.stringify(data) : undefined
  });
  const text = await response.text(); let parsed; try { parsed = JSON.parse(text); } catch { parsed = { error: text.slice(0, 600) }; }
  if (!response.ok) throw new Error(parsed.error || parsed.message || parsed.detail || ("Bot-Hosting retornou HTTP " + response.status) + (parsed.hint ? " — " + parsed.hint : ""));
  return parsed;
}
async function startDiscord(request, env) {
  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) return reply({ error: "Configure DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET nos secrets do Cloudflare." }, 503);
  const state = randomToken(24);
  await env.DB.prepare("INSERT INTO discord_states (state,expires_at) VALUES (?,?)").bind(state, Date.now() + 600000).run();
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", env.DISCORD_CLIENT_ID); url.searchParams.set("redirect_uri", new URL("/api/auth/discord/callback", request.url).href);
  url.searchParams.set("response_type", "code"); url.searchParams.set("scope", "identify email"); url.searchParams.set("state", state);
  return new Response(null, { status: 302, headers: { location: url.href, "set-cookie": setCookie("bz_oauth_state", state, 600) } });
}
async function discordCallback(request, env) {
  const url = new URL(request.url); const code = url.searchParams.get("code"); const state = url.searchParams.get("state");
  const cookieState = cookieMap(request).bz_oauth_state;
  if (!code || !state || !cookieState || !same(state, cookieState)) return reply({ error: "Validação OAuth inválida. Tente novamente." }, 400);
  const saved = await env.DB.prepare("SELECT state FROM discord_states WHERE state=? AND expires_at>?").bind(state, Date.now()).first();
  await env.DB.prepare("DELETE FROM discord_states WHERE state=?").bind(state).run();
  if (!saved) return reply({ error: "A sessão de autenticação expirou." }, 400);
  const redirectUri = new URL("/api/auth/discord/callback", request.url).href;
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: redirectUri })
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) return reply({ error: "O Discord não autorizou o acesso." }, 401);
  const meRes = await fetch("https://discord.com/api/users/@me", { headers: { authorization: "Bearer " + tokenData.access_token } });
  const me = await meRes.json();
  if (!meRes.ok || !me.id || !me.email || !me.verified) return reply({ error: "O Discord precisa fornecer um e-mail verificado. Entre com e-mail e senha para vincular a conta." }, 400);
  let user = await env.DB.prepare("SELECT * FROM users WHERE discord_id=?").bind(String(me.id)).first();
  if (!user) {
    user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(String(me.email).toLowerCase()).first();
    if (user) await env.DB.prepare("UPDATE users SET discord_id=? WHERE id=?").bind(String(me.id), user.id).run();
    else {
      const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
      const username = (String(me.username || "discord").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 24) || "discord") + "_" + String(me.id).slice(-4);
      const id = randomToken(16); const pass = await hashPassword(randomToken(36)); const name = String(me.global_name || me.username || "Discord User").slice(0, 80);
      await env.DB.prepare("INSERT INTO users (id,name,username,email,password_hash,role,discord_id,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .bind(id, name, username, String(me.email).toLowerCase(), pass, count.total === 0 ? "owner" : "member", String(me.id), Date.now()).run();
      user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
    }
  }
  const session = await createSession(user.id, env);
  const headers = new Headers({ location: new URL("/", request.url).href });
  headers.append("set-cookie", session);
  headers.append("set-cookie", clearCookie("bz_oauth_state"));
  return new Response(null, { status: 302, headers });
}
export async function onRequest(context) {
  const { request, env } = context; const url = new URL(request.url); const path = url.pathname.replace(/^\/api/, "") || "/";
  if (path === "/health" && request.method === "GET") {
    return reply({ ok: true, service: "black-zone-estudio", databaseConfigured: !!env.DB, secretsConfigured: { gate: !!env.APP_GATE_PHRASE, session: !!env.APP_SESSION_SECRET, encryption: !!env.APP_ENCRYPTION_KEY, discordOAuth: !!(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) } });
  }
  if (!env.DB) return reply({ error: "Banco D1 não está vinculado. Crie o banco e adicione o binding DB no Pages." }, 503);
  try {
    if (path === "/gate" && request.method === "POST") {
      const b = await body(request);
      if (!env.APP_GATE_PHRASE || !same(String(b.phrase || ""), env.APP_GATE_PHRASE)) return reply({ error: "Chave de entrada incorreta." }, 401);
      if (!env.APP_SESSION_SECRET) return reply({ error: "APP_SESSION_SECRET não foi configurado." }, 503);
      return reply({ ok: true }, 200, { "set-cookie": await gateCookie(env) });
    }
    if (path === "/me" && request.method === "GET") {
      if (!(await gateOk(request, env))) return reply({ gate: false, user: null });
      const user = await currentUser(request, env); return reply({ gate: true, user: user ? publicUser(user) : null });
    }
    if (path.startsWith("/auth/discord/") && path === "/auth/discord/start" && request.method === "GET") {
      if (!(await gateOk(request, env))) return reply({ error: "Informe a chave de entrada antes do Discord." }, 403);
      return await startDiscord(request, env);
    }
    if (path === "/auth/discord/callback" && request.method === "GET") return await discordCallback(request, env);
    if (path === "/register" && request.method === "POST") {
      if (!(await gateOk(request, env))) return reply({ error: "Acesso bloqueado." }, 403);
      const b = await body(request); const name = String(b.name || "").trim(); const username = String(b.username || "").trim().toLowerCase(); const email = String(b.email || "").trim().toLowerCase(); const password = String(b.password || "");
      if (name.length < 2 || name.length > 80 || !/^[a-z0-9_]{3,24}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) return reply({ error: "Confira nome, usuário, e-mail e senha (mínimo de 10 caracteres)." }, 400);
      const duplicate = await env.DB.prepare("SELECT id FROM users WHERE email=? OR username=?").bind(email, username).first();
      if (duplicate) return reply({ error: "Este e-mail ou nome de usuário já está cadastrado." }, 409);
      const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
      const id = randomToken(16);
      await env.DB.prepare("INSERT INTO users (id,name,username,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(id, name, username, email, await hashPassword(password), count.total === 0 ? "owner" : "member", Date.now()).run();
      const user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
      return reply({ user: publicUser(user) }, 201, { "set-cookie": await createSession(id, env) });
    }
    if (path === "/login" && request.method === "POST") {
      if (!(await gateOk(request, env))) return reply({ error: "Acesso bloqueado." }, 403);
      const b = await body(request); const identity = String(b.identity || "").trim().toLowerCase(); const password = String(b.password || "");
      const user = await env.DB.prepare("SELECT * FROM users WHERE email=? OR username=?").bind(identity, identity).first();
      if (!user || !(await verifyPassword(password, user.password_hash))) return reply({ error: "Usuário ou senha incorretos." }, 401);
      return reply({ user: publicUser(user) }, 200, { "set-cookie": await createSession(user.id, env) });
    }
    if (path === "/logout" && request.method === "POST") {
      const token = cookieMap(request).bz_session; if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(token)).run();
      return reply({ ok: true }, 200, { "set-cookie": clearCookie("bz_session") });
    }
    const auth = await requireUser(request, env); if (auth.error) return auth.error; const user = auth.user;
    if (path === "/settings/hosting" && request.method === "GET") {
      const row = await env.DB.prepare("SELECT updated_at FROM hosting_keys WHERE user_id=?").bind(user.id).first();
      return reply({ connected: !!row, updatedAt: row ? row.updated_at : null });
    }
    if (path === "/settings/hosting" && request.method === "POST") {
      const b = await body(request); const key = String(b.apiKey || "").trim();
      if (!/^bhk_[A-Za-z0-9_-]{1,200}$/.test(key)) return reply({ error: "A chave deve começar com bhk_ e conter apenas letras, números, _ ou -." }, 400);
      const check = await fetch(HOST + "/deployments?brief=true", { headers: { authorization: "Bearer " + key } });
      const data = await check.json(); if (!check.ok) return reply({ error: data.error || "A chave foi recusada ou não tem o escopo deployments:read." }, 400);
      const encrypted = await encryptSecret(key, env);
      await env.DB.prepare("INSERT INTO hosting_keys (user_id,encrypted_key,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET encrypted_key=excluded.encrypted_key,updated_at=excluded.updated_at")
        .bind(user.id, encrypted, Date.now()).run();
      return reply({ ok: true, connected: true });
    }
    if (path === "/bots" && request.method === "GET") {
      const result = await hostRequest(user.id, env, "/deployments?brief=true");
      return reply({ deployments: Array.isArray(result.deployments) ? result.deployments : [] });
    }
    if (path === "/bots" && request.method === "POST") {
      const b = await body(request); const name = String(b.name || "CAOS").trim().slice(0, 48);
      const runtime = b.runtime === "nodejs" ? "nodejs" : "python";
      const result = await hostRequest(user.id, env, "/deployments", "POST", { name, source: "blank", runtime, runtimeVersion: runtime === "python" ? "3.11" : "22" });
      return reply(result, 201);
    }
    const match = path.match(/^\/bots\/([A-Za-z0-9_-]{1,80})(?:\/(logs|power|upload-url|extract|config))?$/);
    if (match) {
      const id = match[1]; const action = match[2] || "";
      if (action === "logs" && request.method === "GET") {
        const result = await hostRequest(user.id, env, "/deployments/" + id + "/diagnose?waitSeconds=0");
        return reply({ state: result.state, resources: result.resources, lines: result.logs || [], hint: result.hint || "" });
      }
      if (action === "power" && request.method === "POST") {
        const b = await body(request); const allowed = ["start", "stop", "restart"];
        if (!allowed.includes(b.action)) return reply({ error: "Ação inválida." }, 400);
        const result = await hostRequest(user.id, env, "/deployments/" + id + "/power", "POST", { action: b.action, waitSeconds: b.action === "stop" ? 0 : 30 });
        return reply(result);
      }
      if (action === "upload-url" && request.method === "POST") {
        const result = await hostRequest(user.id, env, "/deployments/" + id + "/files/upload-url", "POST", { path: "/" });
        return reply(result);
      }
      if (action === "extract" && request.method === "POST") {
        const b = await body(request); const file = String(b.filename || "");
        if (!/^[A-Za-z0-9_. -]{1,100}\.zip$/i.test(file)) return reply({ error: "Nome de arquivo ZIP inválido." }, 400);
        const result = await hostRequest(user.id, env, "/deployments/" + id + "/files/decompress", "POST", { file, removeArchive: true });
        return reply(result);
      }
      if (action === "config" && request.method === "POST") {
        const b = await body(request); const token = String(b.discordToken || "").trim();
        if (token.length < 40 || token.length > 200) return reply({ error: "Token de bot Discord inválido." }, 400);
        const allowed = ["music","tickets","attendance","team","goals","warnings","recruitment","logs"];
        const modules = {}; for (const key of allowed) modules[key] = !!(b.modules && b.modules[key]);
        await hostRequest(user.id, env, "/deployments/" + id + "/env", "POST", { key: "DISCORD_TOKEN", value: token, secret: true });
        await hostRequest(user.id, env, "/deployments/" + id + "/env", "POST", { key: "CAOS_MODULES", value: JSON.stringify(modules), secret: false });
        return reply({ ok: true, restartRequired: true, note: "Segredos e seleções foram salvos. Reinicie o bot para aplicar as variáveis de ambiente." });
      }
    }
    return reply({ error: "Rota não encontrada." }, 404);
  } catch (error) {
    return reply({ error: error && error.message ? error.message : "Erro interno." }, 500);
  }
}