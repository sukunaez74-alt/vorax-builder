import { neon } from "@neondatabase/serverless";

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
  if (!env.APP_GATE_PHRASE) return true;
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
async function validateDiscordBotToken(token) {
  let response;
  try {
    response = await fetch("https://discord.com/api/v10/users/@me", {
      method: "GET",
      headers: { authorization: "Bot " + token, accept: "application/json" },
      signal: AbortSignal.timeout(12000)
    });
  } catch (error) {
    console.error("Discord token validation network failure:", error?.name || "NetworkError");
    return { valid: false, unavailable: true, reason: "network" };
  }
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 || response.status === 403) {
    return { valid: false, unavailable: false, reason: "invalid" };
  }
  if (response.status === 429) {
    return { valid: false, unavailable: true, reason: "rate_limited" };
  }
  if (response.status >= 500 || !response.ok) {
    console.error("Discord token validation returned HTTP", response.status);
    return { valid: false, unavailable: true, reason: "discord_http_" + response.status };
  }
  if (!data.id || data.bot !== true) {
    return { valid: false, unavailable: false, reason: "not_a_bot" };
  }
  return {
    valid: true,
    unavailable: false,
    botId: String(data.id),
    botName: data.username ? String(data.username) : null
  };
}
async function encryptSecret(value, env) {
  if (!env.APP_ENCRYPTION_KEY) throw new Error("A criptografia do painel ainda não foi configurada no Vercel.");
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

async function hostingClient(env, redirectUri) {
  let row = await env.DB.prepare("SELECT client_id,redirect_uri FROM hosting_oauth_apps WHERE id='main'").first();
  if (row && row.redirect_uri === redirectUri) return row.client_id;
  const response = await fetch("https://bot-hosting.net/api/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      client_name: "ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      application_type: "web"
    }),
    signal: AbortSignal.timeout(15000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.client_id) {
    const message = data.error_description || data.error || data.message || ("Bot-Hosting não registrou o aplicativo OAuth (HTTP " + response.status + ").");
    throw new Error(message);
  }
  await env.DB.prepare(
    "INSERT INTO hosting_oauth_apps (id,client_id,redirect_uri,updated_at) VALUES ('main',?,?,?) ON CONFLICT (id) DO UPDATE SET client_id=EXCLUDED.client_id,redirect_uri=EXCLUDED.redirect_uri,updated_at=EXCLUDED.updated_at"
  ).bind(String(data.client_id), redirectUri, Date.now()).run();
  return String(data.client_id);
}
async function hostingConnectUrl(request, user, env) {
  const redirectUri = new URL("/api/hosting/callback", request.url).href;
  const clientId = await hostingClient(env, redirectUri);
  const verifier = randomToken(48);
  const challenge = b64(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const state = randomToken(24);
  await env.DB.prepare("INSERT INTO hosting_oauth_states (state,user_id,code_verifier,expires_at) VALUES (?,?,?,?)")
    .bind(state, user.id, verifier, Date.now() + 600000).run();
  const scopes = [
    "deployments:read", "deployments:power", "deployments:write",
    "files:write", "env:write"
  ].join(" ");
  const url = new URL("https://bot-hosting.net/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  return url.href;
}
async function hostingCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (url.searchParams.get("error")) {
    return new Response(null, { status: 302, headers: { location: new URL("/?hosting=cancelled", request.url).href } });
  }
  if (!code || !state) return reply({ error: "Retorno OAuth incompleto." }, 400);
  const saved = await env.DB.prepare(
    "SELECT user_id,code_verifier FROM hosting_oauth_states WHERE state=? AND expires_at>?"
  ).bind(state, Date.now()).first();
  await env.DB.prepare("DELETE FROM hosting_oauth_states WHERE state=?").bind(state).run();
  if (!saved) return new Response(null, { status: 302, headers: { location: new URL("/?hosting=expired", request.url).href } });
  const client = await env.DB.prepare("SELECT client_id FROM hosting_oauth_apps WHERE id='main'").first();
  if (!client?.client_id) return reply({ error: "Aplicativo OAuth não encontrado. Reconecte a hospedagem." }, 503);
  const redirectUri = new URL("/api/hosting/callback", request.url).href;
  const tokenResponse = await fetch("https://bot-hosting.net/api/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: client.client_id,
      code_verifier: saved.code_verifier
    }),
    signal: AbortSignal.timeout(15000)
  });
  const tokenData = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !tokenData.access_token || !tokenData.refresh_token) {
    const note = tokenData.error_description || tokenData.error || "O Bot-Hosting não aceitou a autorização.";
    return new Response(null, { status: 302, headers: { location: new URL("/?hosting=error", request.url).href } });
  }
  const accessEnc = await encryptSecret(String(tokenData.access_token), env);
  const refreshEnc = await encryptSecret(String(tokenData.refresh_token), env);
  await env.DB.prepare(
    "INSERT INTO hosting_connections (user_id,access_token_enc,refresh_token_enc,expires_at,scope,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT (user_id) DO UPDATE SET access_token_enc=EXCLUDED.access_token_enc,refresh_token_enc=EXCLUDED.refresh_token_enc,expires_at=EXCLUDED.expires_at,scope=EXCLUDED.scope,updated_at=EXCLUDED.updated_at"
  ).bind(saved.user_id, accessEnc, refreshEnc, Date.now() + Number(tokenData.expires_in || 604800) * 1000, String(tokenData.scope || ""), Date.now()).run();
  return new Response(null, { status: 302, headers: { location: new URL("/?hosting=connected", request.url).href } });
}
async function hostingAccessToken(userId, env, forceRefresh = false) {
  const connection = await env.DB.prepare(
    "SELECT access_token_enc,refresh_token_enc,expires_at,scope FROM hosting_connections WHERE user_id=?"
  ).bind(userId).first();
  if (!connection) throw new Error("Conecte sua conta Bot-Hosting para controlar este bot.");
  if (!forceRefresh && Number(connection.expires_at) > Date.now() + 120000) {
    return decryptSecret(connection.access_token_enc, env);
  }
  const client = await env.DB.prepare("SELECT client_id FROM hosting_oauth_apps WHERE id='main'").first();
  const refreshToken = await decryptSecret(connection.refresh_token_enc, env);
  if (!client?.client_id || !refreshToken) throw new Error("A conexão do Bot-Hosting expirou. Conecte a conta novamente.");
  const response = await fetch("https://bot-hosting.net/api/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: client.client_id }),
    signal: AbortSignal.timeout(15000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token || !data.refresh_token) {
    await env.DB.prepare("DELETE FROM hosting_connections WHERE user_id=?").bind(userId).run();
    throw new Error("A autorização do Bot-Hosting expirou ou foi revogada. Conecte a conta novamente.");
  }
  const accessEnc = await encryptSecret(String(data.access_token), env);
  const refreshEnc = await encryptSecret(String(data.refresh_token), env);
  await env.DB.prepare(
    "UPDATE hosting_connections SET access_token_enc=?,refresh_token_enc=?,expires_at=?,scope=?,updated_at=? WHERE user_id=?"
  ).bind(accessEnc, refreshEnc, Date.now() + Number(data.expires_in || 604800) * 1000, String(data.scope || connection.scope || ""), Date.now(), userId).run();
  return String(data.access_token);
}
async function hostRequest(userId, env, path, method = "GET", data = null) {
  let token = await hostingAccessToken(userId, env);
  const send = async (bearer) => fetch(HOST + path, {
    method,
    headers: { authorization: "Bearer " + bearer, ...(data !== null ? { "content-type": "application/json" } : {}) },
    body: data !== null ? JSON.stringify(data) : undefined,
    signal: AbortSignal.timeout(60000)
  });
  let response = await send(token);
  if (response.status === 401) {
    token = await hostingAccessToken(userId, env, true);
    response = await send(token);
  }
  const raw = await response.text();
  let parsed;
  try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { error: raw.slice(0, 600) }; }
  if (!response.ok) {
    const reason = parsed.error || parsed.message || parsed.detail || ("Bot-Hosting retornou HTTP " + response.status);
    throw new Error(reason + (parsed.hint ? " — " + parsed.hint : ""));
  }
  return parsed;
}
const CAOS_MAIN_PY = "";
const CAOS_REQUIREMENTS = "discord.py[voice]==2.7.1\ndavey==0.1.7\nPyNaCl>=1.6.0,<1.7.0\npython-dotenv>=1.0,<2.0\nyt-dlp[default]>=2026.10.26\ndeno>=2.3.0\nimageio-ffmpeg>=0.8.1\n";
function runnerTemplate() {
  return "import os, signal, subprocess, sys, time\nfrom datetime import datetime\nfrom zoneinfo import ZoneInfo\n\nTZ = os.getenv('TZ', 'America/Bahia')\nENABLED = os.getenv('CAOS_SCHEDULE_ENABLED', '0') == '1'\nSTART = os.getenv('CAOS_SCHEDULE_START', '00:00')\nEND = os.getenv('CAOS_SCHEDULE_END', '23:59')\nchild = None\nstop_requested = False\n\ndef in_window():\n    if not ENABLED: return True\n    now = datetime.now(ZoneInfo(TZ)).strftime('%H:%M')\n    if START < END: return START <= now < END\n    return now >= START or now < END\n\ndef stop_child():\n    global child\n    if child and child.poll() is None:\n        print('AGENDAMENTO: encerrando o bot fora da janela configurada.', flush=True)\n        child.terminate()\n        try: child.wait(timeout=20)\n        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)\n    child = None\n\ndef shutdown(_sig, _frame):\n    global stop_requested\n    stop_requested = True\n\nsignal.signal(signal.SIGTERM, shutdown)\nsignal.signal(signal.SIGINT, shutdown)\nprint('BLACK ZONE supervisor iniciado; fuso=' + TZ + '; agenda=' + (START + '-' + END if ENABLED else 'sempre online'), flush=True)\ntry:\n    while not stop_requested:\n        desired = in_window()\n        if desired and (child is None or child.poll() is not None):\n            if child is not None: print('CAOS encerrou com código ' + str(child.returncode) + '; tentando novamente.', flush=True)\n            print('AGENDAMENTO: iniciando o CAOS.', flush=True)\n            child = subprocess.Popen([sys.executable, '-u', 'main.py'])\n        elif not desired and child is not None:\n            stop_child()\n        time.sleep(10)\nfinally:\n    stop_child()\n    print('BLACK ZONE supervisor encerrado.', flush=True)\n";
}



function isInsideSchedule(start, end, timezone) {
  try {
    const parts = new Intl.DateTimeFormat("en-GB", { timeZone: timezone || "America/Bahia", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date());
    const now = parts.find(x => x.type === "hour").value + ":" + parts.find(x => x.type === "minute").value;
    return start < end ? now >= start && now < end : now >= start || now < end;
  } catch { return false; }
}

async function setHostEnv(userId, env, deploymentId, key, value, secret = false) {
  return hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/env", "POST", {
    key, value: String(value ?? ""), secret
  });
}
async function ensureBotDeployment(bot, userId, env) {
  if (bot.runtime !== "python") {
    throw new Error("A integração automática atual prepara o modelo CAOS em Python. Para Node.js, envie um ZIP com o código do seu bot.");
  }
  if (!CAOS_MAIN_PY || CAOS_MAIN_PY.length < 10000) {
    throw new Error("O pacote CAOS não foi incluído nesta publicação do servidor. Atualize o painel e tente novamente.");
  }
  if (!bot.discord_token_enc) throw new Error("Salve primeiro o Bot Token Discord deste projeto.");
  const token = await decryptSecret(bot.discord_token_enc, env);
  if (!token) throw new Error("Não consegui abrir o token protegido deste projeto. Salve novamente o token do Discord.");
  const identity = await validateDiscordBotToken(token);
  if (!identity.valid) throw new Error("O Discord não aceitou o token salvo. Abra Configurar token e módulos e atualize a credencial.");
  const modules = typeof bot.modules === "string" ? JSON.parse(bot.modules || "{}") : (bot.modules || {});
  let deploymentId = bot.hosting_deployment_id || null;
  if (!deploymentId) {
    const safeName = ("black-zone-" + String(bot.name || "caos").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) + "-" + String(bot.id).slice(0, 5)).replace(/-+/g, "-");
    const created = await hostRequest(userId, env, "/deployments", "POST", {
      name: safeName,
      source: "blank",
      runtime: "python",
      runtimeVersion: "3.11"
    });
    const deployment = created.deployment || created;
    deploymentId = String(deployment.id || "");
    if (!deploymentId) throw new Error("O Bot-Hosting respondeu sem o identificador da implantação.");
    await env.DB.prepare("UPDATE bots SET hosting_deployment_id=?,discord_bot_id=?,discord_bot_name=?,state='draft',updated_at=? WHERE id=? AND user_id=?")
      .bind(deploymentId, identity.botId, identity.botName || null, Date.now(), bot.id, userId).run();
  }
  const writeResult = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/writeMany", "POST", {
    files: [
      { path: "/main.py", content: CAOS_MAIN_PY, mode: "overwrite" },
      { path: "/requirements.txt", content: CAOS_REQUIREMENTS, mode: "overwrite" },
      { path: "/runner.py", content: runnerTemplate(), mode: "overwrite" }
    ]
  });
  if (Array.isArray(writeResult.failed) && writeResult.failed.length) {
    throw new Error("Não consegui enviar todos os arquivos do CAOS: " + writeResult.failed.map(x => x.path + " — " + x.error).join("; "));
  }
  const start = bot.schedule_start || "00:00";
  const end = bot.schedule_end || "23:59";
  await setHostEnv(userId, env, deploymentId, "DISCORD_TOKEN", token, true);
  await setHostEnv(userId, env, deploymentId, "CAOS_MODULES", JSON.stringify(modules), false);
  await setHostEnv(userId, env, deploymentId, "CAOS_SCHEDULE_ENABLED", bot.schedule_enabled ? "1" : "0", false);
  await setHostEnv(userId, env, deploymentId, "CAOS_SCHEDULE_START", start, false);
  await setHostEnv(userId, env, deploymentId, "CAOS_SCHEDULE_END", end, false);
  await setHostEnv(userId, env, deploymentId, "TZ", bot.schedule_timezone || "America/Bahia", false);
  await setHostEnv(userId, env, deploymentId, "GUILD_ID", bot.guild_id || "", false);
  await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
    runtime: "python",
    runtimeVersion: "3.11",
    entryFile: "runner.py",
    startCommand: "python -m pip install -r requirements.txt && exec python -u runner.py"
  });
  await env.DB.prepare("UPDATE bots SET discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?")
    .bind(identity.botId, identity.botName || null, Date.now(), bot.id, userId).run();
  return { deploymentId, botId: identity.botId, botName: identity.botName || null };
}
async function getOwnedBot(id, userId, env) {
  return env.DB.prepare(
    "SELECT id,name,runtime,state,modules,discord_token_enc,discord_bot_id,discord_bot_name,hosting_deployment_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE id=? AND user_id=?"
  ).bind(id, userId).first();
}
function validClock(value) { return typeof value === "string" && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value); }

async function startDiscord(request, env) {
  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) return reply({ error: "Configure DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET nas variáveis seguras do Vercel." }, 503);
  const state = randomToken(24);
  await env.DB.prepare("INSERT INTO discord_states (state,expires_at) VALUES (?,?)").bind(state, Date.now() + 600000).run();
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", env.DISCORD_CLIENT_ID); url.searchParams.set("redirect_uri", new URL("/api/auth/discord/callback", request.url).href);
  url.searchParams.set("response_type", "code"); url.searchParams.set("scope", "identify email"); url.searchParams.set("state", state);
  return new Response(null, { status: 302, headers: { location: url.href, "set-cookie": setCookie("bz_oauth_state", state, 600) } });
}

async function claimOwner(userId, env) {
  const claimed = await env.DB.prepare("UPDATE app_state SET owner_user_id=? WHERE id='main' AND owner_user_id IS NULL RETURNING owner_user_id")
    .bind(userId).first();
  if (claimed) {
    await env.DB.prepare("UPDATE users SET role='owner' WHERE id=?").bind(userId).run();
    return "owner";
  }
  return "member";
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
      const username = (String(me.username || "discord").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 24) || "discord") + "_" + String(me.id).slice(-4);
      const id = randomToken(16); const pass = await hashPassword(randomToken(36)); const name = String(me.global_name || me.username || "Discord User").slice(0, 80);
      await env.DB.prepare("INSERT INTO users (id,name,username,email,password_hash,role,discord_id,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .bind(id, name, username, String(me.email).toLowerCase(), pass, "member", String(me.id), Date.now()).run();
      await claimOwner(id, env);
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
    let databaseQuery = false;
    if (env.DB) {
      const probe = await env.DB.prepare("SELECT ?::text AS check_value")
        .bind("black-zone-estudio").first();
      databaseQuery = probe?.check_value === "black-zone-estudio";
    }
    return reply({
      ok: true,
      service: "black-zone-estudio",
      databaseConfigured: !!env.DB,
      databaseQuery,
      secretsConfigured: {
        gate: !!env.APP_GATE_PHRASE,
        session: !!env.APP_SESSION_SECRET,
        encryption: !!env.APP_ENCRYPTION_KEY,
        discordOAuth: !!(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET)
      }
    });
  }

    if (path === "/hosting/callback" && request.method === "GET") return await hostingCallback(request, env);
  if (!env.DB) return reply({ error: "Banco de dados indisponível. Conecte o Neon ao projeto Vercel para habilitar cadastro e login." }, 503);
  try {
    if (path === "/gate" && request.method === "POST") {
      const b = await body(request);
      if (env.APP_GATE_PHRASE && !same(String(b.phrase || ""), env.APP_GATE_PHRASE)) return reply({ error: "Chave de entrada incorreta." }, 401);
      if (!env.APP_SESSION_SECRET) return reply({ error: "Segredo de sessão ainda não configurado." }, 503);
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
      const id = randomToken(16);
      await env.DB.prepare("INSERT INTO users (id,name,username,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(id, name, username, email, await hashPassword(password), "member", Date.now()).run();
      await claimOwner(id, env);
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

    if (path === "/hosting/connect" && request.method === "GET") {
      try {
        return reply({ authorizationUrl: await hostingConnectUrl(request, user, env) });
      } catch (error) {
        return reply({ error: error.message || "Não foi possível preparar a autorização do Bot-Hosting." }, 502);
      }
    }
    if (path === "/hosting/status" && request.method === "GET") {
      const row = await env.DB.prepare("SELECT expires_at,scope FROM hosting_connections WHERE user_id=?").bind(user.id).first();
      return reply({ connected: !!row, expiresAt: row?.expires_at || null, scope: row?.scope || "" });
    }
    if (path === "/hosting/disconnect" && request.method === "POST") {
      await env.DB.prepare("DELETE FROM hosting_connections WHERE user_id=?").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }
    if (path === "/bot-config" && request.method === "POST") {
      const b = await body(request);
      const id = String(b.botId || "").trim();
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) {
        return reply({ error: "Projeto inválido. Atualize a lista e tente novamente." }, 400);
      }

      const ownedBot = await env.DB.prepare(
        "SELECT id,discord_token_enc,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
      ).bind(id, user.id).first();
      if (!ownedBot) return reply({ error: "Projeto não encontrado nesta conta. Atualize a lista de bots." }, 404);

      const discordToken = String(b.discordToken || "").trim();
      let identity = null;
      let tokenUpdated = false;
      if (discordToken) {
        if (discordToken.length < 30 || discordToken.length > 256 || /\s/.test(discordToken)) {
          return reply({ error: "O Bot Token parece incompleto. Copie o token inteiro, sem espaços." }, 400);
        }
        identity = await validateDiscordBotToken(discordToken);
        if (identity.unavailable) {
          const message = identity.reason === "rate_limited"
            ? "O Discord limitou temporariamente as verificações. Aguarde um minuto e tente novamente."
            : "Não foi possível alcançar o Discord para validar o token. Verifique a conexão e tente novamente.";
          return reply({ error: message, code: identity.reason || "discord_unavailable" }, 503);
        }
        if (!identity.valid) {
          const message = identity.reason === "not_a_bot"
            ? "A credencial não pertence a um usuário Bot. Use o Bot Token da seção Bot no Discord Developer Portal."
            : "O Discord recusou o token. Gere ou copie novamente o Bot Token na seção Bot do Discord Developer Portal; não use Client Secret, Client ID ou Public Key.";
          return reply({ error: message, code: identity.reason || "invalid_discord_token" }, 400);
        }
        const encryptedToken = await encryptSecret(discordToken, env);
        const savedToken = await env.DB.prepare(
          "UPDATE bots SET discord_token_enc=?,discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=? RETURNING id,discord_token_enc"
        ).bind(encryptedToken, identity.botId, identity.botName || null, Date.now(), id, user.id).first();
        if (!savedToken?.discord_token_enc) {
          return reply({ error: "O Discord validou o token, mas o banco não confirmou a gravação. Nenhuma alteração foi marcada como salva." }, 500);
        }
        const checkToken = await decryptSecret(savedToken.discord_token_enc, env);
        if (!checkToken || !same(checkToken, discordToken)) {
          return reply({ error: "A gravação do token não passou na verificação de integridade. Tente salvar novamente." }, 500);
        }
        tokenUpdated = true;
      } else if (!ownedBot.discord_token_enc) {
        return reply({ error: "Informe o Bot Token do Discord para este projeto." }, 400);
      } else {
        const existingToken = await decryptSecret(ownedBot.discord_token_enc, env);
        if (!existingToken) {
          return reply({ error: "O token salvo não pode ser aberto com a chave de criptografia atual. Informe novamente o Bot Token para substituir a credencial." }, 409);
        }
      }

      const allowed = ["music","tickets","attendance","team","goals","warnings","recruitment","logs"];
      const modules = {};
      for (const key of allowed) modules[key] = !!(b.modules && b.modules[key]);
      await env.DB.prepare(
        "UPDATE bots SET modules=?::jsonb,updated_at=? WHERE id=? AND user_id=? RETURNING id"
      ).bind(JSON.stringify(modules), Date.now(), id, user.id).first();

      const confirmed = await env.DB.prepare(
        "SELECT id,(discord_token_enc IS NOT NULL) AS has_token,modules,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
      ).bind(id, user.id).first();
      if (!confirmed?.has_token) {
        return reply({ error: "As alterações foram enviadas, mas a confirmação final não encontrou um token salvo. Tente novamente." }, 500);
      }
      const savedModules = typeof confirmed.modules === "string" ? JSON.parse(confirmed.modules || "{}") : (confirmed.modules || {});
      return reply({
        ok: true,
        tokenStored: true,
        hasDiscordToken: true,
        tokenUpdated,
        modules: savedModules,
        discordBotId: confirmed.discord_bot_id || null,
        discordBotName: confirmed.discord_bot_name || null,
        message: tokenUpdated
          ? "Token validado no Discord, criptografado, gravado e confirmado no banco de dados."
          : "Alterações salvas. O token anterior foi mantido e confirmado no banco de dados."
      });
    }
    if (path === "/bots" && request.method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT id,name,runtime,state,modules,created_at,updated_at,(discord_token_enc IS NOT NULL) AS has_discord_token,discord_bot_id,discord_bot_name,hosting_deployment_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE user_id=? ORDER BY created_at DESC"
      ).bind(user.id).all();
      return reply({ deployments: rows.map(row => ({
        ...row,
        modules: typeof row.modules === "string" ? JSON.parse(row.modules) : row.modules,
        hasDiscordToken: !!row.has_discord_token,
        discordBotId: row.discord_bot_id || null,
        discordBotName: row.discord_bot_name || null,
        hostingDeploymentId: row.hosting_deployment_id || null,
        scheduleEnabled: !!row.schedule_enabled,
        scheduleStart: row.schedule_start || "00:00",
        scheduleEnd: row.schedule_end || "23:59",
        scheduleTimezone: row.schedule_timezone || "America/Bahia",
        guildId: row.guild_id || "",
        executionAvailable: !!row.hosting_deployment_id
      })) });
    }
    if (path === "/bots" && request.method === "POST") {
      const b = await body(request);
      const name = String(b.name || "Novo bot").trim().slice(0, 48);
      const runtime = b.runtime === "nodejs" ? "nodejs" : "python";
      if (name.length < 2) return reply({ error: "Digite um nome com pelo menos 2 caracteres." }, 400);
      const discordToken = String(b.discordToken || "").trim();
      if (discordToken.length < 30 || discordToken.length > 256 || /\s/.test(discordToken)) {
        return reply({ error: "Informe um token de bot Discord válido, sem espaços, com pelo menos 30 caracteres." }, 400);
      }
      const verifiedToken = await validateDiscordBotToken(discordToken);
      if (verifiedToken.unavailable) {
        const message = verifiedToken.reason === "rate_limited"
          ? "O Discord limitou temporariamente as verificações. Aguarde um minuto e tente novamente."
          : "Não foi possível alcançar o Discord para validar o token. Verifique a conexão e tente novamente.";
        return reply({ error: message, code: verifiedToken.reason || "discord_unavailable" }, 503);
      }
      if (!verifiedToken.valid) {
        const message = verifiedToken.reason === "not_a_bot"
          ? "A credencial foi aceita, mas não pertence a um usuário Bot. Use o Bot Token da seção Bot no Discord Developer Portal."
          : "O Discord recusou o token. Gere ou copie novamente o Bot Token na seção Bot do Discord Developer Portal; não use Client Secret, Client ID ou Public Key.";
        return reply({ error: message, code: verifiedToken.reason || "invalid_discord_token" }, 400);
      }
      const encryptedToken = await encryptSecret(discordToken, env);
      const id = randomToken(12);
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO bots (id,user_id,name,runtime,state,modules,discord_token_enc,discord_bot_id,discord_bot_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(id, user.id, name, runtime, "draft", JSON.stringify({}), encryptedToken, verifiedToken.botId, verifiedToken.botName || null, now, now).run();
      return reply({
        id, name, runtime, state: "draft", modules: {},
        hasDiscordToken: true,
        executionAvailable: false,
        message: "Projeto criado. O token Discord foi armazenado criptografado no servidor."
      }, 201);
    }
    const match = path.match(/^\/bots\/([A-Za-z0-9_-]{1,80})(?:\/(logs|power|upload-url|extract|config|resources|files|shell|schedule|diagnose))?$/);
    if (match) {
      const id = match[1];
      const action = match[2] || "";
      const bot = await getOwnedBot(id, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);

      if (!action && request.method === "DELETE") {
        let stopConfirmed = !bot.hosting_deployment_id;
        let hostingConnected = false;
        if (bot.hosting_deployment_id) {
          const connection = await env.DB.prepare(
            "SELECT user_id FROM hosting_connections WHERE user_id=?"
          ).bind(user.id).first();
          hostingConnected = !!connection;
          if (hostingConnected) {
            try {
              await hostRequest(
                user.id, env,
                "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/power",
                "POST",
                { action: "stop", waitSeconds: 20 }
              );
              stopConfirmed = true;
            } catch (error) {
              return reply({
                error: "Não consegui confirmar que o processo foi parado na hospedagem. O bot continua salvo no painel. Reconecte a hospedagem e tente excluir novamente.",
                code: "bot_stop_failed"
              }, 502);
            }
          }
        }
        await env.DB.prepare(
          "DELETE FROM bots WHERE id=? AND user_id=?"
        ).bind(id, user.id).run();
        return reply({
          ok: true,
          deleted: true,
          stopConfirmed,
          message: stopConfirmed
            ? "Bot removido do painel e processo parado quando havia implantação."
            : "Bot removido do painel, mas a hospedagem não estava conectada para confirmar a parada do processo."
        });
      }

      if (!action && request.method === "GET") {
        const hasToken = !!bot.discord_token_enc;
        let discordBotId = bot.discord_bot_id || null;
        let discordBotName = bot.discord_bot_name || null;
        if (hasToken && !discordBotId) {
          try {
            const savedToken = await decryptSecret(bot.discord_token_enc, env);
            const identity = savedToken ? await validateDiscordBotToken(savedToken) : null;
            if (identity?.valid) {
              discordBotId = identity.botId;
              discordBotName = identity.botName || null;
              await env.DB.prepare("UPDATE bots SET discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?")
                .bind(discordBotId, discordBotName, Date.now(), id, user.id).run();
            }
          } catch (error) {
            console.error("Discord bot identity lookup failed:", error?.name || "Error");
          }
        }
        let state = bot.state || "draft";
        let runtimeInfo = null;
        if (bot.hosting_deployment_id) {
          try {
            runtimeInfo = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0");
            state = runtimeInfo.state || runtimeInfo.deployment?.state || state;
          } catch (error) {
            runtimeInfo = { error: error.message };
          }
        }
        const modules = typeof bot.modules === "string" ? JSON.parse(bot.modules || "{}") : (bot.modules || {});
        return reply({
          id: bot.id, name: bot.name, runtime: bot.runtime, state,
          modules, hasDiscordToken: hasToken,
          discordBotId,
          discordBotName,
          hostingDeploymentId: bot.hosting_deployment_id || null,
          scheduleEnabled: !!bot.schedule_enabled,
          botOnlineNow: !!bot.hosting_deployment_id && state === "running" && (!bot.schedule_enabled || isInsideSchedule(bot.schedule_start || "00:00", bot.schedule_end || "23:59", bot.schedule_timezone || "America/Bahia")),
          scheduleStart: bot.schedule_start || "00:00",
          scheduleEnd: bot.schedule_end || "23:59",
          scheduleTimezone: bot.schedule_timezone || "America/Bahia",
          guildId: bot.guild_id || "",
          executionAvailable: !!bot.hosting_deployment_id,
          runtimeInfo
        });
      }

      if (action === "config" && request.method === "POST") {
        const b = await body(request);
        const discordToken = String(b.discordToken || "").trim();
        let identity = null;
        if (discordToken) {
          if (discordToken.length < 30 || discordToken.length > 256 || /\s/.test(discordToken)) {
            return reply({ error: "O token Discord precisa ter pelo menos 30 caracteres e não pode conter espaços." }, 400);
          }
          identity = await validateDiscordBotToken(discordToken);
          if (identity.unavailable) {
            const message = identity.reason === "rate_limited"
              ? "O Discord limitou temporariamente as verificações. Aguarde um minuto e tente novamente."
              : "Não foi possível alcançar o Discord para validar o token. Verifique a conexão e tente novamente.";
            return reply({ error: message, code: identity.reason || "discord_unavailable" }, 503);
          }
          if (!identity.valid) {
            const message = identity.reason === "not_a_bot"
              ? "A credencial foi aceita, mas não pertence a um usuário Bot. Use o Bot Token da seção Bot no Discord Developer Portal."
              : "O Discord recusou o token. Gere ou copie novamente o Bot Token na seção Bot do Discord Developer Portal; não use Client Secret, Client ID ou Public Key.";
            return reply({ error: message, code: identity.reason || "invalid_discord_token" }, 400);
          }
          const encryptedToken = await encryptSecret(discordToken, env);
          await env.DB.prepare(
            "UPDATE bots SET discord_token_enc=?,discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?"
          ).bind(encryptedToken, identity.botId, identity.botName || null, Date.now(), id, user.id).run();
        } else if (!bot.discord_token_enc) {
          return reply({ error: "Informe o token do bot Discord para este projeto." }, 400);
        }
        const allowed = ["music","tickets","attendance","team","goals","warnings","recruitment","logs"];
        const modules = {};
        for (const key of allowed) modules[key] = !!(b.modules && b.modules[key]);
        await env.DB.prepare(
          "UPDATE bots SET modules=?::jsonb, updated_at=? WHERE id=? AND user_id=?"
        ).bind(JSON.stringify(modules), Date.now(), id, user.id).run();
        return reply({
          ok: true, modules, hasDiscordToken: true, tokenUpdated: !!discordToken,
          discordBotId: identity?.botId || bot.discord_bot_id || null,
          state: bot.state || "draft",
          executionAvailable: !!bot.hosting_deployment_id,
          note: "Token protegido e módulos salvos. Conecte a hospedagem para instalar e iniciar o bot."
        });
      }

      if (action === "schedule" && request.method === "POST") {
        const b = await body(request);
        const enabled = !!b.enabled;
        const startClock = String(b.start || "00:00");
        const endClock = String(b.end || "23:59");
        if (!validClock(startClock) || !validClock(endClock) || (enabled && startClock === endClock)) {
          return reply({ error: "Informe horários válidos e diferentes, no formato HH:MM." }, 400);
        }
        // Guild-specific sync is intentionally disabled: the bot is expected to
        // already be installed in the user's server. Use Discord global commands.
        await env.DB.prepare(
          "UPDATE bots SET schedule_enabled=?,schedule_start=?,schedule_end=?,schedule_timezone='America/Bahia',guild_id=NULL,updated_at=? WHERE id=? AND user_id=?"
        ).bind(enabled, startClock, endClock, Date.now(), id, user.id).run();
        if (bot.hosting_deployment_id && await env.DB.prepare("SELECT user_id FROM hosting_connections WHERE user_id=?").bind(user.id).first()) {
          const deploymentId = bot.hosting_deployment_id;
          await setHostEnv(user.id, env, deploymentId, "CAOS_SCHEDULE_ENABLED", enabled ? "1" : "0", false);
          await setHostEnv(user.id, env, deploymentId, "CAOS_SCHEDULE_START", startClock, false);
          await setHostEnv(user.id, env, deploymentId, "CAOS_SCHEDULE_END", endClock, false);
          await setHostEnv(user.id, env, deploymentId, "GUILD_ID", "", false);
          const live = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=0");
          if ((live.state || live.deployment?.state) === "running") {
            await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "restart", waitSeconds: 35 });
          }
        }
        return reply({ ok: true, scheduleEnabled: enabled, start: startClock, end: endClock, timezone: "America/Bahia" });
      }

      if (action === "power" && request.method === "POST") {
        const b = await body(request);
        const signal = String(b.action || "").toLowerCase();
        if (!["start","stop","restart"].includes(signal)) return reply({ error: "Ação de energia inválida." }, 400);
        const connected = await env.DB.prepare("SELECT user_id FROM hosting_connections WHERE user_id=?").bind(user.id).first();
        if (!connected) return reply({ code: "hosting_not_connected", error: "Conecte sua conta Bot-Hosting para habilitar os controles reais de iniciar e parar." }, 409);
        let deploymentId = bot.hosting_deployment_id;
        let botId = bot.discord_bot_id;
        try {
          if (signal === "start" || signal === "restart") {
            const provisioned = await ensureBotDeployment(bot, user.id, env);
            deploymentId = provisioned.deploymentId;
            botId = provisioned.botId;
          }
          if (!deploymentId) return reply({ error: "Este bot ainda não tem um servidor de execução. Pressione Iniciar para preparar a hospedagem." }, 409);
          const result = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", {
            action: signal, waitSeconds: signal === "start" || signal === "restart" ? 45 : 0
          });
          const actualState = String(result.state || "").toLowerCase();
          await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?")
            .bind(actualState || (signal === "stop" ? "stopped" : "starting"), Date.now(), id, user.id).run();
          const lines = Array.isArray(result.logs) ? result.logs : [];
          const logText = lines.join("\n");
          const commandsSynced = logText.includes("Comandos globais sincronizados") || logText.includes("Comandos sincronizados no servidor de teste");
          const started = signal === "stop" || actualState === "running";
          if (!started) {
            return reply({
              ok: false, state: actualState || "starting", deploymentId,
              logs: lines.slice(-30), hint: result.hint || "O servidor ainda não confirmou que o bot iniciou."
            }, 502);
          }
          return reply({
            ok: true, action: signal, state: actualState || (signal === "stop" ? "stopped" : "running"),
            deploymentId, discordBotId: botId || null, commandsSynced,
            scheduled: !!bot.schedule_enabled,
            botOnlineNow: !bot.schedule_enabled || isInsideSchedule(bot.schedule_start || "00:00", bot.schedule_end || "23:59", bot.schedule_timezone || "America/Bahia"),
            logs: lines.slice(-35), hint: result.hint || null
          });
        } catch (error) {
          return reply({ ok: false, error: error.message || "Falha ao controlar o bot no Bot-Hosting." }, 502);
        }
      }

      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Este projeto ainda não foi iniciado em uma hospedagem." }, 409);
        try {
          const path = action === "logs"
            ? "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/logs?size=100&waitSeconds=1"
            : "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0";
          return reply(await hostRequest(user.id, env, path));
        } catch (error) {
          return reply({ error: error.message || "Não consegui consultar o servidor do bot." }, 502);
        }
      }

      if (["upload-url","extract","files","shell"].includes(action)) {
        return reply({
          code: "feature_not_ready",
          error: "Esta área ainda não foi conectada ao armazenamento de arquivos. Os controles de execução e horários já usam a hospedagem real."
        }, 501);
      }
    }
    return reply({ error: "Rota não encontrada." }, 404);
  } catch (error) {
    return reply({ error: error && error.message ? error.message : "Erro interno." }, 500);
  }
}
let schemaPromise;
function makeDatabase(connectionString) {
  const sql = neon(connectionString);
  function placeholders(statement) {
    let index = 0;
    return statement.replace(/\?/g, () => "$" + (++index));
  }
  function operations(query, params = []) {
    return {
      async first() {
        const rows = await sql.query(query, params);
        return rows[0] || null;
      },
      async run() {
        const rows = await sql.query(query, params);
        return { success: true, results: rows };
      },
      async all() {
        return sql.query(query, params);
      }
    };
  }
  return {
    async raw(statement, params = []) {
      return sql.query(placeholders(statement), params);
    },
    prepare(statement) {
      const query = placeholders(statement);
      return {
        bind(...params) {
          return operations(query, params);
        },
        // Neon adapter also supports statements without bind() parameters.
        first() {
          return operations(query).first();
        },
        run() {
          return operations(query).run();
        },
        all() {
          return operations(query).all();
        }
      };
    }
  };
}
async function ensureSchema(db) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      const statements = [
        `CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL,
          email TEXT NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','member')),
          discord_id TEXT UNIQUE, created_at BIGINT NOT NULL
        )`,
        "CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username))",
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email))",
        `CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL
        )`,
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
        `CREATE TABLE IF NOT EXISTS discord_states (state TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)`,
        "CREATE INDEX IF NOT EXISTS idx_discord_states_expiry ON discord_states(expires_at)",
        `CREATE TABLE IF NOT EXISTS hosting_keys (
          user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          encrypted_key TEXT NOT NULL, updated_at BIGINT NOT NULL
        )`,
        "CREATE TABLE IF NOT EXISTS app_state (id TEXT PRIMARY KEY, owner_user_id TEXT)",
        `CREATE TABLE IF NOT EXISTS bots (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          runtime TEXT NOT NULL CHECK (runtime IN ('python','nodejs')),
          state TEXT NOT NULL DEFAULT 'draft',
          modules JSONB NOT NULL DEFAULT '{}'::jsonb,
          discord_token_enc TEXT,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL
        )`,
        "CREATE INDEX IF NOT EXISTS idx_bots_user_created ON bots(user_id, created_at DESC)",
        "CREATE TABLE IF NOT EXISTS hosting_oauth_apps (id TEXT PRIMARY KEY,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,updated_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS hosting_oauth_states (state TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_verifier TEXT NOT NULL,expires_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS hosting_connections (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,access_token_enc TEXT NOT NULL,refresh_token_enc TEXT NOT NULL,expires_at BIGINT NOT NULL,scope TEXT,updated_at BIGINT NOT NULL)"
      ];
      for (const statement of statements) await db.raw(statement);
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_token_enc TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_bot_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_bot_name TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS hosting_deployment_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_start TEXT NOT NULL DEFAULT '00:00'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_end TEXT NOT NULL DEFAULT '23:59'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_timezone TEXT NOT NULL DEFAULT 'America/Bahia'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS guild_id TEXT");
      await db.raw("INSERT INTO app_state (id, owner_user_id) VALUES ('main', NULL) ON CONFLICT (id) DO NOTHING");
    })().catch(error => { schemaPromise = null; throw error; });
  }
  await schemaPromise;
}
export const config = { api: { bodyParser: false, responseLimit: false } };
export default async function handler(req, res) {
  try {
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers || {})) {
      if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : String(value));
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const rawBody = Buffer.concat(chunks);
    const method = String(req.method || "GET").toUpperCase();
    const url = new URL(req.url || "/", "https://" + (req.headers?.host || "localhost"));
    const init = { method, headers };
    if (method !== "GET" && method !== "HEAD" && rawBody.length) { init.body = rawBody; init.duplex = "half"; }
    const request = new Request(url, init);
    const env = { ...process.env, DB: null };
    if (env.DATABASE_URL) { env.DB = makeDatabase(env.DATABASE_URL); await ensureSchema(env.DB); }
    const response = await onRequest({ request, env });
    res.statusCode = response.status;
    response.headers.forEach((value, key) => { if (key.toLowerCase() !== "set-cookie") res.setHeader(key, value); });
    const cookies = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie() : [response.headers.get("set-cookie")].filter(Boolean);
    if (cookies.length) res.setHeader("Set-Cookie", cookies);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error("black-zone-estudio API error:", error);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(JSON.stringify({ error: "Erro interno no servidor. Confira as configurações do banco e tente novamente." }));
  }
}
