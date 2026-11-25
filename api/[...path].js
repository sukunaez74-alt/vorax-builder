import { neon } from "@neondatabase/serverless";
import { CAOS_MAIN_PY } from "./caos-main.js";

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
function normalizeDiscordBotToken(value) {
  let token = String(value ?? "").trim();
  if (token.length >= 2 &&
      ((token.startsWith('"') && token.endsWith('"')) ||
       (token.startsWith("'") && token.endsWith("'")))) {
    token = token.slice(1, -1).trim();
  }
  // Discord examples sometimes show "Bot " before the actual token.
  // The API request below adds the Bot scheme itself, so remove it if pasted.
  token = token.replace(/^Bot[ \t]+/i, "").trim();
  return token;
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

async function discordOAuthCredentials(env) {
  let row = null;
  try { row = await env.DB.prepare("SELECT oauth_client_id,oauth_client_secret_enc FROM verification_bot_settings WHERE id='main'").first(); } catch {}
  let storedSecret = null;
  if (row?.oauth_client_secret_enc) {
    try { storedSecret = await decryptSecret(row.oauth_client_secret_enc, env); } catch {}
  }
  return {
    clientId: String(row?.oauth_client_id || env.DISCORD_CLIENT_ID || "").trim(),
    clientSecret: String(storedSecret || env.DISCORD_CLIENT_SECRET || "").trim()
  };
}
function ownerOnly(user) {
  return user?.role === "owner";
}
async function verificationBotSettings(env) {
  return await env.DB.prepare(
    "SELECT owner_user_id,bot_token_enc,bot_id,bot_name,oauth_client_id,oauth_client_secret_enc,invite_url,hosting_deployment_id,state,updated_at FROM verification_bot_settings WHERE id='main'"
  ).first();
}
function verificationBotSource() {
  return String.raw`import os
import json
import asyncio
from pathlib import Path
from datetime import datetime, timezone

import discord
from discord import app_commands
from discord.ext import commands, tasks

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
APP_URL = os.getenv("APP_URL", "https://black-zone-estudio.vercel.app").rstrip("/")
INVITE_URL = os.getenv("SERVER_INVITE", "").strip()
VERIFY_URL = INVITE_URL
STATUS_FILE = Path("verification-status.json")

def write_status(status, **extra):
    payload = {"status": status, "updatedAt": datetime.now(timezone.utc).isoformat(), **extra}
    temp = STATUS_FILE.with_suffix(".tmp")
    try:
        temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temp.replace(STATUS_FILE)
    except OSError:
        pass

class VerifyBot(commands.Bot):
    async def setup_hook(self):
        try:
            synced = await self.tree.sync()
            print("VERIFICATION: comandos publicados=" + str(len(synced)), flush=True)
        except Exception as exc:
            print("VERIFICATION: erro ao sincronizar comandos: " + type(exc).__name__ + ": " + str(exc)[:300], flush=True)

    async def on_ready(self):
        print("VERIFICATION: conectado como " + str(self.user) + " | servidores=" + str(len(self.guilds)), flush=True)
        write_status("online", botId=str(self.user.id), botName=str(self.user), guilds=len(self.guilds))
        if not heartbeat.is_running():
            heartbeat.start()

    async def on_resumed(self):
        write_status("online", botId=str(self.user.id), botName=str(self.user), guilds=len(self.guilds))

intents = discord.Intents.none()
bot = VerifyBot(command_prefix="!", intents=intents)

@tasks.loop(seconds=30)
async def heartbeat():
    if bot.user:
        write_status("online", botId=str(bot.user.id), botName=str(bot.user), guilds=len(bot.guilds))

@bot.tree.command(name="verificar", description="Receba o convite do servidor")
async def verificar(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Verificação de conta",
        description="Use o botão abaixo para receber o convite e entrar no servidor.",
        color=discord.Color.blurple()
    )
    embed.set_footer(text="BLACK ZONE • Verificação segura")
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(label="Entrar e verificar", style=discord.ButtonStyle.link, url=VERIFY_URL))
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

@bot.tree.command(name="painel_verificacao", description="Publica o painel de verificação neste canal")
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def painel_verificacao(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Seja bem-vindo(a)! ✦",
        description="Use o botão abaixo para receber o convite e entrar no servidor.",
        color=discord.Color.blurple()
    )
    embed.set_footer(text="BLACK ZONE • Central de verificação")
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(label="Entrar e verificar", style=discord.ButtonStyle.link, url=VERIFY_URL))
    await interaction.response.send_message(embed=embed, view=view)

@bot.tree.command(name="link_servidor", description="Verifica sua conta Discord e libera o convite do servidor")
async def link_servidor(interaction: discord.Interaction):
    if not INVITE_URL:
        await interaction.response.send_message("O convite ainda não foi configurado no painel administrativo.", ephemeral=True)
        return
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(label="Entrar e verificar", style=discord.ButtonStyle.link, url=VERIFY_URL))
    await interaction.response.send_message("Use o botão abaixo para entrar no servidor:", view=view, ephemeral=True)

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    print("VERIFICATION: erro de comando: " + type(error).__name__ + ": " + str(error)[:300], flush=True)
    if not interaction.response.is_done():
        await interaction.response.send_message("Não consegui concluir esse comando. Tente novamente.", ephemeral=True)

if not TOKEN:
    write_status("token_missing")
    raise SystemExit("DISCORD_TOKEN não configurado.")

write_status("starting")
bot.run(TOKEN, log_handler=None)`;
}
async function ensureVerificationBotDeployment(userId, env) {
  const settings = await verificationBotSettings(env);
  if (!settings?.bot_token_enc) throw new Error("Salve primeiro o Bot Token do bot de verificação.");
  const token = await decryptSecret(settings.bot_token_enc, env);
  if (!token) throw new Error("Não consegui abrir o token protegido. Salve novamente o Bot Token.");
  const identity = await validateDiscordBotToken(token);
  if (!identity.valid) throw new Error("O Discord recusou o token do bot de verificação. Atualize a credencial.");
  const duplicate = await env.DB.prepare("SELECT id,name FROM bots WHERE user_id=? AND discord_bot_id=? LIMIT 1")
    .bind(userId, identity.botId).first();
  if (duplicate) throw new Error("Este bot Discord já está configurado no projeto \"" + String(duplicate.name || duplicate.id) + "\". O bot central precisa ter uma aplicação e um token exclusivos.");
  if (settings.oauth_client_id && String(settings.oauth_client_id) !== identity.botId) {
    throw new Error("O Client ID OAuth2 precisa ser o ID da mesma aplicação do bot.");
  }
  const connected = await env.DB.prepare("SELECT user_id FROM hosting_connections WHERE user_id=?").bind(userId).first();
  if (!connected) throw new Error("Conecte sua conta Bot-Hosting nas Configurações do Estúdio antes de iniciar o bot central.");
  let deploymentId = settings.hosting_deployment_id || null;
  const isNew = !deploymentId;
  let reusedCaosBot = null;
  if (isNew) {
    const hosting = await env.DB.prepare("SELECT scope FROM hosting_connections WHERE user_id=?").bind(userId).first();
    const granted = String(hosting?.scope || "").split(/\s+/).filter(Boolean);
    if (!granted.includes("credits:spend") || !granted.includes("deployments:write")) {
      throw new Error("A autorização atual do Bot-Hosting não permite criar o servidor do ADM. Vá em Configurações, clique em Conectar / reconectar Bot-Hosting e aprove a permissão de criação de implantações.");
    }
    const existing = await hostRequest(userId, env, "/deployments?name=black-zone-verificacao&brief=true");
    const matches = Array.isArray(existing.deployments) ? existing.deployments : [];
    const recovered = matches.find(item => item && item.name === "black-zone-verificacao" && item.owned !== false && item.id);
    if (recovered) {
      deploymentId = String(recovered.id);
    } else {
      try {
        const created = await hostRequest(userId, env, "/deployments", "POST", {
          name: "black-zone-verificacao",
          source: "blank",
          runtime: "python",
          runtimeVersion: "3.11"
        });
        const deployment = created.deployment || created;
        deploymentId = String(deployment.id || "");
        if (!deploymentId) throw new Error("O Bot-Hosting não retornou o ID da implantação do bot de verificação.");
      } catch (createError) {
        if (!/HTTP 402\b/.test(String(createError?.message || ""))) throw createError;
        reusedCaosBot = await env.DB.prepare(
          "SELECT id,name,hosting_deployment_id,state FROM bots WHERE user_id=? AND lower(name)=lower('CAOS') AND hosting_deployment_id IS NOT NULL AND state IN ('stopped','draft') ORDER BY updated_at DESC LIMIT 1"
        ).bind(userId).first();
        if (!reusedCaosBot?.hosting_deployment_id) throw createError;
        deploymentId = String(reusedCaosBot.hosting_deployment_id);
        const current = await hostRequest(
          userId, env,
          "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=2"
        );
        const currentState = String(current.state || current.deployment?.state || "").toLowerCase();
        if (!currentState) throw new Error("Encontrei a hospedagem do CAOS, mas não consegui confirmar o estado dela. Nenhum arquivo foi alterado.");
        if (!["offline","stopped","terminated"].includes(currentState)) {
          await hostRequest(
            userId, env,
            "/deployments/" + encodeURIComponent(deploymentId) + "/power",
            "POST",
            { action: "stop", waitSeconds: 0 }
          );
        }
      }
    }
    if (!reusedCaosBot) {
      await env.DB.prepare("UPDATE verification_bot_settings SET hosting_deployment_id=?,bot_id=?,bot_name=?,state='starting',updated_at=? WHERE id='main'")
        .bind(deploymentId, identity.botId, identity.botName || null, Date.now()).run();
    }
  }
  const version = "bz-verification-bot-v3-reuse-caos-2026-11";
  let installed = "";
  if (!isNew) {
    try {
      const r = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/content?path=%2Fverification-version.txt");
      installed = String(r.content || "").trim();
    } catch {}
  }
  if (isNew || installed !== version) {
    const result = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/writeMany", "POST", {
      files: [
        { path: "/verification_bot.py", content: verificationBotSource(), mode: "overwrite" },
        { path: "/requirements.txt", content: "discord.py==2.7.1\n", mode: "overwrite" },
        { path: "/verification-version.txt", content: version, mode: "overwrite" }
      ]
    });
    if (Array.isArray(result.failed) && result.failed.length) {
      const failures = result.failed.map(item => {
        const filePath = item?.path || item?.file || "arquivo";
        const reason = externalErrorText(item?.reason ?? item?.error ?? item?.message ?? item);
        return filePath + " — " + (reason || "falha sem detalhes");
      }).join("; ");
      throw new Error("Falha ao enviar arquivos do bot central: " + failures);
    }
  }
  await setHostEnv(userId, env, deploymentId, "DISCORD_TOKEN", token, true);
  await setHostEnv(userId, env, deploymentId, "APP_URL", "https://black-zone-estudio.vercel.app", false);
  await setHostEnv(userId, env, deploymentId, "SERVER_INVITE", settings.invite_url || "", false);
  await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
    runtime: "python", runtimeVersion: "3.11", entryFile: "verification_bot.py", startCommand: null
  });
  await env.DB.prepare("UPDATE verification_bot_settings SET hosting_deployment_id=?,bot_id=?,bot_name=?,state='starting',updated_at=? WHERE id='main'")
    .bind(deploymentId, identity.botId, identity.botName || null, Date.now()).run();
  if (reusedCaosBot?.id) {
    await env.DB.prepare("UPDATE bots SET hosting_deployment_id=NULL,state='stopped',updated_at=? WHERE id=? AND user_id=? AND hosting_deployment_id=?")
      .bind(Date.now(), reusedCaosBot.id, userId, deploymentId).run();
  }
  return {
    deploymentId, botId: identity.botId, botName: identity.botName || null,
    reusedCaosDeployment: !!reusedCaosBot,
    replacedBotName: reusedCaosBot?.name || null
  };
}
async function readVerificationBotStatus(userId, env, settings) {
  if (!settings?.hosting_deployment_id) return { state: "not_deployed", online: false, deploymentId: null };
  let runtime = null;
  try {
    runtime = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(settings.hosting_deployment_id) + "/diagnose?waitSeconds=15");
  } catch (error) {
    return { state: "error", online: false, deploymentId: settings.hosting_deployment_id, error: error.message };
  }
  let heartbeat = null;
  try {
    const raw = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(settings.hosting_deployment_id) + "/files/content?path=%2Fverification-status.json");
    heartbeat = JSON.parse(String(raw.content || "{}"));
  } catch {}
  const age = heartbeat?.updatedAt ? Date.now() - Date.parse(heartbeat.updatedAt) : Infinity;
  const online = String(runtime.state || runtime.deployment?.state || "").toLowerCase() === "running" &&
    heartbeat?.status === "online" && age >= 0 && age < 120000;
  return {
    state: online ? "online" : String(runtime.state || runtime.deployment?.state || "starting").toLowerCase(),
    online, deploymentId: settings.hosting_deployment_id,
    heartbeatAt: heartbeat?.updatedAt || null,
    guilds: Number(heartbeat?.guilds || 0),
    runtimeState: runtime.state || runtime.deployment?.state || null,
    hint: runtime.hint || null,
    error: heartbeat?.error || runtime.error || null,
    logs: Array.isArray(runtime.logs) ? runtime.logs.slice(-18) : []
  };
}
async function saveVerificationBotSettings(user, input, env) {
  const old = await verificationBotSettings(env);
  const inviteUrl = String(input.inviteUrl || old?.invite_url || "").trim();
  let token = String(input.botToken || "").trim();
  if (!token && old?.bot_token_enc) {
    try { token = await decryptSecret(old.bot_token_enc, env) || ""; } catch {}
  }
  if (!inviteUrl) return { ok: false, status: 400, error: "Informe o convite do seu servidor Discord." };
  let invite;
  try { invite = new URL(inviteUrl); } catch { return { ok: false, status: 400, error: "O convite do servidor não é uma URL válida." }; }
  if (invite.protocol !== "https:" || !["discord.gg","www.discord.gg","discord.com","www.discord.com"].includes(invite.hostname) ||
      !(invite.hostname.includes("discord.gg") || invite.pathname.startsWith("/invite/"))) {
    return { ok: false, status: 400, error: "Use um convite HTTPS do Discord, como https://discord.gg/..." };
  }
  token = normalizeDiscordBotToken(token);
  if (token.length < 30 || token.length > 512 || /\s/.test(token)) return { ok: false, status: 400, error: "Informe um Bot Token válido, sem espaços." };
  const identity = await validateDiscordBotToken(token);
  if (!identity.valid) return { ok: false, status: identity.unavailable ? 503 : 400, error: identity.unavailable ? "Não consegui validar com o Discord agora. Tente novamente." : "O Discord recusou o Bot Token informado." };
  const tokenEnc = await encryptSecret(token, env);
  const previousSecretEnc = old?.oauth_client_id === identity.botId ? (old?.oauth_client_secret_enc || null) : null;
  await env.DB.prepare(
    "INSERT INTO verification_bot_settings (id,owner_user_id,bot_token_enc,bot_id,bot_name,oauth_client_id,oauth_client_secret_enc,invite_url,state,updated_at) VALUES ('main',?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id,bot_token_enc=EXCLUDED.bot_token_enc,bot_id=EXCLUDED.bot_id,bot_name=EXCLUDED.bot_name,oauth_client_id=EXCLUDED.oauth_client_id,oauth_client_secret_enc=CASE WHEN verification_bot_settings.oauth_client_id=EXCLUDED.oauth_client_id THEN COALESCE(EXCLUDED.oauth_client_secret_enc,verification_bot_settings.oauth_client_secret_enc) ELSE EXCLUDED.oauth_client_secret_enc END,invite_url=EXCLUDED.invite_url,state=CASE WHEN verification_bot_settings.hosting_deployment_id IS NULL THEN 'configured' ELSE verification_bot_settings.state END,updated_at=EXCLUDED.updated_at"
  ).bind(user.id, tokenEnc, identity.botId, identity.botName || null, identity.botId, previousSecretEnc, inviteUrl, old?.state || "configured", Date.now()).run();
  return { ok: true, configured: true, botId: identity.botId, botName: identity.botName || null, inviteUrl, hasToken: true, message: "Bot Token validado e convite salvos com segurança." };
 }
async function saveVerificationOAuthSettings(user, input, env) {
  const settings = await verificationBotSettings(env);
  if (!settings?.bot_id || !settings?.bot_token_enc) {
    return { ok: false, status: 409, error: "Salve primeiro o Bot Token do bot central." };
  }
  const clientId = String(input.clientId || settings.bot_id).trim();
  if (clientId !== String(settings.bot_id)) {
    return { ok: false, status: 400, error: "O Client ID OAuth2 precisa ser o mesmo ID da aplicação do Bot Token salvo." };
  }
  let secret = String(input.clientSecret || "").trim();
  if (!secret && settings.oauth_client_secret_enc) {
    try { secret = await decryptSecret(settings.oauth_client_secret_enc, env) || ""; } catch {}
  }
  if (!secret || secret.length < 16 || secret.length > 256 || /\s/.test(secret)) {
    return { ok: false, status: 400, error: "Informe o Client Secret OAuth2 da mesma aplicação Discord, sem espaços." };
  }
  let encrypted;
  try {
    encrypted = await encryptSecret(secret, env);
    const check = await decryptSecret(encrypted, env);
    if (!check || !same(check, secret)) throw new Error("integrity");
  } catch {
    return { ok: false, status: 503, error: "Não foi possível proteger o Client Secret. Confira a chave de criptografia do Estúdio." };
  }
  await env.DB.prepare(
    "UPDATE verification_bot_settings SET oauth_client_id=?,oauth_client_secret_enc=?,updated_at=? WHERE id='main'"
  ).bind(settings.bot_id, encrypted, Date.now()).run();
  return { ok: true, oauthConfigured: true, clientId: settings.bot_id, message: "Login Discord configurado e Client Secret armazenado criptografado." };
}
async function verificationStart(request, env) {
  const settings = await verificationBotSettings(env);
  const oauth = await discordOAuthCredentials(env);
  if (!settings?.invite_url || !oauth.clientId || !oauth.clientSecret) {
    return new Response(null, { status: 302, headers: { location: new URL("/?verification=not_configured", request.url).href } });
  }
  const state = randomToken(24);
  await env.DB.prepare("INSERT INTO verification_states (state,invite_url,expires_at) VALUES (?,?,?)")
    .bind(state, settings.invite_url, Date.now() + 600000).run();
  const redirectUri = new URL("/api/verification/callback", request.url).href;
  const authorize = new URL("https://discord.com/oauth2/authorize");
  authorize.searchParams.set("client_id", oauth.clientId);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "identify");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("prompt", "consent");
  return new Response(null, { status: 302, headers: { location: authorize.href, "set-cookie": setCookie("bz_verify_state", state, 600) } });
}
async function verificationCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieState = cookieMap(request).bz_verify_state;
  if (!code || !state || !cookieState || !same(state, cookieState)) return reply({ error: "A confirmação de verificação expirou. Comece novamente pelo botão Verificar." }, 400, { "set-cookie": clearCookie("bz_verify_state") });
  const saved = await env.DB.prepare("SELECT invite_url FROM verification_states WHERE state=? AND expires_at>?").bind(state, Date.now()).first();
  await env.DB.prepare("DELETE FROM verification_states WHERE state=?").bind(state).run();
  if (!saved) return reply({ error: "O pedido de verificação expirou. Comece novamente." }, 400, { "set-cookie": clearCookie("bz_verify_state") });
  const oauth = await discordOAuthCredentials(env);
  if (!oauth.clientId || !oauth.clientSecret) return reply({ error: "A configuração OAuth2 do Discord ainda não está pronta." }, 503);
  const redirectUri = new URL("/api/verification/callback", request.url).href;
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ client_id: oauth.clientId, client_secret: oauth.clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
    signal: AbortSignal.timeout(12000)
  });
  const tokenData = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokenData.access_token) return reply({ error: "O Discord não concluiu a autorização. Volte ao servidor e tente novamente." }, 401);
  const profileRes = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { authorization: "Bearer " + tokenData.access_token, accept: "application/json" },
    signal: AbortSignal.timeout(12000)
  });
  const profile = await profileRes.json().catch(() => ({}));
  if (!profileRes.ok || !profile.id || !profile.username) return reply({ error: "Não foi possível confirmar o perfil Discord autorizado." }, 502);
  const username = String(profile.global_name || profile.username).slice(0, 100);
  await env.DB.prepare(
    "INSERT INTO discord_verifications (discord_id,discord_username,avatar_hash,verified_at) VALUES (?,?,?,?) ON CONFLICT (discord_id) DO UPDATE SET discord_username=EXCLUDED.discord_username,avatar_hash=EXCLUDED.avatar_hash,verified_at=EXCLUDED.verified_at"
  ).bind(String(profile.id), username, profile.avatar ? String(profile.avatar) : null, Date.now()).run();
  try {
    const basic = btoa(String(oauth.clientId) + ":" + String(oauth.clientSecret));
    await fetch("https://discord.com/api/oauth2/token/revoke", {
      method: "POST", headers: { authorization: "Basic " + basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokenData.access_token, token_type_hint: "access_token" }),
      signal: AbortSignal.timeout(8000)
    });
  } catch {}
  const headers = new Headers({ location: saved.invite_url });
  headers.append("set-cookie", clearCookie("bz_verify_state"));
  return new Response(null, { status: 302, headers });
}

async function prepareDiscordBotToken(rawValue, env) {
  const token = normalizeDiscordBotToken(rawValue);
  if (token.length < 30 || token.length > 512 || /\s/.test(token)) {
    return { ok: false, status: 400, error: "Cole o Bot Token completo, sem espaços. O prefixo opcional 'Bot ' é removido automaticamente." };
  }
  const identity = await validateDiscordBotToken(token);
  if (identity.unavailable) {
    return {
      ok: false,
      status: 503,
      error: identity.reason === "rate_limited"
        ? "O Discord limitou temporariamente a validação. Aguarde um minuto e tente novamente."
        : "Não foi possível consultar o Discord agora. O token não foi alterado; tente novamente."
    };
  }
  if (!identity.valid) {
    return {
      ok: false,
      status: 400,
      error: identity.reason === "not_a_bot"
        ? "Esta credencial não é um Bot Token. Use a seção Bot do Discord Developer Portal."
        : "O Discord recusou o token. Gere ou copie novamente o Bot Token da seção Bot."
    };
  }
  let encryptedToken;
  try {
    encryptedToken = await encryptSecret(token, env);
  } catch {
    return { ok: false, status: 503, error: "A chave de criptografia do Estúdio não está disponível. O token não foi gravado." };
  }
  return { ok: true, token, encryptedToken, identity };
}

async function saveDiscordBotToken(id, userId, rawValue, env) {
  const ownedBot = await env.DB.prepare(
    "SELECT id FROM bots WHERE id=? AND user_id=?"
  ).bind(id, userId).first();
  if (!ownedBot) return { ok: false, status: 404, error: "Projeto não encontrado nesta conta." };

  const prepared = await prepareDiscordBotToken(rawValue, env);
  if (!prepared.ok) return prepared;

  try {
    await env.DB.prepare(
      "UPDATE bots SET discord_token_enc=?,discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?"
    ).bind(
      prepared.encryptedToken,
      prepared.identity.botId,
      prepared.identity.botName || null,
      Date.now(),
      id,
      userId
    ).run();

    const confirmed = await env.DB.prepare(
      "SELECT discord_token_enc,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
    ).bind(id, userId).first();
    if (!confirmed?.discord_token_enc) {
      return { ok: false, status: 500, error: "O banco não confirmou a gravação do Bot Token. Ele não foi marcado como salvo." };
    }

    const roundTrip = await decryptSecret(confirmed.discord_token_enc, env);
    if (!roundTrip || !same(roundTrip, prepared.token)) {
      return { ok: false, status: 500, error: "A verificação de integridade do token salvo falhou. Tente novamente." };
    }

    return {
      ok: true,
      tokenStored: true,
      hasDiscordToken: true,
      tokenUpdated: true,
      discordBotId: confirmed.discord_bot_id || prepared.identity.botId,
      discordBotName: confirmed.discord_bot_name || prepared.identity.botName || null,
      message: "Token validado no Discord, criptografado, relido do banco e confirmado."
    };
  } catch (error) {
    console.error("Discord bot token persistence failed:", error?.name || "DatabaseError");
    return { ok: false, status: 500, error: "Não consegui confirmar a gravação do token no banco. O campo foi mantido para você tentar novamente." };
  }
}

async function createSession(userId, env) {
  const token = randomToken(); const hash = await sha(token);
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)")
    .bind(hash, userId, Date.now() + 30 * 86400000, Date.now()).run();
  return setCookie("bz_session", token, 30 * 86400);
}
async function currentUser(request, env) {
  const token = cookieMap(request).bz_session; if (!token) return null;
  const row = await env.DB.prepare("SELECT users.id,users.name,users.username,users.email,users.role,users.discord_id,users.discord_username,users.discord_linked_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?")
    .bind(await sha(token), Date.now()).first();
  return row || null;
}
function publicUser(user) { return { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role, discordLinked: !!user.discord_id, discordUsername: user.discord_username || null, discordLinkedAt: user.discord_linked_at || null }; }
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
    "deployments:read", "deployments:power", "deployments:write", "deployments:shell",
    "files:read", "files:write", "env:read", "env:write",
    "backups:read", "backups:write", "credits:spend"
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
function externalErrorText(value, depth = 0) {
  if (value === null || value === undefined) return "";
  if (depth > 5) return "Detalhes adicionais indisponíveis.";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    const items = value.map(item => externalErrorText(item, depth + 1)).filter(Boolean);
    return items.join("; ");
  }
  if (typeof value === "object") {
    for (const key of ["message", "error_description", "description", "detail", "reason", "title", "hint", "error"]) {
      if (value[key] !== undefined && value[key] !== value) {
        const message = externalErrorText(value[key], depth + 1);
        if (message) return message;
      }
    }
    try { return JSON.stringify(value).slice(0, 1400); }
    catch { return "A hospedagem retornou um erro em formato desconhecido."; }
  }
  return String(value);
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
  try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { error: raw.slice(0, 1400) }; }
  if (!response.ok || parsed?.ok === false) {
    const source = parsed?.error ?? parsed?.message ?? parsed?.detail ?? parsed;
    const reason = externalErrorText(source) || ("HTTP " + response.status);
    const hint = externalErrorText(parsed?.hint);
    throw new Error("Bot-Hosting · " + method + " " + path + " · HTTP " + response.status + ": " + reason + (hint ? " — " + hint : ""));
  }
  return parsed;
}
const CAOS_REQUIREMENTS = "discord.py[voice]==2.7.1\nyt-dlp>=2026.10.26\nimageio-ffmpeg>=0.8.1\n";
function runnerTemplate() {
  return String.raw`import json, os, signal, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = os.getenv("TZ", "America/Bahia")
ENABLED = os.getenv("CAOS_SCHEDULE_ENABLED", "0") == "1"
START = os.getenv("CAOS_SCHEDULE_START", "00:00")
END = os.getenv("CAOS_SCHEDULE_END", "23:59")
STATUS = Path("caos-status.json")
FATAL_STATUSES = {"token_error", "intents_error", "token_missing", "error"}
child = None
stop_requested = False
blocked = False
next_restart_at = 0.0

def write_status(status, **details):
    payload = {"status": status, "updatedAt": datetime.now(timezone.utc).isoformat(), **details}
    temp = STATUS.with_suffix(".json.tmp")
    try:
        temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temp.replace(STATUS)
    except OSError as exc:
        print("STATUS: não foi possível gravar estado: " + type(exc).__name__, flush=True)

def read_status():
    try:
        return json.loads(STATUS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def in_window():
    if not ENABLED:
        return True
    now = datetime.now(ZoneInfo(TZ)).strftime("%H:%M")
    if START < END:
        return START <= now < END
    return now >= START or now < END

def stop_child(reason="stopped"):
    global child
    current = child
    child = None
    if current and current.poll() is None:
        print("SUPERVISOR: encerrando CAOS (" + reason + ").", flush=True)
        current.terminate()
        try:
            current.wait(timeout=20)
        except subprocess.TimeoutExpired:
            current.kill()
            current.wait(timeout=5)
    write_status("offline", reason=reason)

def shutdown(_sig, _frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)
write_status("starting", supervisor=True)
print("BLACK ZONE supervisor iniciado; fuso=" + TZ + "; agenda=" + (START + "-" + END if ENABLED else "sempre online"), flush=True)

try:
    while not stop_requested:
        if blocked:
            time.sleep(5)
            continue

        desired = in_window()
        if not desired:
            if child is not None:
                stop_child("outside_schedule")
            else:
                write_status("offline", reason="outside_schedule")
        else:
            if child is not None and child.poll() is not None:
                exit_code = child.returncode
                child = None
                last_status = read_status()
                last_kind = str(last_status.get("status", ""))
                if last_kind in FATAL_STATUSES:
                    blocked = True
                    print("SUPERVISOR: início pausado por erro definitivo (" + last_kind + "). Corrija a configuração e reinicie o serviço.", flush=True)
                else:
                    write_status("restarting", reason="process_exited", exitCode=exit_code)
                    next_restart_at = time.monotonic() + 15
                    print("SUPERVISOR: CAOS encerrou com código " + str(exit_code) + "; nova tentativa em 15 segundos.", flush=True)

            if child is None and not blocked and time.monotonic() >= next_restart_at:
                write_status("starting", supervisor=True)
                print("SUPERVISOR: iniciando main.py.", flush=True)
                child = subprocess.Popen([sys.executable, "-u", "main.py"])
        time.sleep(5)
finally:
    stop_child("supervisor_shutdown")
    print("BLACK ZONE supervisor encerrado.", flush=True)
` ;
}


async function caosBundleVersion() {
  const payload = CAOS_MAIN_PY + "\n" + CAOS_REQUIREMENTS + "\n" + runnerTemplate();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  return b64(digest);
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
  const customProject = typeof bot.custom_project === "string" ? JSON.parse(bot.custom_project || "null") : (bot.custom_project || null);
  if (!customProject && bot.runtime !== "python") {
    throw new Error("Este projeto ainda não tem um pacote importado compatível. Envie um ZIP ou uma pasta de arquivos primeiro.");
  }
  if (!customProject && (!CAOS_MAIN_PY || CAOS_MAIN_PY.length < 10000)) {
    throw new Error("O pacote CAOS não foi incluído nesta publicação do servidor. Atualize o painel e tente novamente.");
  }
  if (!bot.discord_token_enc) throw new Error("Salve primeiro o Bot Token Discord deste projeto.");
  const token = await decryptSecret(bot.discord_token_enc, env);
  if (!token) throw new Error("Não consegui abrir o token protegido deste projeto. Salve novamente o token do Discord.");
  const identity = await validateDiscordBotToken(token);
  if (!identity.valid) throw new Error("O Discord não aceitou o token salvo. Abra Configurar token e módulos e atualize a credencial.");
  const duplicate = await env.DB.prepare("SELECT id,name FROM bots WHERE user_id=? AND discord_bot_id=? AND id<>? LIMIT 1")
    .bind(userId, identity.botId, bot.id).first();
  if (duplicate) throw new Error("Este mesmo bot Discord já está cadastrado no projeto \"" + String(duplicate.name || duplicate.id) + "\". Cada projeto precisa de um Bot Token próprio para evitar sessões duplicadas no Discord.");
  const central = await verificationBotSettings(env);
  if (central?.bot_id && String(central.bot_id) === identity.botId) {
    throw new Error("Este Bot Token também está reservado para o bot central do ADM. Use um bot Discord diferente neste projeto.");
  }

  const modules = typeof bot.modules === "string" ? JSON.parse(bot.modules || "{}") : (bot.modules || {});
  let deploymentId = bot.hosting_deployment_id || null;
  const isNewDeployment = !deploymentId;

  if (isNewDeployment) {
    const hosting = await env.DB.prepare("SELECT scope FROM hosting_connections WHERE user_id=?").bind(userId).first();
    const granted = String(hosting?.scope || "").split(/\s+/);
    if (!granted.includes("deployments:write") || !granted.includes("credits:spend")) {
      throw new Error("A hospedagem desta conta não recebeu as permissões deployments:write e credits:spend. Reconecte o Bot-Hosting em Configurações e autorize a criação de servidores.");
    }
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

  if (customProject) {
    const runtime = customProject.runtime === "nodejs" ? "nodejs" : "python";
    const runtimeVersion = runtime === "nodejs" ? "22" : "3.11";
    const entryFile = String(customProject.entryFile || "").replace(/^\/+/, "");
    if (!entryFile || entryFile.split("/").some(part => part === "..")) throw new Error("O pacote importado não tem um arquivo principal válido. Reenvie a pasta ou o ZIP.");
    await setHostEnv(userId, env, deploymentId, "DISCORD_TOKEN", token, true);
    await setHostEnv(userId, env, deploymentId, "BOT_TOKEN", token, true);
    await setHostEnv(userId, env, deploymentId, "TOKEN", token, true);
    await setHostEnv(userId, env, deploymentId, "APP_URL", "https://black-zone-estudio.vercel.app", false);
    await setHostEnv(userId, env, deploymentId, "BOT_NAME", bot.name || "Discord Bot", false);
    await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
      runtime, runtimeVersion, entryFile, startCommand: customProject.startCommand || null
    });
    await env.DB.prepare("UPDATE bots SET runtime=?,discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?")
      .bind(runtime, identity.botId, identity.botName || null, Date.now(), bot.id, userId).run();
    return { deploymentId, botId: identity.botId, botName: identity.botName || null, customProject: true, entryFile, runtime };
  }

  // Só reenviamos o pacote CAOS quando a versão instalada mudou.
  // Isso evita baixar e reinstalar as mesmas dependências a cada clique em Iniciar.
  const bundleVersion = await caosBundleVersion();
  let installedVersion = "";
  if (!isNewDeployment) {
    try {
      const current = await hostRequest(
        userId, env,
        "/deployments/" + encodeURIComponent(deploymentId) + "/files/content?path=%2Fcaos-version.txt"
      );
      installedVersion = String(current.content || "").trim();
    } catch {
      installedVersion = "";
    }
  }

  if (isNewDeployment || installedVersion !== bundleVersion) {
    const writeResult = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/writeMany", "POST", {
      files: [
        { path: "/main.py", content: CAOS_MAIN_PY, mode: "overwrite" },
        { path: "/requirements.txt", content: CAOS_REQUIREMENTS, mode: "overwrite" },
        { path: "/runner.py", content: runnerTemplate(), mode: "overwrite" },
        { path: "/caos-version.txt", content: bundleVersion, mode: "overwrite" }
      ]
    });
    if (Array.isArray(writeResult.failed) && writeResult.failed.length) {
      const failures = writeResult.failed.map(item => {
        const filePath = item?.path || item?.file || "arquivo";
        const reason = externalErrorText(item?.reason ?? item?.error ?? item?.message ?? item);
        return filePath + " — " + (reason || "falha sem detalhes");
      }).join("; ");
      throw new Error("Não consegui enviar todos os arquivos do CAOS: " + failures);
    }
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
    // null selects Bot-Hosting's Python runtime default, which installs
    // requirements.txt before launching the configured entry file.
    startCommand: null
  });
  await env.DB.prepare("UPDATE bots SET discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?")
    .bind(identity.botId, identity.botName || null, Date.now(), bot.id, userId).run();
  return {
    deploymentId,
    botId: identity.botId,
    botName: identity.botName || null,
    packageUpdated: isNewDeployment || installedVersion !== bundleVersion
  };
}
async function getOwnedBot(id, userId, env) {
  return env.DB.prepare(
    "SELECT id,name,runtime,state,modules,custom_project,discord_token_enc,discord_bot_id,discord_bot_name,hosting_deployment_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE id=? AND user_id=?"
  ).bind(id, userId).first();
}
function validClock(value) { return typeof value === "string" && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value); }
function safeVolumePath(value) {
  const raw = String(value || "/").trim();
  if (raw.length > 350 || raw.includes("\\") || raw.includes("\0") ||
      raw.split("/").some(part => part === "..")) {
    throw new Error("Caminho de arquivo inválido.");
  }
  const normalized = "/" + raw.split("/").filter(Boolean).join("/");
  return normalized === "" ? "/" : normalized;
}
async function scanImportedProject(userId, env, deploymentId) {
  const ignored = new Set([".git","node_modules",".venv","venv","__pycache__",".next","vendor"]);
  const imageExt = /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp)$/i;
  const queue = [{ path: "/", depth: 0 }];
  const seen = new Set();
  const files = [];
  let rootEntries = [];
  let directoryCount = 0;
  while (queue.length && files.length < 3500) {
    const item = queue.shift();
    if (seen.has(item.path) || item.depth > 8) continue;
    seen.add(item.path);
    const listing = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files?path=" + encodeURIComponent(item.path));
    const entries = Array.isArray(listing.entries) ? listing.entries : [];
    if (item.path === "/") rootEntries = entries;
    for (const e of entries) {
      const name = String(e?.name || "");
      if (!name || name === "." || name === "..") continue;
      const full = safeVolumePath((item.path === "/" ? "" : item.path) + "/" + name);
      if (e.type === "directory" || e.type === "folder") {
        if (ignored.has(name)) continue;
        directoryCount++;
        if (item.depth < 8) queue.push({ path: full, depth: item.depth + 1 });
      } else if (e.type === "file") files.push(full);
    }
  }
  if (queue.length) throw new Error("O pacote contém pastas demais para uma análise segura. Remova node_modules, .git e ambientes virtuais e envie novamente.");
  const rootFiles = rootEntries.filter(e => e?.type === "file");
  const rootDirs = rootEntries.filter(e => (e?.type === "directory" || e?.type === "folder") && !ignored.has(String(e.name || "")));
  if (!rootFiles.length && rootDirs.length === 1) {
    const wrapper = String(rootDirs[0].name || "");
    const inner = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files?path=" + encodeURIComponent("/" + wrapper));
    const children = (Array.isArray(inner.entries) ? inner.entries : []).filter(e => e?.name && e.name !== "." && e.name !== "..").map(e => wrapper + "/" + String(e.name));
    if (children.length) {
      await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/move", "POST", { files: children, to: "/" });
      await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/delete", "POST", { root: "/", files: [wrapper] });
      return scanImportedProject(userId, env, deploymentId);
    }
  }
  const relative = files.map(p => p.replace(/^\//, ""));
  const pyPriority = ["main.py","bot.py","run.py","app.py","index.py","start.py"];
  const jsPriority = ["index.js","bot.js","main.js","app.js","src/index.js","src/bot.js","index.mjs","bot.mjs"];
  const score = (p, pref) => {
    const exact = pref.indexOf(p.toLowerCase());
    if (exact >= 0) return exact;
    const tail = pref.indexOf(p.toLowerCase().split("/").pop());
    return tail < 0 ? 999 : 30 + tail;
  };
  const py = relative.filter(p => /\.py$/i.test(p)).sort((a,b)=>score(a,pyPriority)-score(b,pyPriority));
  const js = relative.filter(p => /\.(?:js|mjs|cjs)$/i.test(p)).sort((a,b)=>score(a,jsPriority)-score(b,jsPriority));
  let pkg = null;
  const packagePath = relative.find(p => p.toLowerCase() === "package.json");
  if (packagePath) {
    try {
      const r = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/content?path=" + encodeURIComponent("/" + packagePath));
      pkg = JSON.parse(String(r.content || "{}"));
    } catch {}
  }
  let runtime = "python", entryFile = py[0] || "", startCommand = null;
  const declaredMain = typeof pkg?.main === "string" ? pkg.main.replace(/^\.\//, "") : "";
  if (js.length && (!py.length || pkg)) {
    runtime = "nodejs";
    entryFile = (declaredMain && relative.includes(declaredMain) ? declaredMain : "") || js[0];
    if (pkg?.scripts?.start) startCommand = "npm install && npm start";
  }
  if (!entryFile) {
    return {
      ok: false, needsEntryFile: true, fileCount: files.length,
      imageCount: files.filter(p => imageExt.test(p)).length,
      candidates: [...py.slice(0,12).map(path => ({path,runtime:"python"})), ...js.slice(0,12).map(path => ({path,runtime:"nodejs"}))],
      error: "Os arquivos foram enviados, mas não encontrei automaticamente o arquivo principal. Procure main.py, bot.py, index.js ou bot.js."
    };
  }
  return {
    ok: true, runtime, entryFile, startCommand,
    dependencyFile: runtime === "nodejs" ? (relative.includes("package.json") ? "package.json" : null) : (relative.includes("requirements.txt") ? "requirements.txt" : null),
    fileCount: files.length, directoryCount, imageCount: files.filter(p => imageExt.test(p)).length
  };
}

function recentDiscordStatus(status, afterTimestamp = 0) {
  if (!status || status.status !== "online" || !status.updatedAt) return false;
  const updatedAt = Date.parse(status.updatedAt);
  return Number.isFinite(updatedAt) && updatedAt >= afterTimestamp && Date.now() - updatedAt <= 90000;
}
async function readDiscordRuntimeStatus(userId, env, deploymentId) {
  try {
    const file = await hostRequest(
      userId, env,
      "/deployments/" + encodeURIComponent(deploymentId) + "/files/content?path=%2Fcaos-status.json"
    );
    if (!file?.content) return null;
    return JSON.parse(file.content);
  } catch {
    return null;
  }
}


async function startDiscord(request, env) {
  const oauth = await discordOAuthCredentials(env);
  if (!oauth.clientId || !oauth.clientSecret) return reply({ error: "Configure o OAuth2 do Discord no painel administrativo do Estúdio." }, 503);
  const state = randomToken(24);
  await env.DB.prepare("INSERT INTO discord_states (state,expires_at) VALUES (?,?)").bind(state, Date.now() + 600000).run();
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", oauth.clientId); url.searchParams.set("redirect_uri", new URL("/api/auth/discord/callback", request.url).href);
  url.searchParams.set("response_type", "code"); url.searchParams.set("scope", "identify email"); url.searchParams.set("state", state);
  return new Response(null, { status: 302, headers: { location: url.href, "set-cookie": setCookie("bz_oauth_state", state, 600) } });
}

async function startDiscordAccountLink(request, user, env) {
  const oauth = await discordOAuthCredentials(env);
  if (!oauth.clientId || !oauth.clientSecret) {
    return { error: "O login OAuth do Discord ainda não foi configurado pelo proprietário do Estúdio.", status: 503 };
  }
  const state = randomToken(24);
  const codeVerifier = randomToken(48);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  await env.DB.prepare(
    "INSERT INTO discord_link_states (state,user_id,code_verifier,expires_at) VALUES (?,?,?,?)"
  ).bind(state, user.id, codeVerifier, Date.now() + 10 * 60 * 1000).run();
  const redirectUri = new URL("/api/discord/link/callback", request.url).href;
  const authorizationUrl = new URL("https://discord.com/oauth2/authorize");
  authorizationUrl.searchParams.set("client_id", oauth.clientId);
  authorizationUrl.searchParams.set("redirect_uri", redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "identify");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set("prompt", "consent");
  return {
    authorizationUrl: authorizationUrl.href,
    cookie: setCookie("bz_discord_link_state", state, 600)
  };
}

async function discordAccountLinkCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (url.searchParams.get("error")) {
    return new Response(null, {
      status: 302,
      headers: {
        location: new URL("/?discord=error", request.url).href,
        "set-cookie": clearCookie("bz_discord_link_state")
      }
    });
  }
  const issuer = url.searchParams.get("iss");
  if (issuer && issuer !== "https://discord.com") {
    return reply({ error: "O emissor OAuth retornado não corresponde ao Discord." }, 400);
  }
  const cookieState = cookieMap(request).bz_discord_link_state;
  if (!code || !state || !cookieState || !same(state, cookieState)) {
    return reply({ error: "A confirmação de segurança da vinculação expirou. Comece novamente." }, 400, {
      "set-cookie": clearCookie("bz_discord_link_state")
    });
  }
  const saved = await env.DB.prepare(
    "SELECT user_id,code_verifier FROM discord_link_states WHERE state=? AND expires_at>?"
  ).bind(state, Date.now()).first();
  await env.DB.prepare("DELETE FROM discord_link_states WHERE state=?").bind(state).run();
  const signedInUser = await currentUser(request, env);
  if (!saved || !signedInUser || saved.user_id !== signedInUser.id) {
    return reply({ error: "A sessão do Estúdio expirou ou mudou. Entre novamente e refaça a vinculação." }, 401, {
      "set-cookie": clearCookie("bz_discord_link_state")
    });
  }

  const oauth = await discordOAuthCredentials(env);
  if (!oauth.clientId || !oauth.clientSecret) return reply({ error: "O OAuth2 do Discord ainda não está configurado." }, 503);
  const redirectUri = new URL("/api/discord/link/callback", request.url).href;
  const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      client_id: oauth.clientId,
      client_secret: oauth.clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: saved?.code_verifier || ""
    }),
    signal: AbortSignal.timeout(12000)
  });
  const tokenData = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !tokenData.access_token) {
    return reply({ error: "O Discord não concluiu a autorização da conta. Tente novamente." }, 401, {
      "set-cookie": clearCookie("bz_discord_link_state")
    });
  }

  const profileResponse = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { authorization: "Bearer " + tokenData.access_token, accept: "application/json" },
    signal: AbortSignal.timeout(12000)
  });
  const profile = await profileResponse.json().catch(() => ({}));
  if (!profileResponse.ok || !profile.id || !profile.username) {
    return reply({ error: "Não consegui confirmar o perfil do Discord autorizado." }, 502, {
      "set-cookie": clearCookie("bz_discord_link_state")
    });
  }

  try {
    const basic = btoa(String(oauth.clientId) + ":" + String(oauth.clientSecret));
    await fetch("https://discord.com/api/oauth2/token/revoke", {
      method: "POST",
      headers: {
        authorization: "Basic " + basic,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json"
      },
      body: new URLSearchParams({
        token: tokenData.access_token,
        token_type_hint: "access_token"
      }),
      signal: AbortSignal.timeout(8000)
    });
  } catch (error) {
    console.warn("Discord link access-token revocation was not confirmed:", error?.name || "Error");
  }

  const conflict = await env.DB.prepare(
    "SELECT id FROM users WHERE discord_id=? AND id<>?"
  ).bind(String(profile.id), signedInUser.id).first();
  if (conflict) {
    return reply({ error: "Esta conta Discord já está vinculada a outro usuário do Estúdio." }, 409, {
      "set-cookie": clearCookie("bz_discord_link_state")
    });
  }

  const discordUsername = String(profile.global_name || profile.username).slice(0, 100);
  await env.DB.prepare(
    "UPDATE users SET discord_id=?,discord_username=?,discord_linked_at=? WHERE id=?"
  ).bind(String(profile.id), discordUsername, Date.now(), signedInUser.id).run();
  return new Response(null, {
    status: 302,
    headers: {
      location: new URL("/?discord=linked", request.url).href,
      "set-cookie": clearCookie("bz_discord_link_state")
    }
  });
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
  const oauth = await discordOAuthCredentials(env);
  if (!oauth.clientId || !oauth.clientSecret) return reply({ error: "Configure o OAuth2 do Discord no painel administrativo." }, 503);
  const url = new URL(request.url); const code = url.searchParams.get("code"); const state = url.searchParams.get("state");
  const cookieState = cookieMap(request).bz_oauth_state;
  if (!code || !state || !cookieState || !same(state, cookieState)) return reply({ error: "Validação OAuth inválida. Tente novamente." }, 400);
  const saved = await env.DB.prepare("SELECT state FROM discord_states WHERE state=? AND expires_at>?").bind(state, Date.now()).first();
  await env.DB.prepare("DELETE FROM discord_states WHERE state=?").bind(state).run();
  if (!saved) return reply({ error: "A sessão de autenticação expirou." }, 400);
  const redirectUri = new URL("/api/auth/discord/callback", request.url).href;
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: oauth.clientId, client_secret: oauth.clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri })
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) return reply({ error: "O Discord não autorizou o acesso." }, 401);
  const meRes = await fetch("https://discord.com/api/users/@me", { headers: { authorization: "Bearer " + tokenData.access_token } });
  const me = await meRes.json();
  if (!meRes.ok || !me.id || !me.email || !me.verified) return reply({ error: "O Discord precisa fornecer um e-mail verificado. Entre com e-mail e senha para vincular a conta." }, 400);
  let user = await env.DB.prepare("SELECT * FROM users WHERE discord_id=?").bind(String(me.id)).first();
  if (!user) {
    user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(String(me.email).toLowerCase()).first();
    if (user) await env.DB.prepare("UPDATE users SET discord_id=?,discord_username=?,discord_linked_at=? WHERE id=?").bind(String(me.id), String(me.global_name || me.username || "Discord").slice(0,100), Date.now(), user.id).run();
    else {
      const username = (String(me.username || "discord").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 24) || "discord") + "_" + String(me.id).slice(-4);
      const id = randomToken(16); const pass = await hashPassword(randomToken(36)); const name = String(me.global_name || me.username || "Discord User").slice(0, 80);
      await env.DB.prepare("INSERT INTO users (id,name,username,email,password_hash,role,discord_id,discord_username,discord_linked_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(id, name, username, String(me.email).toLowerCase(), pass, "member", String(me.id), String(me.global_name || me.username || "Discord").slice(0,100), Date.now(), Date.now()).run();
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
    let databaseError = null;
    if (env.DB) {
      try {
        const probe = await env.DB.prepare("SELECT ?::text AS check_value").bind("black-zone-estudio").first();
        databaseQuery = probe?.check_value === "black-zone-estudio";
        if (!databaseQuery) databaseError = "A consulta de teste não retornou o valor esperado.";
      } catch (error) { databaseError = error?.message || "A consulta ao banco falhou."; }
    }
    let oauth = { clientId: "", clientSecret: "" };
    try { oauth = await discordOAuthCredentials(env); } catch {}
    const secretsConfigured = {
      gate: !!env.APP_GATE_PHRASE,
      session: !!env.APP_SESSION_SECRET,
      encryption: !!env.APP_ENCRYPTION_KEY,
      discordOAuth: !!(oauth.clientId && oauth.clientSecret)
    };
    const essentialReady = !!env.DB && databaseQuery && secretsConfigured.session && secretsConfigured.encryption;
    return reply({
      ok: true, operational: essentialReady, state: essentialReady ? "operational" : "degraded",
      service: "black-zone-estudio", databaseConfigured: !!env.DB, databaseQuery, databaseError,
      secretsConfigured,
      checks: { api: true, database: !!env.DB && databaseQuery, session: secretsConfigured.session, encryption: secretsConfigured.encryption }
    });
  }

    if (path === "/hosting/callback" && request.method === "GET") return await hostingCallback(request, env);
  if (!env.DB) return reply({ error: "Banco de dados indisponível. Conecte o Neon ao projeto Vercel para habilitar cadastro e login." }, 503);
  try {
    if (path === "/verification/start" && request.method === "GET") return await verificationStart(request, env);
    if (path === "/verification/callback" && request.method === "GET") return await verificationCallback(request, env);
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
    if (path === "/discord/link/start" && request.method === "GET") {
      const required = await requireUser(request, env);
      if (required.error) return required.error;
      const result = await startDiscordAccountLink(request, required.user, env);
      if (result.error) return reply({ error: result.error }, result.status);
      return reply({ authorizationUrl: result.authorizationUrl }, 200, {
        "set-cookie": result.cookie
      });
    }
    if (path === "/discord/link/callback" && request.method === "GET") {
      return await discordAccountLinkCallback(request, env);
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


    if (path === "/admin/verification-bot/status" && request.method === "GET") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await verificationBotSettings(env);
      let runtime = { state: "not_deployed", online: false, deploymentId: null };
      if (settings?.hosting_deployment_id) runtime = await readVerificationBotStatus(user.id, env, settings);
      const oauth = await discordOAuthCredentials(env);
      const hosting = await env.DB.prepare("SELECT user_id,scope FROM hosting_connections WHERE user_id=?").bind(user.id).first();
      const hostingScopes = String(hosting?.scope || "").split(/\s+/).filter(Boolean);
      let hostingDiagnostic = { ok: false, message: hosting ? "Testando conexão com a hospedagem..." : "Conta Bot-Hosting não conectada." };
      if (hosting) {
        try {
          const probe = await hostRequest(user.id, env, "/deployments?brief=true");
          hostingDiagnostic = {
            ok: true,
            message: "Conexão com Bot-Hosting confirmada.",
            deploymentsCount: Array.isArray(probe.deployments) ? probe.deployments.length : 0
          };
        } catch (error) {
          hostingDiagnostic = { ok: false, message: error.message || "A hospedagem recusou a conexão." };
        }
      }
      return reply({
        configured: !!settings?.bot_token_enc && !!settings?.invite_url,
        oauthRedirectUri: new URL("/api/verification/callback", request.url).href,
        hasToken: !!settings?.bot_token_enc,
        botId: settings?.bot_id || null,
        botName: settings?.bot_name || null,
        inviteUrl: settings?.invite_url || "",
        deploymentId: settings?.hosting_deployment_id || null,
        updatedAt: settings?.updated_at || null,
        oauthConfigured: !!(oauth.clientId && oauth.clientSecret),
        clientId: settings?.oauth_client_id || oauth.clientId || "",
        hostingConnected: !!hosting,
        hostingCanCreate: hostingScopes.includes("credits:spend") && hostingScopes.includes("deployments:write"),
        hostingMissingScopes: ["deployments:write", "credits:spend"].filter(scope => !hostingScopes.includes(scope)),
        hostingDiagnostic,
        runtime
      });
    }
    if (path === "/admin/verification-bot/config" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const result = await saveVerificationBotSettings(user, await body(request), env);
      if (!result.ok) return reply({ error: result.error }, result.status);
      return reply(result);
    }
    if (path === "/admin/verification-bot/oauth" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const result = await saveVerificationOAuthSettings(user, await body(request), env);
      if (!result.ok) return reply({ error: result.error }, result.status);
      return reply(result);
    }
    if (path === "/admin/verification-bot/power" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const b = await body(request);
      const action = String(b.action || "").toLowerCase();
      if (!["start","stop","restart"].includes(action)) return reply({ error: "Ação inválida. Use iniciar, reiniciar ou parar." }, 400);
      const settings = await verificationBotSettings(env);
      if (!settings?.bot_token_enc) return reply({ error: "Configure o Bot Token na seção de verificação primeiro." }, 409);
      try {
        let deploymentId = settings.hosting_deployment_id;
        if (action === "stop") {
          if (!deploymentId) return reply({ ok: true, state: "offline", message: "O bot ainda não possui implantação." });
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "stop", waitSeconds: 0 });
          await env.DB.prepare("UPDATE verification_bot_settings SET state='offline',updated_at=? WHERE id='main'").bind(Date.now()).run();
          return reply({ ok: true, state: "offline" });
        }
        const prepared = await ensureVerificationBotDeployment(user.id, env);
        deploymentId = prepared.deploymentId;
        let applied = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/apply", "POST", { restart: true, waitSeconds: 45 });
        const state = String(applied.state || "").toLowerCase();
        if (["offline","stopped","unknown",""].includes(state)) {
          const started = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "start", waitSeconds: 45 });
          applied = { ...applied, ...started };
        }
        await env.DB.prepare("UPDATE verification_bot_settings SET state='starting',updated_at=? WHERE id='main'").bind(Date.now()).run();
        return reply({ ok: true, action, state: String(applied.state || "starting").toLowerCase(), deploymentId, botId: prepared.botId, botName: prepared.botName, message: "Inicialização solicitada. Confira o status enquanto o Discord conecta." });
      } catch (error) {
        return reply({ error: error.message || "Não foi possível iniciar o bot de verificação." }, 502);
      }
    }

    if (path === "/hosting/connect" && request.method === "GET") {
      try {
        return reply({ authorizationUrl: await hostingConnectUrl(request, user, env) });
      } catch (error) {
        return reply({ error: error.message || "Não foi possível preparar a autorização do Bot-Hosting." }, 502);
      }
    }
    if (path === "/hosting/status" && request.method === "GET") {
      const row = await env.DB.prepare("SELECT expires_at,scope FROM hosting_connections WHERE user_id=?").bind(user.id).first();
      const scopes = String(row?.scope || "").split(/\s+/).filter(Boolean);
      const missingScopes = ["deployments:write", "credits:spend"].filter(scope => !scopes.includes(scope));
      return reply({ connected: !!row, expiresAt: row?.expires_at || null, scope: row?.scope || "", canCreateDeployments: missingScopes.length === 0, missingScopes });
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
      if (!ownedBot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);

      // Backward-compatible: older clients may still send a token together
      // with modules. New clients save the token through /bot-token separately.
      const newToken = String(b.discordToken || "").trim();
      let tokenResult = null;
      if (newToken) {
        tokenResult = await saveDiscordBotToken(id, user.id, newToken, env);
        if (!tokenResult.ok) return reply({ error: tokenResult.error }, tokenResult.status);
      } else if (ownedBot.discord_token_enc) {
        // A blank token means "leave unchanged", not "delete".
        let existingToken = null;
        try { existingToken = await decryptSecret(ownedBot.discord_token_enc, env); } catch {}
        if (!existingToken) {
          return reply({
            error: "O token já registrado não pode ser aberto com a chave de criptografia atual. Salve um Bot Token novo antes de continuar."
          }, 409);
        }
      }

      const allowed = ["music","tickets","attendance","team","goals","warnings","recruitment","logs"];
      const modules = {};
      for (const key of allowed) modules[key] = !!(b.modules && b.modules[key]);
      await env.DB.prepare(
        "UPDATE bots SET modules=?::jsonb,updated_at=? WHERE id=? AND user_id=?"
      ).bind(JSON.stringify(modules), Date.now(), id, user.id).run();

      const confirmed = await env.DB.prepare(
        "SELECT discord_token_enc,modules,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
      ).bind(id, user.id).first();
      const tokenStored = !!confirmed?.discord_token_enc;
      if (tokenStored) {
        let roundTrip = null;
        try { roundTrip = await decryptSecret(confirmed.discord_token_enc, env); } catch {}
        if (!roundTrip) {
          return reply({
            error: "Os módulos foram enviados, mas a integridade do token guardado não pôde ser confirmada. Salve um Bot Token novo."
          }, 409);
        }
      }

      const savedModules = typeof confirmed?.modules === "string"
        ? JSON.parse(confirmed.modules || "{}")
        : (confirmed?.modules || {});
      return reply({
        ok: true,
        tokenStored,
        hasDiscordToken: tokenStored,
        tokenUpdated: !!tokenResult?.tokenUpdated,
        modules: savedModules,
        discordBotId: confirmed?.discord_bot_id || tokenResult?.discordBotId || null,
        discordBotName: confirmed?.discord_bot_name || tokenResult?.discordBotName || null,
        message: tokenResult?.tokenUpdated
          ? "Token validado e salvo; módulos atualizados."
          : (tokenStored
            ? "Módulos salvos; o token anterior foi mantido."
            : "Módulos salvos. Nenhum token foi alterado.")
      });
    }

    if (path === "/bot-token" && request.method === "POST") {
      const b = await body(request);
      const id = String(b.botId || "").trim();
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) {
        return reply({ error: "Projeto inválido. Atualize a lista de bots." }, 400);
      }
      const result = await saveDiscordBotToken(id, user.id, b.discordToken, env);
      if (!result.ok) return reply({ error: result.error }, result.status);
      return reply(result);
    }

    if (path === "/bot-token/status" && request.method === "GET") {
      const id = String(url.searchParams.get("botId") || "").trim();
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) {
        return reply({ error: "Projeto inválido. Atualize a lista de bots." }, 400);
      }
      const ownedBot = await env.DB.prepare(
        "SELECT id,discord_token_enc,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
      ).bind(id, user.id).first();
      if (!ownedBot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);
      if (!ownedBot.discord_token_enc) {
        return reply({ ok: true, hasDiscordToken: false, valid: false, status: "missing" });
      }

      let savedToken = null;
      try {
        savedToken = await decryptSecret(ownedBot.discord_token_enc, env);
      } catch {
        savedToken = null;
      }
      if (!savedToken) {
        return reply({
          ok: true, hasDiscordToken: true, valid: false, status: "decrypt_failed",
          error: "Existe um registro de token, mas não foi possível abrir com a chave de criptografia atual. Cole novamente o Bot Token."
        }, 409);
      }

      const identity = await validateDiscordBotToken(savedToken);
      if (identity.unavailable) {
        return reply({
          ok: false, hasDiscordToken: true, valid: false, status: "discord_unavailable",
          error: identity.reason === "rate_limited"
            ? "O Discord limitou a verificação. Aguarde um minuto e tente novamente."
            : "Não consegui consultar o Discord agora. O token continua protegido no banco, mas a validação ficou pendente."
        }, 503);
      }
      if (!identity.valid) {
        return reply({
          ok: true, hasDiscordToken: true, valid: false, status: "discord_rejected",
          error: "O Discord não reconheceu o token atualmente salvo. Gere um novo Bot Token no Developer Portal e salve novamente."
        }, 200);
      }

      if (identity.botId !== ownedBot.discord_bot_id || identity.botName !== ownedBot.discord_bot_name) {
        await env.DB.prepare(
          "UPDATE bots SET discord_bot_id=?,discord_bot_name=?,updated_at=? WHERE id=? AND user_id=?"
        ).bind(identity.botId, identity.botName || null, Date.now(), id, user.id).run();
      }
      return reply({
        ok: true, hasDiscordToken: true, valid: true, status: "verified",
        discordBotId: identity.botId, discordBotName: identity.botName || null,
        message: "O token salvo foi aberto com segurança e aceito pelo Discord."
      });
    }

    if (path === "/bots" && request.method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT id,name,runtime,state,modules,custom_project,created_at,updated_at,(discord_token_enc IS NOT NULL) AS has_discord_token,discord_bot_id,discord_bot_name,hosting_deployment_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE user_id=? ORDER BY created_at DESC"
      ).bind(user.id).all();
      return reply({ deployments: rows.map(row => ({
        ...row,
        modules: typeof row.modules === "string" ? JSON.parse(row.modules) : row.modules,
        customProject: typeof row.custom_project === "string" ? JSON.parse(row.custom_project || "null") : (row.custom_project || null),
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
      const runtime = "python";
      if (b.runtime && b.runtime !== "python") {
        return reply({ error: "O executor automático atual está preparado para o CAOS em Python 3.11." }, 400);
      }
      if (name.length < 2) return reply({ error: "Digite um nome com pelo menos 2 caracteres." }, 400);

      // Create the project first; Discord credentials have their own save flow.
      const rawToken = String(b.discordToken || "").trim();
      let prepared = null;
      if (rawToken) {
        prepared = await prepareDiscordBotToken(rawToken, env);
        if (!prepared.ok) return reply({ error: prepared.error }, prepared.status);
      }

      const id = randomToken(12);
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO bots (id,user_id,name,runtime,state,modules,discord_token_enc,discord_bot_id,discord_bot_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        id, user.id, name, runtime, "draft", JSON.stringify({}),
        prepared?.encryptedToken || null,
        prepared?.identity.botId || null,
        prepared?.identity.botName || null,
        now, now
      ).run();

      const persisted = await env.DB.prepare(
        "SELECT discord_token_enc,discord_bot_id,discord_bot_name FROM bots WHERE id=? AND user_id=?"
      ).bind(id, user.id).first();
      if (!persisted) {
        return reply({ error: "O projeto não apareceu no banco depois da criação. Atualize a lista e tente novamente." }, 500);
      }
      if (prepared) {
        const tokenRoundTrip = await decryptSecret(persisted.discord_token_enc, env);
        if (!tokenRoundTrip || !same(tokenRoundTrip, prepared.token)) {
          await env.DB.prepare("DELETE FROM bots WHERE id=? AND user_id=?").bind(id, user.id).run();
          return reply({ error: "O projeto foi criado, mas o banco não confirmou a gravação do token. Tente novamente." }, 500);
        }
      }

      return reply({
        id, name, runtime, state: "draft", modules: {},
        hasDiscordToken: !!prepared,
        discordBotId: persisted.discord_bot_id || null,
        discordBotName: persisted.discord_bot_name || null,
        executionAvailable: false,
        message: prepared
          ? "Projeto criado e token Discord armazenado com segurança."
          : "Projeto criado. Agora salve e valide o Bot Token para poder iniciar."
      }, 201);
    }

    const match = path.match(/^\/bots\/([A-Za-z0-9_-]{1,80})(?:\/(logs|power|upload-url|extract|import|config|resources|files|shell|schedule|diagnose|backups)(?:\/([A-Za-z0-9._-]{1,120})(?:\/(restore))?)?)?$/);
    if (match) {
      const id = match[1];
      const action = match[2] || "";
      const subPath = match[3] || "";
      const suffix = match[4] || "";
      const bot = await getOwnedBot(id, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);

      if (!action && request.method === "DELETE") {
        let deploymentDeleted = false;
        if (bot.hosting_deployment_id) {
          const otherReference = await env.DB.prepare("SELECT id FROM bots WHERE hosting_deployment_id=? AND id<>? LIMIT 1").bind(bot.hosting_deployment_id, id).first();
          const centralSettings = await verificationBotSettings(env);
          const usedByVerificationBot = String(centralSettings?.hosting_deployment_id || "") === String(bot.hosting_deployment_id);
          if (!otherReference && !usedByVerificationBot) {
            const connection = await env.DB.prepare("SELECT user_id FROM hosting_connections WHERE user_id=?").bind(user.id).first();
            if (!connection) return reply({ error: "Conecte o Bot-Hosting antes de excluir este bot. Assim posso parar e remover também a implantação, sem deixar recursos abandonados." }, 409);
            try {
              await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/power", "POST", { action: "stop", waitSeconds: 10 });
              await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id), "DELETE");
              deploymentDeleted = true;
            } catch (error) {
              return reply({ error: "Não consegui remover a implantação da hospedagem. O projeto continua salvo no painel. " + (error.message || ""), code: "deployment_delete_failed" }, 502);
            }
          }
        }
        await env.DB.prepare("DELETE FROM bots WHERE id=? AND user_id=?").bind(id, user.id).run();
        return reply({ ok: true, deleted: true, deploymentDeleted, sharedDeploymentRetained: !!bot.hosting_deployment_id && !deploymentDeleted });
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
        let discordStatus = null;
        if (bot.hosting_deployment_id) {
          try {
            runtimeInfo = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0");
            state = runtimeInfo.state || state;
          } catch (error) {
            runtimeInfo = { error: error.message };
          }
          discordStatus = await readDiscordRuntimeStatus(user.id, env, bot.hosting_deployment_id);
        }
        const scheduleAllowed = !bot.schedule_enabled ||
          isInsideSchedule(bot.schedule_start || "00:00", bot.schedule_end || "23:59", bot.schedule_timezone || "America/Bahia");
        const discordOnline = state === "running" && scheduleAllowed && recentDiscordStatus(discordStatus);
        const modules = typeof bot.modules === "string" ? JSON.parse(bot.modules || "{}") : (bot.modules || {});
        return reply({
          id: bot.id, name: bot.name, runtime: bot.runtime, state,
          modules, customProject: typeof bot.custom_project === "string" ? JSON.parse(bot.custom_project || "null") : (bot.custom_project || null),
          hasDiscordToken: hasToken,
          discordBotId, discordBotName,
          hostingDeploymentId: bot.hosting_deployment_id || null,
          scheduleEnabled: !!bot.schedule_enabled,
          scheduleActiveNow: scheduleAllowed,
          botOnlineNow: discordOnline,
          discordOnline,
          discordStatus: discordStatus ? {
            status: discordStatus.status,
            updatedAt: discordStatus.updatedAt || null,
            guilds: Number(discordStatus.guilds || 0),
            commandsTotal: Number(discordStatus.commandsTotal || 0),
            commandsRegistered: Number(discordStatus.commandsRegistered || 0),
            commandsSyncedGuilds: Number(discordStatus.commandsSyncedGuilds || 0),
            commandSyncErrors: Array.isArray(discordStatus.commandSyncErrors) ? discordStatus.commandSyncErrors : [],
            error: discordStatus.error || null
          } : null,
          scheduleStart: bot.schedule_start || "00:00",
          scheduleEnd: bot.schedule_end || "23:59",
          scheduleTimezone: bot.schedule_timezone || "America/Bahia",
          guildId: "",
          executionAvailable: !!bot.hosting_deployment_id,
          runtimeInfo
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
        await env.DB.prepare(
          "UPDATE bots SET schedule_enabled=?,schedule_start=?,schedule_end=?,schedule_timezone='America/Bahia',guild_id=NULL,updated_at=? WHERE id=? AND user_id=?"
        ).bind(enabled, startClock, endClock, Date.now(), id, user.id).run();
        if (bot.hosting_deployment_id) {
          await setHostEnv(user.id, env, bot.hosting_deployment_id, "CAOS_SCHEDULE_ENABLED", enabled ? "1" : "0", false);
          await setHostEnv(user.id, env, bot.hosting_deployment_id, "CAOS_SCHEDULE_START", startClock, false);
          await setHostEnv(user.id, env, bot.hosting_deployment_id, "CAOS_SCHEDULE_END", endClock, false);
          const live = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0");
          if ((live.state || live.deployment?.state) === "running") {
            await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/power", "POST", { action: "restart", waitSeconds: 35 });
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
        const requestStartedAt = Date.now();
        try {
          if (signal === "start" || signal === "restart") {
            const provisioned = await ensureBotDeployment(bot, user.id, env);
            deploymentId = provisioned.deploymentId;
            botId = provisioned.botId;
          }
          if (!deploymentId) return reply({ error: "Este bot ainda não tem um servidor de execução." }, 409);

          if (signal !== "stop") {
            await hostRequest(
              user.id, env,
              "/deployments/" + encodeURIComponent(deploymentId) + "/files/content",
              "POST",
              {
                path: "/caos-status.json",
                content: JSON.stringify({
                  status: "starting",
                  updatedAt: new Date(requestStartedAt).toISOString(),
                  source: "black-zone-estudio"
                }),
                mode: "overwrite"
              }
            );
          }

          let result = null;
          if (signal === "stop") {
            result = await hostRequest(
              user.id, env,
              "/deployments/" + encodeURIComponent(deploymentId) + "/power",
              "POST",
              { action: "stop", waitSeconds: 0 }
            );
          } else {
            // Apply starts the updated runtime. Return quickly: dependency installation
            // can take minutes, so the browser follows state/logs in separate requests.
            result = await hostRequest(
              user.id, env,
              "/deployments/" + encodeURIComponent(deploymentId) + "/apply",
              "POST",
              { restart: true, waitSeconds: 0 }
            );
            let appliedState = String(result.state || "").toLowerCase();
            if (["offline","stopped","unknown",""].includes(appliedState)) {
              const startResult = await hostRequest(
                user.id, env,
                "/deployments/" + encodeURIComponent(deploymentId) + "/power",
                "POST",
                { action: "start", waitSeconds: 0 }
              );
              result = {
                ...result,
                ...startResult,
                logs: [
                  ...(Array.isArray(result.logs) ? result.logs : []),
                  ...(Array.isArray(startResult.logs) ? startResult.logs : [])
                ]
              };
            }
          }

          const actualState = String(result.state || (signal === "stop" ? "offline" : "starting")).toLowerCase();
          await env.DB.prepare("UPDATE bots SET state=?,hosting_deployment_id=?,updated_at=? WHERE id=? AND user_id=?")
            .bind(actualState, deploymentId, Date.now(), id, user.id).run();

          const discordStatus = signal === "stop"
            ? null
            : await readDiscordRuntimeStatus(user.id, env, deploymentId);
          const scheduleAllowed = !bot.schedule_enabled ||
            isInsideSchedule(bot.schedule_start || "00:00", bot.schedule_end || "23:59", bot.schedule_timezone || "America/Bahia");
          const discordOnline = signal !== "stop" &&
            actualState === "running" &&
            scheduleAllowed &&
            recentDiscordStatus(discordStatus, requestStartedAt);

          const logs = (Array.isArray(result.logs) ? result.logs : []).slice(-100);
          if (signal !== "stop" && ["offline","stopped","unknown"].includes(actualState)) {
            return reply({
              ok: false,
              action: signal,
              state: actualState,
              deploymentId,
              discordOnline: false,
              discordStatus: discordStatus ? {
                status: discordStatus.status,
                updatedAt: discordStatus.updatedAt || null,
                guilds: Number(discordStatus.guilds || 0),
                commandsTotal: Number(discordStatus.commandsTotal || 0),
                commandsRegistered: Number(discordStatus.commandsRegistered || 0),
                commandsSyncedGuilds: Number(discordStatus.commandsSyncedGuilds || 0),
                commandSyncErrors: Array.isArray(discordStatus.commandSyncErrors) ? discordStatus.commandSyncErrors : [],
                error: discordStatus.error || null
              } : null,
              logs,
              hint: result.hint || "A hospedagem não iniciou o processo. Confira os logs de instalação e inicialização."
            }, 502);
          }

          await env.DB.prepare("UPDATE bots SET state=?,hosting_deployment_id=?,updated_at=? WHERE id=? AND user_id=?")
            .bind(signal === "stop" ? "stopped" : actualState, deploymentId, Date.now(), id, user.id).run();

          return reply({
            ok: true,
            action: signal,
            state: signal === "stop" ? "stopped" : actualState,
            installing: !!result.installing,
            deploymentId,
            discordBotId: botId || null,
            commandsSynced: Number(discordStatus?.commandsRegistered || 0),
            commandsTotal: Number(discordStatus?.commandsTotal || 0),
            commandsSyncedGuilds: Number(discordStatus?.commandsSyncedGuilds || 0),
            commandSyncErrors: Array.isArray(discordStatus?.commandSyncErrors) ? discordStatus.commandSyncErrors : [],
            scheduled: !!bot.schedule_enabled,
            scheduleActiveNow: scheduleAllowed,
            botOnlineNow: discordOnline,
            discordOnline,
            discordStatus: discordStatus ? {
              status: discordStatus.status,
              updatedAt: discordStatus.updatedAt || null,
              guilds: Number(discordStatus.guilds || 0),
              commandsTotal: Number(discordStatus.commandsTotal || 0),
              commandsRegistered: Number(discordStatus.commandsRegistered || 0),
              commandsSyncedGuilds: Number(discordStatus.commandsSyncedGuilds || 0),
              commandSyncErrors: Array.isArray(discordStatus.commandSyncErrors) ? discordStatus.commandSyncErrors : [],
              error: discordStatus.error || null
            } : null,
            logs,
            hint: signal === "stop"
              ? "O processo foi parado na hospedagem."
              : (discordOnline
                ? "O CAOS confirmou a conexão e a publicação de comandos no Discord."
                : (result.hint || "Inicialização solicitada. Acompanhe a instalação, o login no Discord e a publicação dos comandos nos logs."))
          });
        } catch (error) {
          return reply({ ok: false, error: error.message || "Falha ao controlar o bot no Bot-Hosting." }, 502);
        }
      }

      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Este bot ainda não foi iniciado em uma hospedagem." }, 409);
        try {
          const path = action === "logs"
            ? "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/logs?size=100&waitSeconds=20"
            : "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0";
          return reply(await hostRequest(user.id, env, path));
        } catch (error) {
          return reply({ error: error.message || "Não consegui consultar o servidor do bot." }, 502);
        }
      }

      if (action === "files" && !subPath && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de abrir os arquivos." }, 409);
        try {
          const root = safeVolumePath(url.searchParams.get("path") || "/");
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files?path=" + encodeURIComponent(root)));
        } catch (error) { return reply({ error: error.message || "Falha ao listar arquivos." }, 502); }
      }

      if (action === "files" && subPath === "download-url" && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Hospedagem não preparada." }, 409);
        try {
          const filePath = safeVolumePath(url.searchParams.get("path"));
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/download-url?path=" + encodeURIComponent(filePath)));
        } catch (error) { return reply({ error: error.message || "Falha ao preparar download." }, 502); }
      }

      if (action === "files" && subPath === "compress" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Hospedagem não preparada." }, 409);
        const b = await body(request);
        const root = safeVolumePath(b.root || "/");
        const items = Array.isArray(b.files) ? b.files : [];
        if (!items.length || items.length > 300) return reply({ error: "Selecione de 1 a 300 arquivos ou pastas para exportar." }, 400);
        const files = items.map(item => safeVolumePath(item));
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/compress", "POST", { root, files }));
        } catch (error) { return reply({ error: error.message || "Falha ao criar o arquivo ZIP." }, 502); }
      }

      if (action === "files" && subPath === "content" && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de ler arquivos." }, 409);
        try {
          const filePath = safeVolumePath(url.searchParams.get("path") || "/main.py");
          const params = new URLSearchParams({ path: filePath, offset: String(Math.max(0, Number(url.searchParams.get("offset") || 0) || 0)), limit: String(Math.min(1000, Math.max(1, Number(url.searchParams.get("limit") || 400) || 400))) });
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?" + params.toString()));
        } catch (error) { return reply({ error: error.message || "Falha ao ler arquivo." }, 502); }
      }

      if (action === "files" && subPath === "content" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de editar arquivos." }, 409);
        const b = await body(request);
        const filePath = safeVolumePath(b.path);
        const content = String(b.content ?? "");
        if (content.length > 450000) return reply({ error: "O arquivo é grande demais para o editor de texto. Use o envio de arquivos." }, 413);
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content", "POST", { path: filePath, content, mode: "overwrite" }));
        } catch (error) { return reply({ error: error.message || "Falha ao salvar arquivo." }, 502); }
      }

      if (action === "files" && subPath === "delete" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de remover arquivos." }, 409);
        const b = await body(request);
        const filePath = safeVolumePath(b.path);
        if (filePath === "/" || filePath === "/main.py" || filePath === "/runner.py") {
          return reply({ error: "Este arquivo é essencial para o bot e não pode ser removido por aqui." }, 400);
        }
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/delete", "POST", { root: "/", files: [filePath] }));
        } catch (error) { return reply({ error: error.message || "Falha ao excluir arquivo." }, 502); }
      }

      if (action === "upload-url" && request.method === "POST") {
        try {
          const b = await body(request);
          const root = safeVolumePath(b.path || "/");
          const requestedRuntime = String(b.runtime || bot.runtime || "python").toLowerCase();
          if (!["python","nodejs"].includes(requestedRuntime)) return reply({ error: "Escolha Python ou Node.js para este pacote." }, 400);
          let deploymentId = bot.hosting_deployment_id || null;
          if (!deploymentId) {
            const hosting = await env.DB.prepare("SELECT scope FROM hosting_connections WHERE user_id=?").bind(user.id).first();
            if (!hosting) return reply({ code: "hosting_not_connected", error: "Conecte o Bot-Hosting antes de enviar o pacote do bot." }, 409);
            const scopes = String(hosting.scope || "").split(/\\s+/).filter(Boolean);
            if (!scopes.includes("deployments:write") || !scopes.includes("credits:spend") || !scopes.includes("files:write")) {
              return reply({ code: "hosting_scope_missing", error: "A autorização do Bot-Hosting precisa liberar criação e envio de arquivos. Reconecte a hospedagem nas Configurações." }, 403);
            }
            const safeName = ("black-zone-" + String(bot.name || "bot").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) + "-" + String(bot.id).slice(0, 5)).replace(/-+/g, "-");
            const created = await hostRequest(user.id, env, "/deployments", "POST", {
              name: safeName, source: "blank", runtime: requestedRuntime,
              runtimeVersion: requestedRuntime === "nodejs" ? "22" : "3.11"
            });
            deploymentId = String((created.deployment || created).id || "");
            if (!deploymentId) throw new Error("O Bot-Hosting não retornou o ID do servidor para receber arquivos.");
            await env.DB.prepare("UPDATE bots SET hosting_deployment_id=?,runtime=?,state='draft',updated_at=? WHERE id=? AND user_id=?")
              .bind(deploymentId, requestedRuntime, Date.now(), id, user.id).run();
          } else if (requestedRuntime !== String(bot.runtime || "python").toLowerCase()) {
            await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
              runtime: requestedRuntime, runtimeVersion: requestedRuntime === "nodejs" ? "22" : "3.11",
              entryFile: requestedRuntime === "nodejs" ? "index.js" : "main.py",
              startCommand: null, wipeFiles: true
            });
            await env.DB.prepare("UPDATE bots SET runtime=?,custom_project=NULL,state='draft',updated_at=? WHERE id=? AND user_id=?")
              .bind(requestedRuntime, Date.now(), id, user.id).run();
          }
          const signed = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/upload-url", "POST", { path: root });
          return reply({ ...signed, deploymentId, path: root, runtime: requestedRuntime });
        } catch (error) { return reply({ error: error.message || "Falha ao preparar envio." }, 502); }
      }

      if (action === "extract" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Hospedagem não preparada." }, 409);
        const b = await body(request);
        const file = String(b.file || "");
        if (!/^[A-Za-z0-9._-]{1,140}\.zip$/i.test(file) || file.includes("..")) {
          return reply({ error: "Nome de ZIP inválido." }, 400);
        }
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/decompress", "POST", { root: safeVolumePath(b.path || "/"), file, removeArchive: true }));
        } catch (error) { return reply({ error: error.message || "Falha ao extrair ZIP." }, 502); }
      }

      if (action === "import" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Envie o pacote para preparar a hospedagem primeiro." }, 409);
        try {
          const importBody = await body(request);
          const packageName = String(importBody.packageName || bot.name || "meu-bot").trim().slice(0, 64) || String(bot.name || "meu-bot");
          const analysis = await scanImportedProject(user.id, env, bot.hosting_deployment_id);
          if (!analysis.ok) return reply(analysis, 422);
          if (analysis.runtime !== String(bot.runtime || "python").toLowerCase()) {
            return reply({
              error: "O pacote parece ser " + (analysis.runtime === "nodejs" ? "Node.js" : "Python") +
                ", mas este projeto está configurado para " + (bot.runtime === "nodejs" ? "Node.js" : "Python") +
                ". Escolha a linguagem correta e envie novamente."
            }, 422);
          }
          const customProject = {
            packageName, rootPath: "/", runtime: analysis.runtime, entryFile: analysis.entryFile,
            startCommand: analysis.startCommand || null, dependencyFile: analysis.dependencyFile || null,
            fileCount: analysis.fileCount, directoryCount: analysis.directoryCount,
            imageCount: analysis.imageCount, importedAt: Date.now()
          };
          try {
            const marker = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?path=%2Fcaos-version.txt");
            if (String(marker.content || "").trim()) {
              const main = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?path=%2Fmain.py");
              if (String(main.content || "") === CAOS_MAIN_PY) await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/delete", "POST", { root: "/", files: ["/main.py"] });
              await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/delete", "POST", { root: "/", files: ["/runner.py", "/caos-version.txt"] });
            }
          } catch {}
          await env.DB.prepare("UPDATE bots SET runtime=?,custom_project=?::jsonb,state='stopped',updated_at=? WHERE id=? AND user_id=?")
            .bind(analysis.runtime, JSON.stringify(customProject), Date.now(), id, user.id).run();
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/startup", "PATCH", {
            runtime: analysis.runtime, runtimeVersion: analysis.runtime === "nodejs" ? "22" : "3.11",
            entryFile: analysis.entryFile, startCommand: customProject.startCommand
          });
          return reply({
            ok: true, imported: true, customProject,
            message: "Pacote analisado e salvo. O arquivo principal foi identificado; as dependências serão instaladas pela hospedagem na próxima inicialização."
          });
        } catch (error) { return reply({ error: error.message || "Falha ao analisar o pacote importado." }, 502); }
      }

      if (action === "shell" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Prepare a hospedagem antes de abrir o terminal." }, 409);
        const b = await body(request);
        const command = String(b.command || "").trim();
        if (!command || command.length > 4000) return reply({ error: "Digite um comando de até 4.000 caracteres." }, 400);
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/shell", "POST", { command, timeout: 45, maxChars: 12000 }));
        } catch (error) { return reply({ error: error.message || "Falha ao executar comando." }, 502); }
      }

      if (action === "backups" && subPath === "manual" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Prepare a hospedagem antes de criar um backup manual." }, 409);
        try {
          const pending = [{ path: "/", depth: 0 }];
          const visited = new Set();
          const files = [];
          while (pending.length && files.length < 400) {
            const current = pending.shift();
            if (visited.has(current.path) || current.depth > 7) continue;
            visited.add(current.path);
            const listing = await hostRequest(
              user.id, env,
              "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files?path=" + encodeURIComponent(current.path)
            );
            const entries = Array.isArray(listing.entries) ? listing.entries : [];
            for (const entry of entries) {
              if (!entry?.name || entry.name === "." || entry.name === "..") continue;
              const fullPath = safeVolumePath((current.path === "/" ? "" : current.path) + "/" + entry.name);
              if (entry.type === "directory" || entry.type === "folder") {
                if (current.depth < 7 && !["node_modules", ".git", ".venv", "__pycache__"].includes(entry.name)) {
                  pending.push({ path: fullPath, depth: current.depth + 1 });
                }
              } else if (entry.type === "file") {
                if (!/^black-zone-manual-backup-/i.test(entry.name)) files.push(fullPath);
                if (files.length >= 400) break;
              }
            }
          }
          if (!files.length) return reply({ error: "Não encontrei arquivos para incluir no backup." }, 409);
          if (pending.length) return reply({ error: "Este projeto tem arquivos demais para um backup manual único. Exporte pastas menores pela área Arquivos." }, 413);
          const compressed = await hostRequest(
            user.id, env,
            "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/compress",
            "POST",
            { root: "/", files }
          );
          if (!compressed.archive) return reply({ error: "O provedor não retornou o nome do ZIP criado." }, 502);
          const archivePath = safeVolumePath(compressed.archive);
          const download = await hostRequest(
            user.id, env,
            "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/download-url?path=" + encodeURIComponent(archivePath)
          );
          if (!download.url) return reply({ error: "O ZIP foi criado, mas o provedor não forneceu o link de download." }, 502);
          return reply({
            ok: true,
            archive: archivePath,
            downloadUrl: download.url,
            filesCount: files.length,
            note: "Backup manual compactado no container e pronto para baixar. Guarde o ZIP fora da hospedagem."
          });
        } catch (error) {
          return reply({ error: error.message || "Falha ao criar backup manual." }, 502);
        }
      }

      if (action === "backups" && !subPath && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Prepare a hospedagem para consultar os pontos de restauração." }, 409);
        try {
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/backups"));
        } catch (error) { return reply({ error: error.message || "Falha ao consultar backups." }, 502); }
      }

      if (action === "backups" && subPath && suffix === "restore" && request.method === "POST") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Hospedagem não preparada." }, 409);
        if (!/^[A-Za-z0-9_-]{1,120}$/.test(subPath)) return reply({ error: "Identificador do backup inválido." }, 400);
        const b = await body(request);
        const mode = b.mode === "subfolder" ? "subfolder" : "replace";
        try {
          const result = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/backups/" + encodeURIComponent(subPath) + "/restore", "POST", { mode });
          return reply({ ...result, restoreStarted: true, warning: mode === "replace" ? "Restauração substitui os arquivos atuais da hospedagem." : null });
        } catch (error) { return reply({ error: error.message || "Falha ao iniciar restauração." }, 502); }
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
        `CREATE TABLE IF NOT EXISTS discord_link_states (state TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, code_verifier TEXT, expires_at BIGINT NOT NULL)`,
        "CREATE INDEX IF NOT EXISTS idx_discord_states_expiry ON discord_states(expires_at)",
        "CREATE TABLE IF NOT EXISTS verification_bot_settings (id TEXT PRIMARY KEY,owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,bot_token_enc TEXT,bot_id TEXT,bot_name TEXT,oauth_client_id TEXT,oauth_client_secret_enc TEXT,invite_url TEXT,hosting_deployment_id TEXT,state TEXT NOT NULL DEFAULT 'draft',updated_at BIGINT NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS verification_states (state TEXT PRIMARY KEY,invite_url TEXT NOT NULL,expires_at BIGINT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_verification_states_expiry ON verification_states(expires_at)",
        "CREATE TABLE IF NOT EXISTS discord_verifications (discord_id TEXT PRIMARY KEY,discord_username TEXT NOT NULL,avatar_hash TEXT,verified_at BIGINT NOT NULL)",
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
      await db.raw("ALTER TABLE discord_link_states ADD COLUMN IF NOT EXISTS code_verifier TEXT");
      await db.raw("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_username TEXT");
      await db.raw("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_linked_at BIGINT");
      await db.raw("CREATE INDEX IF NOT EXISTS idx_discord_link_states_expiry ON discord_link_states(expires_at)");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_token_enc TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_bot_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS discord_bot_name TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS hosting_deployment_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_start TEXT NOT NULL DEFAULT '00:00'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_end TEXT NOT NULL DEFAULT '23:59'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_timezone TEXT NOT NULL DEFAULT 'America/Bahia'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS guild_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS custom_project JSONB");
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
