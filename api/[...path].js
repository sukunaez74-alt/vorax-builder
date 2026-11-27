import { neon } from "@neondatabase/serverless";
import JSZip from "jszip";
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
async function adminCaosSettings(env) {
  return await env.DB.prepare(
    "SELECT id,owner_user_id,bot_token_enc,bot_id,bot_name,hosting_deployment_id,package_uploaded_at,state,updated_at FROM admin_caos_settings WHERE id='main'"
  ).first();
}
async function saveAdminCaosToken(user, input, env) {
  const old = await adminCaosSettings(env);
  if (old && String(old.owner_user_id) !== String(user.id)) throw new Error("A configuração CAOS já pertence à conta administradora principal.");
  const token = normalizeDiscordBotToken(input.botToken);
  if (!token) throw new Error("Cole o token do bot Discord antes de salvar.");
  const identity = await validateDiscordBotToken(token);
  if (!identity.valid) {
    if (identity.unavailable) throw new Error("Não consegui validar o token com o Discord agora. Tente novamente.");
    throw new Error("O Discord recusou o token. Confira se você copiou o Bot Token correto.");
  }
  const encrypted = await encryptSecret(token, env);
  await env.DB.prepare(
    "INSERT INTO admin_caos_settings (id,owner_user_id,bot_token_enc,bot_id,bot_name,state,updated_at) VALUES ('main',?,?,?,?, 'draft',?) ON CONFLICT (id) DO UPDATE SET bot_token_enc=EXCLUDED.bot_token_enc,bot_id=EXCLUDED.bot_id,bot_name=EXCLUDED.bot_name,state=CASE WHEN admin_caos_settings.package_uploaded_at IS NULL THEN 'draft' ELSE admin_caos_settings.state END,updated_at=EXCLUDED.updated_at"
  ).bind(user.id, encrypted, identity.botId, identity.botName || null, Date.now()).run();
  return { ok: true, configured: true, botId: identity.botId, botName: identity.botName || null, message: "Token validado e salvo protegido no painel." };
}
async function ensureAdminCaosDeployment(userId, env, settings) {
  if (settings?.hosting_deployment_id) return String(settings.hosting_deployment_id);
  const hosting = await env.DB.prepare("SELECT scope FROM hosting_connections WHERE user_id=?").bind(userId).first();
  const scopes = String(hosting?.scope || "").split(/\s+/).filter(Boolean);
  const missing = ["files:write","deployments:power"].filter(scope => !scopes.includes(scope));
  if (!hosting || missing.length) {
    throw new Error("Reconecte o Bot-Hosting pelo botão desta página e autorize envio de arquivos e controle do servidor.");
  }

  // Reaproveita a vaga do ADM antigo somente se ela pertence ao mesmo administrador.
  // O usuário autorizou expressamente substituir esse bot pelo CAOS.
  const oldAdmin = await env.DB.prepare(
    "SELECT owner_user_id,hosting_deployment_id FROM verification_bot_settings WHERE id='main'"
  ).first();
  const deploymentId = String(oldAdmin?.hosting_deployment_id || "");
  if (!deploymentId || String(oldAdmin?.owner_user_id || "") !== String(userId)) {
    throw new Error("Não encontrei a vaga do antigo ADM vinculada a esta conta. Nenhum outro bot foi alterado.");
  }

  const collision = await env.DB.prepare(
    "SELECT id,name FROM bots WHERE user_id=? AND hosting_deployment_id=? LIMIT 1"
  ).bind(userId, deploymentId).first();
  if (collision) {
    throw new Error("A vaga antiga também está vinculada ao bot \"" + String(collision.name || collision.id) + "\". Para proteger esse bot, a instalação foi bloqueada.");
  }

  // Confirma que a hospedagem é acessível e consulta seu estado antes de parar o ADM.
  const diagnosis = await hostRequest(
    userId, env,
    "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=2"
  );
  let currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
  if (!currentState) {
    const current = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId));
    currentState = String(current.state || current.deployment?.state || "").toLowerCase();
  }
  if (!currentState) {
    throw new Error("Encontrei a vaga do ADM, mas não consegui confirmar o estado dela. Nenhum arquivo foi alterado.");
  }
  if (!["offline","stopped","terminated"].includes(currentState)) {
    await hostRequest(
      userId, env,
      "/deployments/" + encodeURIComponent(deploymentId) + "/power",
      "POST",
      { action: "stop", waitSeconds: 20 }
    );
  }

  // Desvincula somente o painel antigo; mantém token e histórico para referência.
  await env.DB.prepare(
    "UPDATE verification_bot_settings SET hosting_deployment_id=NULL,state='replaced',updated_at=? WHERE id='main' AND owner_user_id=? AND hosting_deployment_id=?"
  ).bind(Date.now(), userId, deploymentId).run();

  await env.DB.prepare(
    "INSERT INTO admin_caos_settings (id,owner_user_id,hosting_deployment_id,state,updated_at) VALUES ('main',?,?,'draft',?) ON CONFLICT (id) DO UPDATE SET hosting_deployment_id=EXCLUDED.hosting_deployment_id,updated_at=EXCLUDED.updated_at"
  ).bind(userId, deploymentId, Date.now()).run();
  return deploymentId;
}
async function readAdminCaosRuntime(userId, env, settings) {
  const deploymentId = settings?.hosting_deployment_id || null;
  if (!deploymentId) return { state: "not_deployed", online: false, deploymentId: null, logs: [] };
  let diagnosis = {};
  let logsResponse = {};
  try {
    diagnosis = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=0");
  } catch (error) {
    return { state: "error", online: false, deploymentId, error: error.message, logs: [] };
  }
  try {
    logsResponse = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/logs?size=100&waitSeconds=0");
  } catch {}
  const rawLines = Array.isArray(logsResponse.logs) ? logsResponse.logs
    : Array.isArray(logsResponse.lines) ? logsResponse.lines
    : Array.isArray(diagnosis.logs) ? diagnosis.logs : [];
  const lines = rawLines.map(item => typeof item === "string" ? item : String(item?.message || item?.line || JSON.stringify(item))).slice(-60);
  const state = String(diagnosis.state || diagnosis.deployment?.state || settings.state || "unknown").toLowerCase();
  const ready = lines.some(line => /CAOS conectado como|logged in as/i.test(line));
  return {
    state, online: state === "running", discordReady: ready, deploymentId,
    botName: settings.bot_name || null, logs: lines,
    hint: diagnosis.hint || null, error: diagnosis.error || null,
    packageUploaded: !!settings.package_uploaded_at
  };
}
async function adminCaosHostingInfo(userId, env) {
  const hosting = await env.DB.prepare("SELECT scope,expires_at FROM hosting_connections WHERE user_id=?").bind(userId).first();
  const scopes = String(hosting?.scope || "").split(/\s+/).filter(Boolean);
  const required = ["deployments:write","credits:spend","files:write"];
  let diagnostic = { ok: false, message: hosting ? "Verificando autorização do Bot-Hosting…" : "Bot-Hosting ainda não conectado." };
  if (hosting) {
    try {
      await hostRequest(userId, env, "/deployments?brief=true");
      diagnostic = { ok: true, message: "Conexão com Bot-Hosting confirmada." };
    } catch (error) {
      diagnostic = { ok: false, message: error.message || "Não consegui validar a hospedagem." };
    }
  }
  return {
    hostingConnected: !!hosting,
    hostingCanCreate: required.every(scope => scopes.includes(scope)),
    hostingMissingScopes: required.filter(scope => !scopes.includes(scope)),
    hostingDiagnostic: diagnostic
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
async function waitForHostReinstall(userId, env, deploymentId) {
  // Keep each serverless request short. The browser retries while the host is installing.
  const deadline = Date.now() + 4500;
  let lastState = "unknown";
  while (Date.now() < deadline) {
    const current = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId));
    lastState = String(current.state || current.deployment?.state || "").toLowerCase();
    if (lastState && !["installing","starting","provisioning","reinstalling","creating","unknown"].includes(lastState)) {
      return { state: lastState };
    }
    await new Promise(resolve => setTimeout(resolve, 900));
  }
  const error = new Error("O Bot-Hosting ainda está preparando o ambiente (" + lastState + ").");
  error.code = "hosting_installing";
  error.retryAfterMs = 1800;
  throw error;
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
  const projectType = bot.project_type === "custom" || customProject ? "custom" : "standard";
  if (projectType === "custom" && !customProject) {
    throw new Error("Envie primeiro o ZIP, a pasta ou os arquivos do seu bot na área Arquivos.");
  }
  if (projectType === "standard" && bot.runtime !== "python") {
    throw new Error("O bot padrão do Estúdio utiliza Python 3.11.");
  }
  if (projectType === "standard" && (!CAOS_MAIN_PY || CAOS_MAIN_PY.length < 10000)) {
    throw new Error("O bot padrão não foi incluído nesta publicação. Atualize o painel e tente novamente.");
  }
  let token = null;
  if (bot.discord_token_enc) {
    token = await decryptSecret(bot.discord_token_enc, env);
    if (!token) throw new Error("Não consegui abrir o token protegido deste projeto. Salve novamente o token do Discord.");
  }
  if (!token && projectType === "standard") {
    throw new Error("Salve o Bot Token Discord para o bot padrão antes de iniciar.");
  }
  let identity = null;
  if (token) {
    identity = await validateDiscordBotToken(token);
    if (!identity.valid) throw new Error("O Discord não aceitou o token salvo. Abra Configurar bot e atualize a credencial.");
    const duplicate = await env.DB.prepare("SELECT id,name FROM bots WHERE user_id=? AND discord_bot_id=? AND id<>? LIMIT 1")
      .bind(userId, identity.botId, bot.id).first();
    if (duplicate) throw new Error("Este mesmo bot Discord já está cadastrado no projeto \"" + String(duplicate.name || duplicate.id) + "\". Cada projeto precisa de um Bot Token próprio para evitar sessões duplicadas no Discord.");
    const central = await verificationBotSettings(env);
    if (central?.bot_id && String(central.bot_id) === identity.botId) {
      throw new Error("Este Bot Token também está reservado para o bot central do ADM. Use um bot Discord diferente neste projeto.");
    }
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
    const deployRuntime = projectType === "custom" ? (customProject.runtime === "nodejs" ? "nodejs" : "python") : "python";
    const created = await hostRequest(userId, env, "/deployments", "POST", {
      name: safeName,
      source: "blank",
      runtime: deployRuntime,
      runtimeVersion: deployRuntime === "nodejs" ? "22" : "3.11"
    });
    const deployment = created.deployment || created;
    deploymentId = String(deployment.id || "");
    if (!deploymentId) throw new Error("O Bot-Hosting respondeu sem o identificador da implantação.");
    await env.DB.prepare("UPDATE bots SET hosting_deployment_id=?,discord_bot_id=COALESCE(?,discord_bot_id),discord_bot_name=COALESCE(?,discord_bot_name),state='draft',updated_at=? WHERE id=? AND user_id=?")
      .bind(deploymentId, identity?.botId || null, identity?.botName || null, Date.now(), bot.id, userId).run();
  }

  if (customProject) {
    const runtime = customProject.runtime === "nodejs" ? "nodejs" : "python";
    const runtimeVersion = runtime === "nodejs" ? "22" : "3.11";
    const entryFile = String(customProject.entryFile || "").replace(/^\/+/, "");
    if (!entryFile || entryFile.split("/").some(part => part === "..")) throw new Error("O pacote importado não tem um arquivo principal válido. Reenvie a pasta ou o ZIP.");
    if (token) {
      await setHostEnv(userId, env, deploymentId, "DISCORD_TOKEN", token, true);
      await setHostEnv(userId, env, deploymentId, "BOT_TOKEN", token, true);
      await setHostEnv(userId, env, deploymentId, "TOKEN", token, true);
    }
    await setHostEnv(userId, env, deploymentId, "APP_URL", "https://black-zone-estudio.vercel.app", false);
    await setHostEnv(userId, env, deploymentId, "BOT_NAME", bot.name || "Discord Bot", false);
    await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
      runtime, runtimeVersion, entryFile, startCommand: customProject.startCommand || null
    });
    await env.DB.prepare("UPDATE bots SET runtime=?,discord_bot_id=COALESCE(?,discord_bot_id),discord_bot_name=COALESCE(?,discord_bot_name),updated_at=? WHERE id=? AND user_id=?")
      .bind(runtime, identity?.botId || null, identity?.botName || null, Date.now(), bot.id, userId).run();
    return { deploymentId, botId: identity?.botId || bot.discord_bot_id || null, botName: identity?.botName || bot.discord_bot_name || null, customProject: true, entryFile, runtime, tokenSource: token ? "secure-field" : "project-files" };
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

async function keritRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  const suffix = path ? (path.startsWith("?") ? path : (path.startsWith("/") ? path : "/" + path)) : "";
  const headers = { Authorization: "Bearer " + token, Accept: "application/vnd.pterodactyl.v1+json, application/json" };
  if (payload !== null && !rawBody && !form) headers["Content-Type"] = "application/json";
  if (rawBody) headers["Content-Type"] = "text/plain";
  const response = await fetch("https://panel.kerit.cloud/api/client" + suffix, {
    method, headers,
    body: form || (payload === null ? undefined : (rawBody ? String(payload) : JSON.stringify(payload))),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  if (raw) { try { data = JSON.parse(raw); } catch { data = { text: raw }; } }
  if (!response.ok) {
    const reason = externalErrorText(data?.errors?.[0]?.detail || data?.message || data?.error || raw) || ("HTTP " + response.status);
    const error = new Error("Kerit Cloud · " + method + " " + suffix + " · HTTP " + response.status + ": " + reason);
    error.status = response.status; throw error;
  }
  return { data, raw, status: response.status };
}
async function cogitRequest(token, path, method = "GET", payload = null, rawBody = false) {
  const headers = { Authorization: "Bearer " + token, Accept: "application/vnd.pterodactyl.v1+json, application/json", ...(payload !== null && !rawBody ? {"Content-Type":"application/json"} : {}) };
  if (rawBody) headers["Content-Type"] = "text/plain";
  const response = await fetch("https://panel.cogitdev.net/api/client" + path, {
    method, headers,
    body: payload === null ? undefined : (rawBody ? String(payload) : JSON.stringify(payload)),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  if (raw) { try { data = JSON.parse(raw); } catch { data = { text: raw }; } }
  if (!response.ok) {
    const reason = externalErrorText(data?.errors?.[0]?.detail || data?.message || data?.error || raw) || ("HTTP " + response.status);
    const error = new Error("Cogithost · " + method + " " + path + " · HTTP " + response.status + ": " + reason);
    error.status = response.status; throw error;
  }
  return { data, raw, status: response.status };
}
async function sillydevRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  const suffix = path ? (path.startsWith("?") ? path : (path.startsWith("/") ? path : "/" + path)) : "";
  const headers = { Authorization: "Bearer " + token, Accept: "application/json" };
  if (payload !== null && !rawBody && !form) headers["Content-Type"] = "application/json";
  if (rawBody) headers["Content-Type"] = "text/plain";
  const response = await fetch("https://sillydev.co.uk/panel/api/client" + suffix, {
    method, headers,
    body: form || (payload === null ? undefined : (rawBody ? String(payload) : JSON.stringify(payload))),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  if (raw) { try { data = JSON.parse(raw); } catch { data = { text: raw }; } }
  if (!response.ok) {
    const detail = data?.errors?.[0]?.detail || data?.message || data?.error || raw;
    const reason = externalErrorText(detail) || ("HTTP " + response.status);
    const error = new Error("Silly Development · " + method + " " + suffix + " · HTTP " + response.status + ": " + reason);
    error.status = response.status;
    error.code = data?.errors?.[0]?.code || data?.code || "";
    throw error;
  }
  return { data, raw, status: response.status };
}
function providerRequestForId(providerId) {
  const requests = {
    sillydev: sillydevRequest, keritcloud: keritRequest, waifly: waiflyRequest,
    xsystems: xsystemsRequest, torchlite: torchliteRequest, daki: dakiRequest,
    unixsys: unixsysRequest, consolex1: consolex1Request
  };
  return requests[providerId] || null;
}
function providerDisplayName(providerId) {
  const names = {
    sillydev: "Silly Development", keritcloud: "Kerit Cloud", waifly: "Waifly",
    xsystems: "X Systems Hosting", torchlite: "Torchlite", daki: "Daki Hosting",
    unixsys: "Unixsys", consolex1: "ConsoleX1"
  };
  return names[providerId] || "provedor externo";
}
async function cogitConfig(userId, env) {
  const row = await env.DB.prepare("SELECT encrypted_token FROM provider_connections WHERE user_id=? AND provider='cogithost'").bind(userId).first();
  if (!row?.encrypted_token) return null;
  try { const value = await decryptSecret(row.encrypted_token, env); const config = JSON.parse(value || "{}"); return config?.token ? { token: String(config.token) } : null; }
  catch { return null; }
}

async function waiflyRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("waifly", token, path, method, payload, rawBody, form);
}
async function xsystemsRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("xsystems", token, path, method, payload, rawBody, form);
}
async function torchliteRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("torchlite", token, path, method, payload, rawBody, form);
}
async function dakiRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("daki", token, path, method, payload, rawBody, form);
}
async function unixsysRequest(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("unixsys", token, path, method, payload, rawBody, form);
}
async function consolex1Request(token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  return pterodactylRequest("consolex1", token, path, method, payload, rawBody, form);
}
async function pterodactylRequest(provider, token, path = "", method = "GET", payload = null, rawBody = false, form = null) {
  const panels = {
    waifly: "https://panel.waifly.com",
    xsystems: "https://panel.xsystemshosting.com",
    torchlite: "https://game.torchlite.host",
    daki: "https://portal.daki.cc",
    unixsys: "https://panel.unixsys.tech",
    consolex1: "https://panel.consolex1.com"
  };
  const labels = { waifly: "Waifly", xsystems: "X Systems Hosting", torchlite: "Torchlite", daki: "Daki Hosting", unixsys: "Unixsys", consolex1: "ConsoleX1" };
  const base = panels[provider];
  if (!base) throw new Error("Provedor Pterodactyl não reconhecido.");
  const suffix = path ? (path.startsWith("?") ? path : (path.startsWith("/") ? path : "/" + path)) : "";
  const headers = { Authorization: "Bearer " + token, Accept: "application/vnd.pterodactyl.v1+json, application/json" };
  if (payload !== null && !rawBody && !form) headers["Content-Type"] = "application/json";
  if (rawBody) headers["Content-Type"] = "text/plain";
  const response = await fetch(base + "/api/client" + suffix, {
    method, headers,
    body: form || (payload === null ? undefined : (rawBody ? String(payload) : JSON.stringify(payload))),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  if (raw) { try { data = JSON.parse(raw); } catch { data = { text: raw }; } }
  if (!response.ok) {
    const reason = externalErrorText(data?.errors?.[0]?.detail || data?.message || data?.error || raw) || ("HTTP " + response.status);
    const error = new Error((labels[provider] || provider) + " · " + method + " " + suffix + " · HTTP " + response.status + ": " + reason);
    error.status = response.status; throw error;
  }
  return { data, raw, status: response.status };
}

async function keritConfig(userId, env) {
  const row = await env.DB.prepare("SELECT encrypted_token FROM provider_connections WHERE user_id=? AND provider='keritcloud'").bind(userId).first();
  if (!row?.encrypted_token) return null;
  try { const value = await decryptSecret(row.encrypted_token, env); const config = JSON.parse(value || "{}"); return config?.token ? { token: String(config.token) } : null; }
  catch { return null; }
}
async function keritDeployZip(apiKey, serverIdValue, archiveBytes, archiveName, bot, requestedRuntime, userId, env) {
  const serverId = keritIdentifier(serverIdValue);
  const prepared = await prepareDiscloudProject(archiveBytes, bot, requestedRuntime, env);
  const zip = await JSZip.loadAsync(prepared.bytes, { checkCRC32: false });
  const runtime = prepared.runtime;
  const startupResult = await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/startup");
  const variables = Array.isArray(startupResult.data?.data) ? startupResult.data.data : [];
  const envFile = zip.file(".env");
  let envText = envFile ? await envFile.async("string") : "";
  let tokenConfigured = false;
  let tokenKey = null;
  const discordToken = bot.discord_token_enc ? await decryptSecret(bot.discord_token_enc, env) : null;
  const preferred = ["DISCORD_TOKEN", "BOT_TOKEN", "TOKEN"];
  const tokenVariable = variables.find(item => item?.attributes?.is_editable && preferred.includes(String(item.attributes.env_variable || "").toUpperCase()));
  if (discordToken && tokenVariable?.attributes?.env_variable) {
    tokenKey = String(tokenVariable.attributes.env_variable);
    await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", { key: tokenKey, value: discordToken });
    tokenConfigured = true;
    envText = envText.split(/\r?\n/).filter(line => !/^\s*(?:DISCORD_TOKEN|BOT_TOKEN|TOKEN)\s*=/.test(line)).join("\n");
    if (envText.trim()) zip.file(".env", envText.replace(/\n*$/, "\n"));
    else zip.remove(".env");
  }

  if (runtime === "nodejs") {
    const pkgFile = zip.file("package.json");
    let packageJson = {};
    if (pkgFile) {
      try { packageJson = JSON.parse(await pkgFile.async("string")); }
      catch { throw new Error("O package.json deste bot não é um JSON válido."); }
    }
    packageJson.name = String(packageJson.name || String(bot.name || "discord-bot").toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 48));
    packageJson.scripts = packageJson.scripts && typeof packageJson.scripts === "object" ? packageJson.scripts : {};
    if (!String(packageJson.scripts.start || "").trim()) packageJson.scripts.start = "node blackzone_launcher.cjs";
    zip.file("package.json", JSON.stringify(packageJson, null, 2) + "\n");
  } else if (runtime === "python") {
    let pythonEntry = prepared.entryFile;
    if (pythonEntry === "main.py") {
      const originalMain = zip.file("main.py");
      if (originalMain) {
        zip.file("_blackzone_original_main.py", await originalMain.async("uint8array"));
        pythonEntry = "_blackzone_original_main.py";
      }
    }
    zip.file("main.py", [
      "from pathlib import Path",
      "import os",
      "from runpy import run_path",
      "env_file = Path('.env')",
      "if env_file.exists():",
      "    for raw in env_file.read_text(encoding='utf-8').splitlines():",
      "        line = raw.strip()",
      "        if not line or line.startswith('#') or '=' not in line:",
      "            continue",
      "        key, value = line.split('=', 1)",
      "        key, value = key.strip(), value.strip()",
      "        if len(value) >= 2 and value[0] == value[-1] and value[0] in (chr(34), chr(39)):",
      "            value = value[1:-1]",
      "        if key:",
      "            os.environ[key] = value",
      "run_path(" + JSON.stringify(pythonEntry) + ", run_name='__main__')",
      ""
    ].join("\n"));
  }

  const bytes = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
  if (!bytes.byteLength || bytes.byteLength > 25 * 1024 * 1024) throw new Error("O ZIP preparado ultrapassa 25 MB, limite de segurança do Estúdio para o Kerit Cloud.");
  const uploadName = String(archiveName || "meu-bot.zip").replace(/[^A-Za-z0-9._-]/g, "-").replace(/\.zip$/i, "") + "-black-zone.zip";
  const uploadInfo = await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/upload");
  const signedUrl = String(uploadInfo.data?.attributes?.url || uploadInfo.data?.url || "");
  if (!signedUrl.startsWith("https://")) throw new Error("O Kerit Cloud não retornou uma URL HTTPS de upload.");
  const target = new URL(signedUrl);
  target.searchParams.set("directory", "/");
  const form = new FormData();
  form.append("files", new Blob([bytes], { type: "application/zip" }), uploadName);
  const uploaded = await fetch(target.href, { method: "POST", body: form, signal: AbortSignal.timeout(90000) });
  if (!uploaded.ok) throw new Error("O envio do ZIP ao Kerit Cloud falhou: HTTP " + uploaded.status + ".");
  await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/decompress", "POST", { root: "/", file: uploadName });
  try {
    await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/delete", "POST", { root: "/", files: [uploadName] });
  } catch {}
  const resourceResult = await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/resources");
  const stateBefore = String(resourceResult.data?.attributes?.current_state || "").toLowerCase();
  const signal = stateBefore === "running" ? "restart" : "start";
  await keritRequest(apiKey, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
  const customProject = {
    ...prepared.customProject,
    runtime,
    provider: "keritcloud",
    providerName: "Kerit Cloud",
    deployedAt: Date.now(),
    tokenConfigured,
    tokenStoredInEnvFile: !!discordToken && !tokenConfigured
  };
  await env.DB.prepare("UPDATE bots SET hosting_provider='keritcloud',provider_app_id=?,hosting_deployment_id=NULL,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?")
    .bind(serverId, runtime, JSON.stringify(customProject), Date.now(), bot.id, userId).run();
  return {
    ok: true, provider: "keritcloud", providerAppId: serverId, runtime, customProject,
    message: "ZIP enviado, extraído e comando de " + (signal === "restart" ? "reinício" : "início") + " solicitado ao Kerit Cloud. " +
      (tokenConfigured ? "O token foi guardado na variável privada do servidor." : (discordToken ? "O token permanece no arquivo .env privado do servidor; a chave não foi exposta a outros membros." : "Configure o token do Discord nas variáveis de ambiente do servidor."))
  };
}
async function pterodactylDeployZip(apiKey, serverIdValue, archiveBytes, archiveName, bot, requestedRuntime, userId, env, providerId, providerName, requestFn) {
  const serverId = keritIdentifier(serverIdValue);
  const prepared = await prepareDiscloudProject(archiveBytes, bot, requestedRuntime, env);
  const zip = await JSZip.loadAsync(prepared.bytes, { checkCRC32: false });
  const runtime = prepared.runtime;
  const startupResult = await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/startup");
  const variables = Array.isArray(startupResult.data?.data) ? startupResult.data.data : [];
  const envFile = zip.file(".env");
  let envText = envFile ? await envFile.async("string") : "";
  let tokenConfigured = false;
  let tokenKey = null;
  const discordToken = bot.discord_token_enc ? await decryptSecret(bot.discord_token_enc, env) : null;
  const preferred = ["DISCORD_TOKEN", "BOT_TOKEN", "TOKEN"];
  const tokenVariable = variables.find(item => item?.attributes?.is_editable && preferred.includes(String(item.attributes.env_variable || "").toUpperCase()));
  if (discordToken && tokenVariable?.attributes?.env_variable) {
    tokenKey = String(tokenVariable.attributes.env_variable);
    await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", { key: tokenKey, value: discordToken });
    tokenConfigured = true;
    envText = envText.split(/\r?\n/).filter(line => !/^\s*(?:DISCORD_TOKEN|BOT_TOKEN|TOKEN)\s*=/.test(line)).join("\n");
    if (envText.trim()) zip.file(".env", envText.replace(/\n*$/, "\n"));
    else zip.remove(".env");
  }

  const launcherFile = runtime === "nodejs" ? "blackzone_launcher.cjs" : "main.py";
  const startupFileVariables = ["MAIN_FILE","BOT_FILE","APP_FILE","ENTRY_FILE","START_FILE","PY_FILE","JS_FILE"];
  const startupFileVariable = variables.find(item =>
    item?.attributes?.is_editable &&
    startupFileVariables.includes(String(item.attributes.env_variable || "").toUpperCase())
  );
  let startupFileConfigured = false;
  if (startupFileVariable?.attributes?.env_variable) {
    await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", {
      key: String(startupFileVariable.attributes.env_variable),
      value: launcherFile
    });
    startupFileConfigured = true;
  }

  if (runtime === "nodejs") {
    const pkgFile = zip.file("package.json");
    let packageJson = {};
    if (pkgFile) {
      try { packageJson = JSON.parse(await pkgFile.async("string")); }
      catch { throw new Error("O package.json deste bot não é um JSON válido."); }
    }
    packageJson.name = String(packageJson.name || String(bot.name || "discord-bot").toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 48));
    packageJson.scripts = packageJson.scripts && typeof packageJson.scripts === "object" ? packageJson.scripts : {};
    if (!String(packageJson.scripts.start || "").trim()) packageJson.scripts.start = "node blackzone_launcher.cjs";
    zip.file("package.json", JSON.stringify(packageJson, null, 2) + "\n");
  } else if (runtime === "python") {
    let pythonEntry = prepared.entryFile;
    if (pythonEntry === "main.py") {
      const originalMain = zip.file("main.py");
      if (originalMain) {
        zip.file("_blackzone_original_main.py", await originalMain.async("uint8array"));
        pythonEntry = "_blackzone_original_main.py";
      }
    }
    zip.file("main.py", [
      "from pathlib import Path",
      "import os",
      "from runpy import run_path",
      "env_file = Path('.env')",
      "if env_file.exists():",
      "    for raw in env_file.read_text(encoding='utf-8').splitlines():",
      "        line = raw.strip()",
      "        if not line or line.startswith('#') or '=' not in line:",
      "            continue",
      "        key, value = line.split('=', 1)",
      "        key, value = key.strip(), value.strip()",
      "        if len(value) >= 2 and value[0] == value[-1] and value[0] in (chr(34), chr(39)):",
      "            value = value[1:-1]",
      "        if key:",
      "            os.environ[key] = value",
      "run_path(" + JSON.stringify(pythonEntry) + ", run_name='__main__')",
      ""
    ].join("\n"));
  }

  const bytes = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
  if (!bytes.byteLength || bytes.byteLength > 25 * 1024 * 1024) throw new Error("O ZIP preparado ultrapassa 25 MB, limite de segurança do Estúdio para " + providerName + ".");
  const uploadName = String(archiveName || "meu-bot.zip").replace(/[^A-Za-z0-9._-]/g, "-").replace(/\.zip$/i, "") + "-black-zone.zip";
  const uploadInfo = await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/upload");
  const signedUrl = String(uploadInfo.data?.attributes?.url || uploadInfo.data?.url || "");
  if (!signedUrl.startsWith("https://")) throw new Error(providerName + " não retornou uma URL HTTPS de upload.");
  const target = new URL(signedUrl);
  target.searchParams.set("directory", "/");
  const form = new FormData();
  form.append("files", new Blob([bytes], { type: "application/zip" }), uploadName);
  const uploaded = await fetch(target.href, { method: "POST", body: form, signal: AbortSignal.timeout(90000) });
  if (!uploaded.ok) throw new Error("O envio do ZIP à " + providerName + " falhou: HTTP " + uploaded.status + ".");
  await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/decompress", "POST", { root: "/", file: uploadName });
  try {
    await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/files/delete", "POST", { root: "/", files: [uploadName] });
  } catch {}
  const resourceResult = await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/resources");
  const stateBefore = String(resourceResult.data?.attributes?.current_state || "").toLowerCase();
  const signal = stateBefore === "running" ? "restart" : "start";
  await requestFn(apiKey, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
  const customProject = {
    ...prepared.customProject,
    runtime,
    provider: providerId,
    providerName,
    deployedAt: Date.now(),
    tokenConfigured,
    tokenStoredInEnvFile: !!discordToken && !tokenConfigured,
    startupFile: launcherFile,
    startupFileConfigured
  };
  await env.DB.prepare("UPDATE bots SET hosting_provider=?,provider_app_id=?,hosting_deployment_id=NULL,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?")
    .bind(providerId, serverId, runtime, JSON.stringify(customProject), Date.now(), bot.id, userId).run();
  return {
    ok: true, provider: providerId, providerAppId: serverId, runtime, customProject,
    message: "ZIP enviado, extraído e comando de " + (signal === "restart" ? "reinício" : "início") + " solicitado à " + providerName + ". " +
      (tokenConfigured ? "O token foi guardado na variável privada do servidor." : (discordToken ? "O token permanece no arquivo .env privado do servidor; a chave não foi exposta a outros membros." : "Configure o token do Discord nas variáveis de ambiente do servidor.")) +
      (startupFileConfigured ? " O arquivo principal foi configurado automaticamente." : " Se o provedor não iniciar automaticamente, ajuste o campo Main File/Startup para " + launcherFile + " no painel dele.")
  };
}


async function aclCloudsRequest(token, path = "", method = "GET", payload = null, form = null, raw = false) {
  const suffix = path ? (path.startsWith("?") ? path : (path.startsWith("/") ? path : "/" + path)) : "";
  const headers = { Authorization: "Bearer " + token, Accept: "application/json", "User-Agent": "BlackZoneStudio/1.0" };
  if (payload !== null && !form && !raw) headers["Content-Type"] = "application/json";
  if (raw) headers["Content-Type"] = "text/plain";
  const response = await fetch("https://aclclouds.com/api/client" + suffix, {
    method, headers,
    body: form || (payload === null ? undefined : (raw ? String(payload) : JSON.stringify(payload))),
    signal: AbortSignal.timeout(60000)
  });
  const text = await response.text();
  let data = {};
  if (text) { try { data = JSON.parse(text); } catch { data = { text }; } }
  if (!response.ok) {
    const first = Array.isArray(data?.errors) ? data.errors[0] : null;
    const code = String(first?.code || data?.code || data?.error || "");
    const reason = externalErrorText(first?.detail || data?.message || data?.error_description || data?.error || text) || ("HTTP " + response.status);
    const error = new Error("ACLClouds · " + method + " /api/client" + suffix + " · " + reason);
    error.status = response.status; error.code = code; throw error;
  }
  return { data, raw: text, status: response.status };
}
function aclCloudsAttributes(value) {
  if (!value || typeof value !== "object") return {};
  if (value.attributes && typeof value.attributes === "object") return value.attributes;
  if (value.data?.attributes && typeof value.data.attributes === "object") return value.data.attributes;
  return value.data && typeof value.data === "object" && !Array.isArray(value.data) ? value.data : value;
}
function aclCloudsIdentifier(value) {
  const id = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) throw new Error("Identificador de servidor ACLClouds inválido.");
  return id;
}
async function aclCloudsServices(token) {
  const services = [];
  for (let page = 1; page <= 50; page++) {
    const response = await aclCloudsRequest(token, "?per_page=100&page=" + page);
    const payload = response.data || {};
    const items = Array.isArray(payload.data) ? payload.data : (Array.isArray(payload) ? payload : []);
    services.push(...items.map(item => item?.attributes || item).filter(Boolean));
    const pagination = payload.meta?.pagination || null;
    if (!pagination || Number(pagination.current_page || page) >= Number(pagination.total_pages || page) || !items.length) break;
  }
  return services;
}
async function aclCloudsSetDiscordToken(token, serverId, bot, env) {
  if (!bot?.discord_token_enc) return false;
  try {
    const discordToken = await decryptSecret(bot.discord_token_enc, env);
    if (!discordToken) return false;
    const startup = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/startup");
    const variables = Array.isArray(startup.data?.data) ? startup.data.data : [];
    const preferred = ["DISCORD_TOKEN", "BOT_TOKEN", "TOKEN"];
    const variable = variables.find(item =>
      item?.attributes?.is_editable &&
      preferred.includes(String(item.attributes.env_variable || "").toUpperCase())
    );
    if (!variable?.attributes?.env_variable) return false;
    await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", {
      key: variable.attributes.env_variable, value: discordToken
    });
    return true;
  } catch {
    return false;
  }
}
function cogitIdentifier(value) {
  const id = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error("Identificador do servidor Cogithost inválido.");
  return id;
}
function keritIdentifier(value) {
  const id = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error("Identificador do servidor Kerit Cloud inválido.");
  return id;
}
async function providerToken(userId, provider, env) {
  const row = await env.DB.prepare(
    "SELECT encrypted_token FROM provider_connections WHERE user_id=? AND provider=?"
  ).bind(userId, provider).first();
  if (!row?.encrypted_token) return null;
  try { return await decryptSecret(row.encrypted_token, env); } catch { return null; }
}
const SHARED_HOSTING_OWNER_ID = "JL5lXxET1LffmlasSBxrgw";
const SHARED_FREE_HOST_PROVIDERS = new Set(["discloud","cubecloud","sillydev"]);
async function providerTokenForPool(userId, provider, env) {
  const ownToken = await providerToken(userId, provider, env);
  if (ownToken || String(userId) === SHARED_HOSTING_OWNER_ID || !SHARED_FREE_HOST_PROVIDERS.has(String(provider))) return ownToken;
  return await providerToken(SHARED_HOSTING_OWNER_ID, provider, env);
}
async function discloudRequest(token, path, method = "GET", form = null) {
  const headers = { "api-token": token, accept: "application/json" };
  if (!form) headers["content-type"] = "application/json";
  const response = await fetch("https://api.discloud.app/v2" + path, {
    method, headers, body: form || undefined, signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0, 1200) }; }
  if (!response.ok || data?.status === "error") {
    const reason = externalErrorText(data?.message || data?.error || data?.details || data) || ("HTTP " + response.status);
    throw new Error("Discloud · " + method + " " + path + " · HTTP " + response.status + ": " + reason);
  }
  return data;
}
function discloudExpectedProjectName(bot) {
  return String(bot?.name || "Discord Bot").normalize("NFKD").replace(/[^\w -]/g, "").trim().slice(0, 30) || "Discord Bot";
}
function discloudNormalizeProjectName(value) {
  return String(value || "").normalize("NFKD").replace(/[^\w -]/g, "").trim().slice(0, 30).toLowerCase();
}
function discloudLauncherForRuntime(runtime) {
  return String(runtime || "").toLowerCase() === "nodejs" ? "blackzone_launcher.cjs" : "blackzone_launcher.py";
}
async function findDiscloudProjectApp(token, appIds, expectedName, expectedMainFile) {
  const ids = [...new Set((Array.isArray(appIds) ? appIds : []).map(value => String(value || "")).filter(Boolean))];
  const matches = [];
  for (const appId of ids.slice(0, 12)) {
    try {
      const result = await discloudRequest(token, "/app/" + encodeURIComponent(appId));
      const app = result?.apps || result?.app || null;
      if (!app || String(app.id || appId) !== appId) continue;
      const nameMatches = discloudNormalizeProjectName(app.name) === discloudNormalizeProjectName(expectedName);
      const mainFile = String(app.mainFile || "").replace(/^\/+/, "").toLowerCase();
      if (nameMatches && mainFile === String(expectedMainFile || "").toLowerCase()) matches.push({ ...app, id: appId });
    } catch {}
  }
  return matches.length === 1 ? matches[0] : null;
}
async function recoverPendingDiscloudBot(bot, userId, env) {
  let project = bot?.custom_project;
  if (typeof project === "string") {
    try { project = JSON.parse(project || "null"); } catch { project = null; }
  }
  const pending = project?.discloudUploadPending;
  if (!pending || bot?.provider_app_id || bot?.hosting_deployment_id) return { pending: false };
  const token = await providerTokenForPool(userId, "discloud", env);
  if (!token) return { pending: true, error: "A tentativa anterior foi feita pela Discloud, mas a conta não está mais conectada. O Estúdio não tentará uma hospedagem paga nem criará outro servidor." };
  let account = null;
  try { account = (await discloudRequest(token, "/user"))?.user || null; }
  catch (error) {
    return { pending: true, error: "Não consegui consultar a Discloud para recuperar a tentativa anterior: " + String(error?.message || "falha de consulta") };
  }
  const appIds = Array.isArray(account?.apps) ? account.apps.map(value => String(value || "")).filter(Boolean) : null;
  if (!appIds) return { pending: true, error: "A Discloud não informou os aplicativos desta conta. O Estúdio não tentará criar outro servidor até confirmar a tentativa anterior." };
  const baseline = Array.isArray(pending.baselineAppIds) ? pending.baselineAppIds.map(String) : [];
  const candidates = appIds.filter(appId => !baseline.includes(appId));
  const expectedName = String(pending.expectedName || discloudExpectedProjectName(bot));
  const expectedMainFile = String(pending.expectedMainFile || discloudLauncherForRuntime(project?.runtime || bot.runtime));
  const recovered = candidates.length
    ? await findDiscloudProjectApp(token, candidates, expectedName, expectedMainFile)
    : null;
  if (!recovered) {
    const ageMs = Math.max(0, Date.now() - Number(pending.startedAt || 0));
    return {
      pending: true,
      notFound: true,
      retryAfter: ageMs < 300000,
      error: ageMs < 300000
        ? "A Discloud ainda pode estar processando o envio anterior. O Estúdio não vai tentar o Bot-Hosting novamente enquanto esse envio estiver pendente. Aguarde alguns minutos."
        : "A vaga do Bot-Hosting está cheia e a tentativa anterior da Discloud não apareceu na lista de aplicativos. Para preservar seu ZIP e evitar duplicidade, reimporte o mesmo arquivo na área Arquivos; o Estúdio vai consultar a Discloud antes de qualquer novo envio."
    };
  }
  const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='discloud' AND provider_app_id=? AND id<>? LIMIT 1")
    .bind(userId, String(recovered.id), bot.id).first();
  if (linked) return { pending: true, error: "A aplicação encontrada na Discloud já está vinculada a outro projeto do Estúdio. Nenhum bot foi alterado." };
  const cleanProject = { ...project };
  delete cleanProject.discloudUploadPending;
  await env.DB.prepare(
    "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='discloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?"
  ).bind(String(recovered.id), String(project.runtime || bot.runtime || "python"), JSON.stringify(cleanProject), Date.now(), bot.id, userId).run();
  let startMessage = "A aplicação recuperada está vinculada ao projeto.";
  try {
    await discloudRequest(token, "/app/" + encodeURIComponent(String(recovered.id)) + "/start", "PUT");
    startMessage = "A aplicação recuperada foi vinculada e o comando de início foi enviado.";
  } catch (error) {
    if (!/already|online|running|process|in process|409/i.test(String(error?.message || ""))) {
      startMessage += " O comando de início não foi confirmado: " + String(error?.message || "falha ao iniciar");
    }
  }
  return { pending: false, recovered: true, app: recovered, providerAppId: String(recovered.id), message: startMessage };
}
async function squareCloudRequest(token, path, method = "GET", payload = null, form = null) {
  const headers = { Authorization: token, accept: "application/json" };
  if (payload && !form) headers["content-type"] = "application/json";
  const response = await fetch("https://api.squarecloud.app/v2" + path, {
    method, headers,
    body: form || (payload ? JSON.stringify(payload) : undefined),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0, 1200) }; }
  if (!response.ok || data?.status === "error") {
    const code = String(data?.code || "");
    const reason = externalErrorText(data?.message || data?.error || code || data) || ("HTTP " + response.status);
    const error = new Error("Square Cloud · " + method + " " + path + " · " + (code ? code + ": " : "") + reason);
    error.code = code;
    error.status = response.status;
    throw error;
  }
  return data?.response ?? data;
}

async function cubeCloudRequest(token, path, method = "GET", payload = null, form = null) {
  const headers = { Authorization: "Bearer " + token, accept: "application/json" };
  if (payload && !form) headers["content-type"] = "application/json";
  const response = await fetch("https://app.cubehosting.com.br/api" + path, {
    method, headers, body: form || (payload ? JSON.stringify(payload) : undefined),
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0, 1200) }; }
  if (!response.ok || data?.ok === false || data?.status === "error") {
    const code = String(data?.code || data?.error?.code || "");
    const reason = externalErrorText(data?.message || data?.error?.message || data?.error || data?.details || raw) || ("HTTP " + response.status);
    const error = new Error("Cube Hosting · " + method + " " + path + " · " + (code ? code + ": " : "") + reason);
    error.code = code; error.status = response.status; throw error;
  }
  return data;
}
function cubeProjectId(value) {
  const id = String(value || "").trim();
  if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(id)) throw new Error("ID de projeto Cube Hosting inválido.");
  return id;
}
function cubeRelativePath(value) {
  return safeVolumePath(value || "/").replace(/^\/+/, "");
}
async function cubeCloudLogs(token, projectId) {
  const id = cubeProjectId(projectId);
  const response = await fetch("https://app.cubehosting.com.br/api/projects/" + encodeURIComponent(id) + "/logs?lines=120", {
    headers: { Authorization: "Bearer " + token, accept: "text/event-stream, application/json" },
    signal: AbortSignal.timeout(60000)
  });
  const raw = await response.text();
  if (!response.ok) {
    let data = {}; try { data = JSON.parse(raw); } catch {}
    const error = new Error("Cube Hosting · logs · HTTP " + response.status + ": " + externalErrorText(data.message || data.error || raw));
    error.code = data.code || ""; error.status = response.status; throw error;
  }
  const lines = [];
  for (const event of raw.split(/\r?\n\r?\n/)) {
    const eventType = (event.match(/^event:\s*(.+)$/m) || [])[1] || "";
    const payload = (event.match(/^data:\s*(.+)$/m) || [])[1] || "";
    if (!payload) continue;
    try {
      const item = JSON.parse(payload);
      if (eventType === "line") lines.push(String(item.text || ""));
    } catch { if (eventType === "line") lines.push(payload); }
  }
  return { provider: "cubecloud", lines: lines.filter(Boolean).slice(-200), logs: lines.filter(Boolean).slice(-200), raw };
}
async function prepareCubeCloudProject(archiveBytes, bot, requestedRuntime, env) {
  const input = await JSZip.loadAsync(archiveBytes, { checkCRC32: false, createFolders: false });
  const entries = Object.values(input.files).filter(file => !file.dir);
  if (!entries.length) throw new Error("O ZIP não contém arquivos de projeto.");
  if (entries.length > 6000) throw new Error("O ZIP contém arquivos demais para a importação automática (limite: 6.000).");
  const names = entries.map(file => String(file.name || "").replace(/\\/g, "/"));
  for (const name of names) {
    if (!name || name.startsWith("/") || name.split("/").some(part => part === "..")) throw new Error("O ZIP contém um caminho de arquivo inválido.");
  }
  const rootFiles = names.filter(name => !name.includes("/") && !name.startsWith("__MACOSX"));
  const roots = [...new Set(names.filter(name => name.includes("/")).map(name => name.split("/")[0]))];
  const wrapper = rootFiles.length === 0 && roots.length === 1 ? roots[0] + "/" : "";
  const ignored = new Set([".git","node_modules",".venv","venv","__pycache__",".pytest_cache",".mypy_cache",".next","__macosx"]);
  const output = new JSZip();
  const filePaths = [];
  let totalUnpacked = 0, dotenv = "";
  for (let i = 0; i < entries.length; i++) {
    let relative = wrapper && names[i].startsWith(wrapper) ? names[i].slice(wrapper.length) : names[i];
    relative = cleanProjectEntry(relative);
    if (!relative || relative.endsWith("/")) continue;
    const parts = relative.split("/");
    const base = parts[parts.length - 1];
    if (parts.some(part => ignored.has(part.toLowerCase())) || base === ".DS_Store" || base.startsWith("._")) continue;
    const expectedSize = Number(entries[i]._data?.uncompressedSize || entries[i]._data?.compressedSize || 0);
    totalUnpacked += expectedSize;
    if (totalUnpacked > 50 * 1024 * 1024) throw new Error("O conteúdo descompactado passa de 50 MB. Remova caches e dependências locais.");
    const bytes = await entries[i].async("uint8array");
    if (relative.toLowerCase() === ".env") {
      dotenv = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      continue;
    }
    output.file(relative, bytes);
    filePaths.push(relative);
  }
  if (!filePaths.length) throw new Error("Não encontrei arquivos de projeto depois de remover caches e dependências locais.");
  let packageJson = {};
  const packagePath = filePaths.find(path => path.toLowerCase() === "package.json");
  if (packagePath) {
    try { packageJson = JSON.parse(await output.file(packagePath).async("string")); }
    catch { throw new Error("O package.json do projeto não é um JSON válido."); }
  }
  const hasNode = !!packagePath || filePaths.some(path => /\.(?:js|mjs|cjs|ts|mts|cts)$/i.test(path));
  const runtime = String(requestedRuntime || (hasNode ? "nodejs" : "python")).toLowerCase() === "nodejs" ? "nodejs" : "python";
  const envs = {};
  for (const line of dotenv.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    let value = match[2] || "";
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, "").trim();
    envs[match[1]] = value;
  }
  let entryFile = "", command = "";
  if (runtime === "nodejs") {
    const startScript = String(packageJson.scripts?.start || "").trim();
    entryFile = String(packageJson.main || "").trim();
    if (!entryFile) entryFile = filePaths.find(path => /^(?:index|main|bot|app)\.(?:js|mjs|cjs)$/i.test(path)) || filePaths.find(path => /\.(?:js|mjs|cjs)$/i.test(path)) || "";
    command = startScript ? "npm start" : (entryFile ? "node " + entryFile : "");
    if (!command) throw new Error("Não encontrei o arquivo principal Node.js nem um script start no package.json.");
  } else {
    entryFile = filePaths.find(path => /^(?:main|bot|runner|app|index)\.py$/i.test(path)) || filePaths.find(path => /\.py$/i.test(path)) || "";
    command = entryFile ? "python " + entryFile : "";
    if (!command) throw new Error("Não encontrei o arquivo principal Python no ZIP.");
  }
  let discordToken = null;
  try { if (bot.discord_token_enc) discordToken = await decryptSecret(bot.discord_token_enc, env); } catch {}
  if (discordToken) {
    envs.DISCORD_TOKEN = discordToken; envs.BOT_TOKEN = discordToken; envs.TOKEN = discordToken;
  }
  envs.APP_URL = env.APP_URL || "https://black-zone-estudio.vercel.app";
  envs.BOT_NAME = String(bot.name || "Discord Bot");
  for (const [key, value] of Object.entries(envs)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || String(value).length > 10000) delete envs[key];
  }
  let priorConfig = {};
  if (filePaths.includes("cube.json")) {
    try { priorConfig = JSON.parse(await output.file("cube.json").async("string")); } catch {}
  }
  output.file("cube.json", JSON.stringify({
    ...priorConfig,
    name: String(bot.name || "Discord Bot").replace(/[^A-Za-z0-9 ._-]/g, "").slice(0, 40) || "Discord Bot",
    type: "bot",
    language: runtime === "nodejs" ? "node" : "python",
    version: runtime === "nodejs" ? "22" : "3.12",
    command
  }, null, 2));
  const bytes = await output.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
  return {
    bytes, runtime, envs,
    customProject: {
      runtime, entryFile, fileCount: filePaths.length + 1,
      directories: [...new Set(filePaths.map(path => path.split("/").slice(0,-1).join("/")).filter(Boolean))].length,
      dependencyFile: filePaths.find(path => /^(?:package\.json|requirements\.txt|pyproject\.toml)$/i.test(path)) || null
    }
  };
}
function squareAppId(value) {
  const id = String(value || "").trim();
  if (!/^[a-f0-9]{32}(?:-[a-f0-9-]+)?$/i.test(id)) throw new Error("ID de aplicação Square Cloud inválido.");
  return id;
}
function decodeBase64Text(value) {
  const binary = atob(String(value || ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
async function prepareSquareCloudProject(archiveBytes, bot, requestedRuntime, env) {
  const input = await JSZip.loadAsync(archiveBytes, { checkCRC32: false, createFolders: false });
  const entries = Object.values(input.files).filter(file => !file.dir);
  if (!entries.length) throw new Error("O ZIP não contém arquivos de projeto.");
  if (entries.length > 6000) throw new Error("O ZIP contém arquivos demais para a importação automática (limite: 6.000).");
  const names = entries.map(file => String(file.name || "").replace(/\\/g, "/"));
  for (const name of names) {
    if (!name || name.startsWith("/") || name.split("/").some(part => part === "..")) {
      throw new Error("O ZIP contém um caminho de arquivo inválido. Compacte novamente a pasta do bot.");
    }
  }
  const rootFiles = names.filter(name => !name.includes("/") && !name.startsWith("__MACOSX"));
  const roots = [...new Set(names.filter(name => name.includes("/")).map(name => name.split("/")[0]))];
  const wrapper = rootFiles.length === 0 && roots.length === 1 ? roots[0] + "/" : "";
  const ignored = new Set([".git","node_modules",".venv","venv","__pycache__",".pytest_cache",".mypy_cache",".next","__macosx"]);
  const output = new JSZip();
  const filePaths = [];
  let totalUnpacked = 0;
  let directoryCount = 0;
  let dotenv = "";
  for (let i = 0; i < entries.length; i++) {
    let relative = wrapper && names[i].startsWith(wrapper) ? names[i].slice(wrapper.length) : names[i];
    relative = cleanProjectEntry(relative);
    if (!relative || relative.endsWith("/")) continue;
    const parts = relative.split("/");
    if (parts.some(part => ignored.has(part.toLowerCase())) || parts[parts.length - 1] === ".DS_Store" || parts[parts.length - 1].startsWith("._")) continue;
    const expectedSize = Number(entries[i]._data?.uncompressedSize || entries[i]._data?.compressedSize || 0);
    totalUnpacked += expectedSize;
    if (totalUnpacked > 50 * 1024 * 1024) throw new Error("O conteúdo descompactado passa de 50 MB. Remova caches e dependências já instaladas e envie novamente.");
    const bytes = await entries[i].async("uint8array");
    if (relative.toLowerCase() === ".env") {
      dotenv = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      continue;
    }
    output.file(relative, bytes);
    filePaths.push(relative);
    directoryCount += Math.max(0, parts.length - 1);
  }
  if (!filePaths.length) throw new Error("Não encontrei arquivos válidos no ZIP depois de remover caches e dependências locais.");
  let packageJson = {};
  const packagePath = filePaths.find(path => path.toLowerCase() === "package.json");
  if (packagePath) {
    try { packageJson = JSON.parse(await output.file(packagePath).async("string")); }
    catch { throw new Error("O package.json do projeto não é um JSON válido."); }
  }
  const hasJs = filePaths.some(path => /\.(?:js|mjs|cjs|ts|mts|cts)$/i.test(path));
  const hasPython = filePaths.some(path => /\.py$/i.test(path)) || filePaths.some(path => /(?:^|\/)(?:requirements\.txt|pyproject\.toml|pipfile|setup\.py)$/i.test(path));
  let runtime = String(requestedRuntime || bot.runtime || "").toLowerCase();
  if (!["python","nodejs"].includes(runtime)) runtime = packagePath && hasJs ? "nodejs" : (hasPython && !hasJs ? "python" : (hasJs ? "nodejs" : "python"));
  if (runtime === "nodejs" && !hasJs) runtime = "python";
  if (runtime === "python" && !hasPython && hasJs) runtime = "nodejs";
  const pathSet = new Set(filePaths);
  let entryFile = "";
  let startCommand = "";
  if (runtime === "nodejs") {
    const candidates = [
      cleanProjectEntry(packageJson?.main),
      "index.js","bot.js","main.js","app.js","start.js","src/index.js","src/bot.js","src/main.js","bot/index.js"
    ].filter(Boolean);
    entryFile = candidates.find(path => pathSet.has(path)) || filePaths.find(path => /\.(?:js|mjs|cjs)$/i.test(path)) || "";
    if (String(packageJson?.scripts?.start || "").trim()) startCommand = "npm run start";
    else if (entryFile) startCommand = "node " + shellQuote(entryFile);
  } else {
    const candidates = ["main.py","bot.py","run.py","app.py","index.py","start.py","src/main.py","src/bot.py","bot/main.py"];
    entryFile = candidates.find(path => pathSet.has(path)) || filePaths.find(path => /\.py$/i.test(path)) || "";
    if (entryFile) startCommand = "python " + shellQuote(entryFile);
  }
  if (!entryFile) throw new Error("Não consegui identificar o arquivo principal. Inclua main.py, bot.py, index.js ou bot.js no ZIP.");
  const envs = {};
  for (const line of dotenv.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)\s*$/);
    if (!match) continue;
    let value = match[2].trim();
    if (value.length >= 2 && ((value[0] === '"' && value[value.length-1] === '"') || (value[0] === "'" && value[value.length-1] === "'"))) value = value.slice(1,-1);
    envs[match[1]] = value;
  }
  const token = bot.discord_token_enc ? await decryptSecret(bot.discord_token_enc, env) : null;
  if (token) {
    envs.DISCORD_TOKEN = token;
    envs.BOT_TOKEN = token;
    envs.TOKEN = token;
  }
  envs.APP_URL = "https://black-zone-estudio.vercel.app";
  envs.BOT_NAME = bot.name || "Discord Bot";
  const displayName = String(bot.name || "Discord Bot").replace(/[^\w .-]/g, "").trim().slice(0, 32) || "Discord Bot";
  let squareMain = entryFile;
  if (runtime === "nodejs") {
    squareMain = "bz_launcher.mjs";
    output.file(squareMain, [
      "import { pathToFileURL } from 'node:url';",
      "import { resolve } from 'node:path';",
      "await import(pathToFileURL(resolve(process.cwd(), " + JSON.stringify(entryFile) + ")).href);",
      ""
    ].join("\n"));
  } else {
    squareMain = "bz_launcher.py";
    output.file(squareMain, [
      "import runpy",
      "runpy.run_path(" + JSON.stringify(entryFile) + ", run_name='__main__')",
      ""
    ].join("\n"));
  }
  const config = [
    "MAIN=" + squareMain,
    "MEMORY=512",
    "VERSION=recommended",
    "DISPLAY_NAME=" + displayName,
    startCommand ? "START=" + startCommand : "",
    "AUTORESTART=true"
  ].filter(Boolean).join("\n") + "\n";
  output.file("squarecloud.app", config);
  const bytes = await output.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
  const imageCount = filePaths.filter(path => /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f)$/i.test(path)).length;
  const resourceCount = filePaths.filter(path => /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf)$/i.test(path)).length;
  const dependencyFile = filePaths.find(path => /(?:^|\/)(?:requirements\.txt|pyproject\.toml|pipfile|package\.json|gemfile|cargo\.toml)$/i.test(path)) || null;
  return {
    bytes, runtime, entryFile, startCommand, envs, fileCount: filePaths.length,
    directoryCount, imageCount, resourceCount, dependencyFile, tokenIncluded: !!token,
    customProject: {
      packageName: String(bot.name || "meu-bot").slice(0, 64), rootPath: "/",
      runtime, entryFile, startCommand, dependencyFile,
      fileCount: filePaths.length, directoryCount, imageCount, resourceCount,
      commandFileCount: filePaths.filter(path => /(?:^|\/)(?:commands|cogs|extensions|plugins|handlers|events|slash_commands|text_commands)\//i.test(path)).length,
      detectedFolders: [...new Set(filePaths.map(path => path.split("/")[0]))].filter(folder => filePaths.some(path => path.startsWith(folder + "/"))).slice(0, 20),
      importedAt: Date.now()
    }
  };
}
function decodeBase64Bytes(value) {
  const encoded = String(value || "");
  if (!encoded || encoded.length > 8 * 1024 * 1024) throw new Error("O ZIP enviado está vazio ou excede o limite de 5 MB do painel.");
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function cleanProjectEntry(value) {
  const path = String(value || "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
  if (!path || path.length > 240 || path.split("/").some(part => !part || part === "." || part === "..") || /[\r\n\0]/.test(path)) return "";
  return path;
}
function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}
async function prepareDiscloudProject(archiveBytes, bot, requestedRuntime, env) {
  const input = await JSZip.loadAsync(archiveBytes, { checkCRC32: false, createFolders: false });
  const entries = Object.values(input.files).filter(file => !file.dir);
  if (!entries.length) throw new Error("O ZIP não contém arquivos de projeto.");
  if (entries.length > 6000) throw new Error("O ZIP contém arquivos demais para a importação automática (limite: 6.000).");
  const cleanedNames = entries.map(file => String(file.name || "").replace(/\\/g, "/"));
  for (const name of cleanedNames) {
    if (!name || name.startsWith("/") || name.split("/").some(part => part === "..")) {
      throw new Error("O ZIP contém um caminho de arquivo inválido. Compacte novamente a pasta do bot.");
    }
  }
  const rootFiles = cleanedNames.filter(name => !name.includes("/") && !name.startsWith("__MACOSX"));
  const topFolders = [...new Set(cleanedNames.filter(name => name.includes("/")).map(name => name.split("/")[0]))];
  const wrapper = rootFiles.length === 0 && topFolders.length === 1 ? topFolders[0] + "/" : "";
  const ignored = new Set([".git","node_modules",".venv","venv","__pycache__",".pytest_cache",".mypy_cache",".next","__macosx"]);
  const output = new JSZip();
  const filePaths = [];
  let totalUnpacked = 0;
  let directoryCount = 0;
  for (let i = 0; i < entries.length; i++) {
    const originalName = cleanedNames[i];
    let relative = wrapper && originalName.startsWith(wrapper) ? originalName.slice(wrapper.length) : originalName;
    relative = cleanProjectEntry(relative);
    if (!relative || relative.endsWith("/")) continue;
    const parts = relative.split("/");
    if (parts.some(part => ignored.has(part.toLowerCase())) || parts[parts.length - 1] === ".DS_Store" || parts[parts.length - 1].startsWith("._")) continue;
    const expectedSize = Number(entries[i]._data?.uncompressedSize || entries[i]._data?.compressedSize || 0);
    totalUnpacked += expectedSize;
    if (totalUnpacked > 50 * 1024 * 1024) throw new Error("O conteúdo descompactado passa de 50 MB. Remova caches e dependências já instaladas e envie novamente.");
    const bytes = await entries[i].async("uint8array");
    output.file(relative, bytes);
    filePaths.push(relative);
    directoryCount += Math.max(0, parts.length - 1);
  }
  if (!filePaths.length) throw new Error("Não encontrei arquivos válidos no ZIP depois de remover caches e dependências locais.");
  let packageJson = {};
  const packagePath = filePaths.find(path => path.toLowerCase() === "package.json");
  if (packagePath) {
    try { packageJson = JSON.parse(await output.file(packagePath).async("string")); } catch { throw new Error("O package.json do projeto não é um JSON válido."); }
  }
  const hasJs = filePaths.some(path => /\.(?:js|mjs|cjs|ts|mts|cts)$/i.test(path));
  const hasPython = filePaths.some(path => /\.py$/i.test(path)) || filePaths.some(path => /(?:^|\/)(?:requirements\.txt|pyproject\.toml|pipfile|setup\.py)$/i.test(path));
  let runtime = String(requestedRuntime || bot.runtime || "").toLowerCase();
  if (!["python","nodejs"].includes(runtime)) runtime = packagePath && hasJs ? "nodejs" : (hasPython && !hasJs ? "python" : (hasJs ? "nodejs" : "python"));
  if (runtime === "nodejs" && !hasJs) runtime = "python";
  if (runtime === "python" && !hasPython && hasJs) runtime = "nodejs";
  const pathSet = new Set(filePaths);
  let entryFile = "";
  let startCommand = "";
  if (runtime === "nodejs") {
    const rawStart = String(packageJson?.scripts?.start || "").trim();
    const scriptMatch = rawStart.match(/(?:^|\s)(?:node|tsx|ts-node|nodemon|bun)\s+(?:--[^\s]+\s+)*["']?([^"'\s;&|]+)/i);
    const candidates = [
      cleanProjectEntry(packageJson?.main),
      cleanProjectEntry(scriptMatch?.[1]),
      "index.js","bot.js","main.js","app.js","start.js","src/index.js","src/bot.js","src/main.js","bot/index.js"
    ].filter(Boolean);
    entryFile = candidates.find(path => pathSet.has(path)) || filePaths.find(path => /\.(?:js|mjs|cjs)$/i.test(path)) || "";
    if (rawStart) startCommand = rawStart;
    else if (entryFile) startCommand = "node " + shellQuote(entryFile);
  } else {
    const candidates = ["main.py","bot.py","run.py","app.py","index.py","start.py","src/main.py","src/bot.py","bot/main.py"];
    entryFile = candidates.find(path => pathSet.has(path)) || filePaths.find(path => /\.py$/i.test(path)) || "";
    if (entryFile) startCommand = "python " + shellQuote(entryFile);
  }
  if (!entryFile) throw new Error("Não consegui identificar o arquivo principal. Inclua main.py, bot.py, index.js, bot.js ou indique a inicialização pelo package.json.");
  const botName = String(bot.name || "Discord Bot").normalize("NFKD").replace(/[^\w -]/g, "").trim().slice(0, 30) || "Discord Bot";
  const token = bot.discord_token_enc ? await decryptSecret(bot.discord_token_enc, env) : null;
  let envText = output.file(".env") ? await output.file(".env").async("string") : "";
  const envValues = new Map();
  for (const line of envText.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)\s*$/);
    if (match) envValues.set(match[1], match[2]);
  }
  if (token) {
    for (const key of ["DISCORD_TOKEN","BOT_TOKEN","TOKEN"]) envValues.set(key, token);
  }
  envValues.set("APP_URL", "https://black-zone-estudio.vercel.app");
  envValues.set("BOT_NAME", bot.name || "Discord Bot");
  output.file(".env", [...envValues.entries()].map(([key, value]) => key + "=" + JSON.stringify(String(value))).join("\n") + "\n");
  let mainFile = "";
  if (runtime === "nodejs") {
    mainFile = "blackzone_launcher.cjs";
    const launcher = String.raw`const fs=require("node:fs");
const path=require("node:path");
const {spawn}=require("node:child_process");
const {pathToFileURL}=require("node:url");
for(const line of (fs.existsSync(".env")?fs.readFileSync(".env","utf8"):"").split(/\r?\n/)){
 const m=line.match(/^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)\s*$/);
 if(!m)continue;
 let value=m[2].trim();
 if((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")))value=value.slice(1,-1);
 process.env[m[1]]=value;
}
(async()=>{
 if(${JSON.stringify(!!packageJson?.scripts?.start)}){
  const child=spawn("npm",["run","start"],{stdio:"inherit",env:process.env});
  const forward=(signal)=>{if(child.exitCode===null)child.kill(signal)};
  process.on("SIGTERM",()=>forward("SIGTERM"));
  process.on("SIGINT",()=>forward("SIGINT"));
  child.on("exit",(code,signal)=>{process.exitCode=code??(signal?1:0)});
  child.on("error",error=>{console.error("BLACK ZONE launcher:",error);process.exitCode=1});
 }else{
  const target=path.resolve(process.cwd(), ${JSON.stringify(entryFile)});
  await import(pathToFileURL(target).href);
 }
})().catch(error=>{console.error("BLACK ZONE launcher:",error);process.exitCode=1;});`;
    output.file(mainFile, launcher);
  } else {
    mainFile = "blackzone_launcher.py";
    const launcher = String.raw`from pathlib import Path
import os
import runpy

env_file = Path(".env")
if env_file.exists():
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            os.environ[key] = value

runpy.run_path(${JSON.stringify(entryFile)}, run_name="__main__")
`;
    output.file(mainFile, launcher);
  }
  const config = [
    "NAME=" + botName,
    "TYPE=bot",
    "MAIN=" + mainFile,
    "RAM=100",
    "VERSION=latest"
  ].join("\n") + "\n";
  output.file("discloud.config", config);
  const bytes = await output.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
  const imageCount = filePaths.filter(path => /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f)$/i.test(path)).length;
  const resourceCount = filePaths.filter(path => /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf)$/i.test(path)).length;
  const dependencyFile = filePaths.find(path => /(?:^|\/)(?:requirements\.txt|pyproject\.toml|pipfile|package\.json|gemfile|cargo\.toml)$/i.test(path)) || null;
  return {
    bytes, runtime, entryFile, startCommand, fileCount: filePaths.length,
    directoryCount, imageCount, resourceCount, dependencyFile, tokenIncluded: !!token,
    customProject: {
      packageName: String(bot.name || "meu-bot").slice(0, 64), rootPath: "/",
      runtime, entryFile, startCommand: null, dependencyFile,
      fileCount: filePaths.length, directoryCount, imageCount, resourceCount,
      commandFileCount: filePaths.filter(path => /(?:^|\/)(?:commands|cogs|extensions|plugins|handlers|events|slash_commands|text_commands)\//i.test(path)).length,
      detectedFolders: [...new Set(filePaths.map(path => path.split("/")[0]))].filter(folder => filePaths.some(path => path.startsWith(folder + "/"))).slice(0, 20),
      importedAt: Date.now()
    }
  };
}
async function getOwnedBot(id, userId, env) {
  return env.DB.prepare(
    "SELECT id,name,runtime,state,modules,project_type,custom_project,discord_token_enc,discord_bot_id,discord_bot_name,hosting_deployment_id,hosting_provider,provider_app_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE id=? AND user_id=?"
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
  const ignored = new Set([".git","node_modules",".venv","venv","__pycache__",".pytest_cache",".mypy_cache",".next","__MACOSX"]);
  const imageExt = /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f)$/i;
  const resourceExt = /\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf)$/i;
  const commandFolders = new Set(["commands","cogs","extensions","plugins","handlers","events","slash_commands","text_commands"]);
  const resourceFolders = new Set(["assets","images","image","img","media","fonts","locales","translations","data","resources"]);
  const queue = [{ path: "/", depth: 0 }];
  const seen = new Set();
  const files = [];
  let rootEntries = [];
  let directoryCount = 0;
  while (queue.length && files.length < 12000) {
    const item = queue.shift();
    if (seen.has(item.path) || item.depth > 12) continue;
    seen.add(item.path);
    const listing = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files?path=" + encodeURIComponent(item.path));
    const entries = Array.isArray(listing.entries) ? listing.entries : [];
    if (item.path === "/") rootEntries = entries;
    for (const e of entries) {
      const name = String(e?.name || "");
      if (!name || name === "." || name === ".." || name === ".DS_Store" || name.startsWith("._")) continue;
      const full = safeVolumePath((item.path === "/" ? "" : item.path) + "/" + name);
      const type = String(e?.type || "").toLowerCase();
      if (type === "directory" || type === "folder" || type === "dir") {
        if (ignored.has(name.toLowerCase())) continue;
        directoryCount++;
        if (item.depth < 12) queue.push({ path: full, depth: item.depth + 1 });
      } else if (type === "file" || (!type && /\.[^/]+$/.test(name))) {
        files.push(full);
      }
    }
  }
  if (queue.length) {
    throw new Error("O projeto tem mais de 12.000 arquivos ou pastas profundas demais para a análise automática. Remova caches e dependências já instaladas (node_modules, .venv e __pycache__) e envie novamente.");
  }

  const rootFiles = rootEntries.filter(e => String(e?.type || "").toLowerCase() === "file" && String(e?.name || "") !== ".DS_Store" && !String(e?.name || "").startsWith("._"));
  const rootDirs = rootEntries.filter(e => {
    const type = String(e?.type || "").toLowerCase();
    return (type === "directory" || type === "folder" || type === "dir") && !ignored.has(String(e.name || "").toLowerCase());
  });
  if (!rootFiles.length && rootDirs.length === 1) {
    const wrapper = String(rootDirs[0].name || "");
    const inner = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files?path=" + encodeURIComponent("/" + wrapper));
    const children = (Array.isArray(inner.entries) ? inner.entries : [])
      .filter(e => e?.name && e.name !== "." && e.name !== ".." && e.name !== ".DS_Store")
      .map(e => wrapper + "/" + String(e.name));
    if (children.length) {
      const moved = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/move", "POST", { files: children, to: "/" });
      if (Array.isArray(moved.failed) && moved.failed.length) {
        throw new Error("Encontrei a pasta principal do ZIP, mas não consegui organizar todos os arquivos: " +
          moved.failed.slice(0, 5).map(x => String(x.from || x.path || "arquivo") + " — " + String(x.reason || "falha")).join("; "));
      }
      const removed = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/delete", "POST", { root: "/", files: [wrapper] });
      if (Array.isArray(removed.failed) && removed.failed.length) {
        throw new Error("Os arquivos foram movidos, mas a pasta externa do ZIP não pôde ser limpa. Atualize a lista e tente analisar novamente.");
      }
      return scanImportedProject(userId, env, deploymentId);
    }
  }

  const relative = files.map(p => p.replace(/^\//, ""));
  const lower = relative.map(p => p.toLowerCase());
  const has = path => lower.includes(path.toLowerCase());
  const fileAt = path => relative[lower.indexOf(path.toLowerCase())] || null;
  const pyPriority = [
    "main.py","bot.py","run.py","app.py","index.py","start.py",
    "src/main.py","src/bot.py","bot/main.py","src/index.py","src/app.py",
    "discord_bot.py","launcher.py"
  ];
  const jsPriority = [
    "index.js","bot.js","main.js","app.js","index.mjs","bot.mjs","index.cjs","bot.cjs",
    "src/index.js","src/bot.js","src/main.js","bot/index.js","dist/index.js","dist/bot.js"
  ];
  const score = (path, preferred) => {
    const p = path.toLowerCase();
    const exact = preferred.indexOf(p);
    if (exact >= 0) return exact;
    const base = p.split("/").pop();
    const tail = preferred.findIndex(x => x.split("/").pop() === base);
    if (tail >= 0) return 40 + tail;
    if (/\/(?:cogs|commands|extensions|plugins|events)\//.test("/" + p)) return 500;
    if (/^(?:setup|config|settings|__init__)\.py$/i.test(base)) return 900;
    return 700;
  };
  const py = relative.filter(p => /\.py$/i.test(p)).sort((a,b)=>score(a,pyPriority)-score(b,pyPriority));
  const js = relative.filter(p => /\.(?:js|mjs|cjs)$/i.test(p)).sort((a,b)=>score(a,jsPriority)-score(b,jsPriority));

  const packagePath = relative.find(p => p.toLowerCase() === "package.json") ||
    relative.find(p => p.toLowerCase().endsWith("/package.json"));
  let pkg = null;
  if (packagePath) {
    try {
      const r = await hostRequest(userId, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/content?path=" + encodeURIComponent("/" + packagePath));
      pkg = JSON.parse(String(r.content || "{}"));
    } catch {}
  }
  const hasPythonManifest = relative.some(p => /^(?:requirements\.txt|pyproject\.toml|Pipfile|setup\.py)$/i.test(p.split("/").pop()));
  const hasNodeManifest = !!packagePath;
  const pythonSignal = py.length > 0 || hasPythonManifest;
  const nodeSignal = js.length > 0 || hasNodeManifest;
  let runtime = "python";
  if (hasNodeManifest && nodeSignal && (pkg?.scripts?.start || pkg?.main || !pythonSignal)) runtime = "nodejs";
  else if (!pythonSignal && nodeSignal) runtime = "nodejs";
  else if (pythonSignal) runtime = "python";

  let entryFile = "";
  let startCommand = null;
  if (runtime === "nodejs") {
    const declaredMain = typeof pkg?.main === "string" ? pkg.main.replace(/^\.\//, "").replace(/^\/+/, "") : "";
    if (declaredMain && relative.includes(declaredMain)) entryFile = declaredMain;
    if (!entryFile && typeof pkg?.scripts?.start === "string") {
      const script = pkg.scripts.start;
      const commandMatch = script.match(/(?:^|[;&|]\s*)(?:node|tsx|ts-node|nodemon)\s+(?:\.\/)?([A-Za-z0-9_./-]+\.(?:js|mjs|cjs|ts|mts|cts))/i);
      if (commandMatch && relative.includes(commandMatch[1])) entryFile = commandMatch[1];
    }
    if (!entryFile) entryFile = js.find(p => score(p, jsPriority) < 40) || js[0] || "";
    if (pkg?.scripts?.start) startCommand = "npm install && npm start";
  } else {
    entryFile = py.find(p => score(p, pyPriority) < 40) || py[0] || "";
  }

  const commandFiles = relative.filter(p => {
    const parts = p.toLowerCase().split("/");
    return parts.some(part => commandFolders.has(part)) ||
      /(?:^|\/)(?:commands?|handlers?)\.(?:py|js|mjs|cjs|ts)$/i.test(p);
  });
  const detectedFolders = [...new Set(relative.flatMap(p => p.toLowerCase().split("/").slice(0, -1))
    .filter(name => commandFolders.has(name) || resourceFolders.has(name)))].sort();
  const imageCount = files.filter(p => imageExt.test(p)).length;
  const resourceCount = files.filter(p => resourceExt.test(p)).length;
  const dependencyFile = runtime === "nodejs"
    ? (packagePath ? packagePath : null)
    : (relative.find(p => p.toLowerCase() === "requirements.txt") ||
       relative.find(p => p.toLowerCase() === "pyproject.toml") ||
       relative.find(p => p.toLowerCase() === "pipfile") ||
       relative.find(p => p.toLowerCase() === "setup.py") || null);

  if (!entryFile) {
    return {
      ok: false, needsEntryFile: true, runtime, fileCount: files.length,
      directoryCount, imageCount, resourceCount, commandFileCount: commandFiles.length,
      detectedFolders,
      candidates: [...py.slice(0,16).map(path => ({path,runtime:"python"})), ...js.slice(0,16).map(path => ({path,runtime:"nodejs"}))],
      manifests: relative.filter(p => /(?:requirements\.txt|pyproject\.toml|Pipfile|setup\.py|package\.json)$/i.test(p)),
      error: "Recebi os arquivos e encontrei a estrutura, mas não consegui identificar com segurança o arquivo que inicia o bot. Confira os candidatos e selecione/renomeie o arquivo principal para main.py, bot.py, index.js ou bot.js."
    };
  }
  return {
    ok: true, runtime, entryFile, startCommand, dependencyFile,
    fileCount: files.length, directoryCount, imageCount, resourceCount,
    commandFileCount: commandFiles.length, detectedFolders
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
    const auth = await requireUser(request, env); if (auth.error) return auth.error;
    const user = auth.user;


    if (path === "/admin/caos/status" && request.method === "GET") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (settings && String(settings.owner_user_id) !== String(user.id)) return reply({ error: "A configuração CAOS pertence a outra conta." }, 403);
      const hosting = await adminCaosHostingInfo(user.id, env);
      const runtime = await readAdminCaosRuntime(user.id, env, settings);
      return reply({
        configured: !!settings?.bot_token_enc,
        hasToken: !!settings?.bot_token_enc,
        botId: settings?.bot_id || null,
        botName: settings?.bot_name || null,
        deploymentId: settings?.hosting_deployment_id || null,
        packageUploaded: !!settings?.package_uploaded_at,
        packageReplacementPending: settings?.state === "replacement_pending",
        updatedAt: settings?.updated_at || null,
        ...hosting,
        runtime
      });
    }
    if (path === "/admin/caos/config" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      try {
        const result = await saveAdminCaosToken(user, await body(request), env);
        return reply(result);
      } catch (error) {
        return reply({ error: error.message || "Não foi possível salvar o token CAOS." }, 400);
      }
    }

    if (path === "/admin/caos/replace-package" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (!settings?.package_uploaded_at) return reply({ error: "Não existe um pacote instalado para substituir." }, 409);
      const deploymentId = String(settings.hosting_deployment_id || "");
      if (!deploymentId) return reply({ error: "A hospedagem CAOS não está vinculada." }, 409);
      try {
        const diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=3");
        let currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        if (!currentState) {
          const current = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId));
          currentState = String(current.state || current.deployment?.state || "").toLowerCase();
        }
        if (!currentState) throw new Error("Não consegui confirmar o estado do bot. O pacote antigo foi mantido.");
        if (!["offline","stopped","terminated"].includes(currentState)) {
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "stop", waitSeconds: 25 });
        }
        const backupScript = "from pathlib import Path\nimport shutil, sqlite3\nsource = Path(\"/home/container/caos.sqlite3\")\nbackup = Path(\"/home/container/.blackzone-caos.sqlite3.backup\")\nif not source.is_file():\n    raise SystemExit(\"BANCO_NAO_ENCONTRADO: /home/container/caos.sqlite3\")\ncon = sqlite3.connect(str(source), timeout=10)\ncon.execute(\"PRAGMA wal_checkpoint(FULL)\")\ncon.close()\nshutil.copy2(source, backup)\nif not backup.is_file() or backup.stat().st_size != source.stat().st_size:\n    raise SystemExit(\"FALHA_VERIFICACAO_BACKUP_SQLITE\")\nprint(\"BLACKZONE_SQLITE_BACKUP_OK bytes=\" + str(backup.stat().st_size))";
        const backupResult = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/shell", "POST", {
          command: "python - <<'PY'\n" + backupScript + "\nPY", timeout: 35, maxChars: 5000
        });
        const backupText = String(backupResult?.stdout || backupResult?.output || backupResult?.message || JSON.stringify(backupResult));
        if (!backupText.includes("BLACKZONE_SQLITE_BACKUP_OK")) {
          throw new Error("A hospedagem não confirmou o backup do banco SQLite. O ZIP antigo continua instalado. Detalhe: " + backupText.slice(0, 600));
        }
        await env.DB.prepare("UPDATE admin_caos_settings SET package_uploaded_at=NULL,state='replacement_pending',updated_at=? WHERE id='main' AND owner_user_id=?").bind(Date.now(), user.id).run();
        return reply({
          ok: true,
          packageReplacementPending: true,
          databaseBackup: true,
          message: "Bot parado e banco SQLite protegido. Agora selecione o ZIP atualizado para substituir o pacote antigo."
        });
      } catch (error) {
        return reply({ error: error.message || "Não consegui preparar a substituição do pacote." }, 502);
      }
    }
    if (path === "/admin/caos/upload-url" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (!settings?.bot_token_enc) return reply({ error: "Salve e valide primeiro o token do bot Discord." }, 409);
      if (settings.package_uploaded_at) return reply({ error: "O pacote CAOS já foi instalado. Para proteger seu banco SQLite, esta instalação não será sobrescrita." }, 409);
      try {
        const deploymentId = await ensureAdminCaosDeployment(user.id, env, settings);
        await waitForHostReinstall(user.id, env, deploymentId);
        const signed = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/upload-url", "POST", { path: "/" });
        return reply({ ...signed, deploymentId });
      } catch (error) {
        if (error?.code === "hosting_installing") return reply({ code: "hosting_installing", error: error.message, retryAfterMs: Number(error.retryAfterMs || 1800) }, 202);
        return reply({ error: error.message || "Não consegui preparar o envio do pacote CAOS." }, 502);
      }
    }
    if (path === "/admin/caos/upload-proxy" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (!settings?.bot_token_enc) return reply({ error: "Salve e valide primeiro o token do bot Discord." }, 409);
      if (settings.package_uploaded_at) return reply({ error: "O pacote CAOS já foi instalado; o banco SQLite está protegido." }, 409);
      try {
        const form = await request.formData();
        const file = form.get("file");
        if (!file || typeof file.arrayBuffer !== "function" || !/\.zip$/i.test(String(file.name || ""))) {
          return reply({ error: "Envie o arquivo ZIP original do CAOS." }, 400);
        }
        if (Number(file.size || 0) > 4 * 1024 * 1024) {
          return reply({ error: "O ZIP excede o limite de 4 MB desta transferência. Comprima os arquivos sem incluir caches ou ambientes virtuais." }, 413);
        }
        const deploymentId = await ensureAdminCaosDeployment(user.id, env, settings);
        // A vaga foi autorizada para substituir o ADM antigo; pare-o antes de trocar os arquivos.
        const diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=2");
        let currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        if (!currentState) {
          const current = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId));
          currentState = String(current.state || current.deployment?.state || "").toLowerCase();
        }
        if (!currentState) throw new Error("Não consegui confirmar o estado da vaga antiga do ADM. Nenhum arquivo foi enviado.");
        if (!["offline","stopped","terminated"].includes(currentState)) {
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "stop", waitSeconds: 20 });
        }
        await waitForHostReinstall(user.id, env, deploymentId);
        const signed = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/upload-url", "POST", { path: "/" });
        if (!signed?.url) throw new Error("A hospedagem não retornou o endereço de envio.");
        const upstreamForm = new FormData();
        upstreamForm.append(signed.field || "files", file, "caos-paineis-azuis.zip");
        const upstream = await fetch(signed.url, {
          method: "POST",
          body: upstreamForm,
          signal: AbortSignal.timeout(180000)
        });
        const upstreamText = await upstream.text().catch(() => "");
        if (!upstream.ok) {
          throw new Error("A hospedagem recusou o pacote (HTTP " + upstream.status + "). " + upstreamText.slice(0, 300));
        }
        return reply({ ok: true, uploaded: true, deploymentId, file: "caos-paineis-azuis.zip" });
      } catch (error) {
        if (error?.code === "hosting_installing") return reply({ code: "hosting_installing", error: error.message, retryAfterMs: Number(error.retryAfterMs || 1800) }, 202);
        return reply({ error: error.message || "Não consegui encaminhar o ZIP à hospedagem." }, 502);
      }
    }
    if (path === "/admin/caos/install" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (!settings?.bot_token_enc) return reply({ error: "Salve primeiro o token do bot Discord." }, 409);
      if (settings.package_uploaded_at) return reply({ error: "O pacote CAOS já foi instalado. Seu banco de dados foi protegido contra sobrescrita." }, 409);
      const file = String((await body(request)).file || "");
      if (!/^[A-Za-z0-9._-]{1,140}\.zip$/i.test(file) || file.includes("..")) return reply({ error: "Nome de ZIP inválido." }, 400);
      const deploymentId = settings.hosting_deployment_id;
      if (!deploymentId) return reply({ error: "Prepare primeiro a hospedagem para receber o pacote." }, 409);

      try {
        const replacingInstalledPackage = settings.state === "replacement_pending";
        await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/decompress", "POST", {
          root: "/", file, removeArchive: true
        });
        if (replacingInstalledPackage) {
          const restoreScript = "from pathlib import Path\nimport shutil\nbackup = Path(\"/home/container/.blackzone-caos.sqlite3.backup\")\ndatabase = Path(\"/home/container/caos.sqlite3\")\nif not backup.is_file():\n    raise SystemExit(\"BACKUP_SQLITE_NAO_ENCONTRADO: não vou iniciar sem proteger o banco anterior.\")\nshutil.copy2(backup, database)\nif not database.is_file() or database.stat().st_size != backup.stat().st_size:\n    raise SystemExit(\"FALHA_RESTAURAR_SQLITE: o banco antigo não foi restaurado.\")\nbackup.unlink()\nprint(\"BLACKZONE_SQLITE_RESTORE_OK bytes=\" + str(database.stat().st_size))";
          const restoreResult = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/shell", "POST", {
            command: "python - <<'PY'\n" + restoreScript + "\nPY", timeout: 35, maxChars: 5000
          });
          const restoreText = String(restoreResult?.stdout || restoreResult?.output || restoreResult?.message || JSON.stringify(restoreResult));
          if (!restoreText.includes("BLACKZONE_SQLITE_RESTORE_OK")) {
            throw new Error("O pacote novo foi extraído, mas a hospedagem não confirmou a restauração do banco SQLite. O backup permanece salvo. Detalhe: " + restoreText.slice(0, 600));
          }
        }
        const token = await decryptSecret(settings.bot_token_enc, env);
        if (!token) throw new Error("Não consegui abrir o token protegido. Salve novamente o token do Discord.");
        await setHostEnv(user.id, env, deploymentId, "DISCORD_TOKEN", token, true);
        await setHostEnv(user.id, env, deploymentId, "TOKEN", token, true);
        await setHostEnv(user.id, env, deploymentId, "APP_URL", "https://black-zone-estudio.vercel.app", false);
        await setHostEnv(user.id, env, deploymentId, "PYTHONUNBUFFERED", "1", false);
        // O comando explícito garante a instalação das dependências do ZIP antes do main.py.
        const caosStartCommand = "python -m pip install --disable-pip-version-check -r requirements.txt && python -u main.py";
        await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
          runtime: "python", runtimeVersion: "3.11", entryFile: "main.py", startCommand: caosStartCommand
        });
        await env.DB.prepare("UPDATE admin_caos_settings SET package_uploaded_at=?,state='starting',updated_at=? WHERE id='main' AND owner_user_id=?")
          .bind(Date.now(), Date.now(), user.id).run();
        let diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/apply", "POST", {
          restart: true, waitSeconds: 45
        });
        let currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        if (["offline","stopped","terminated","unknown",""].includes(currentState)) {
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "start", waitSeconds: 45 });
          diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=45");
          currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        }
        const rawLogs = Array.isArray(diagnosis.logs) ? diagnosis.logs : (Array.isArray(diagnosis.lines) ? diagnosis.lines : []);
        const logs = rawLogs.map(line => typeof line === "string" ? line : String(line?.message || line?.line || JSON.stringify(line))).slice(-30);
        const joinedLogs = logs.join("\\n");
        const discordReady = /CAOS conectado como|logged in as/i.test(joinedLogs);
        const startupError = /PrivilegedIntentsRequired|disallowed intents|4014/i.test(joinedLogs)
          ? "O Discord recusou as intents privilegiadas. Ative Server Members Intent e Message Content Intent em Discord Developer Portal → Bot → Privileged Gateway Intents."
          : /ModuleNotFoundError|No module named/i.test(joinedLogs)
            ? "Uma dependência Python não foi instalada. O painel agora instala requirements.txt antes de executar; confira o nome do módulo nos logs."
            : /LoginFailure|Improper token|401 Unauthorized/i.test(joinedLogs)
              ? "O Discord recusou o token do bot durante o login. Confira se o token salvo pertence a este bot."
              : /out of memory|oom|killed|exit code 137/i.test(joinedLogs)
                ? "A hospedagem encerrou o processo por falta de memória. O plano gratuito pode não comportar o CAOS completo."
                : String(diagnosis.hint || diagnosis.error || "");
        const nextState = currentState === "running" ? "running" : (currentState === "offline" ? "error" : "starting");
        await env.DB.prepare("UPDATE admin_caos_settings SET state=?,updated_at=? WHERE id='main' AND owner_user_id=?")
          .bind(nextState, Date.now(), user.id).run();
        if (nextState === "error") {
          return reply({
            ok: false, deploymentId, state: nextState, discordReady: false,
            error: startupError || logs.slice(-8).join(" | ") || "A hospedagem recebeu o pacote, mas o processo encerrou antes de ficar online.",
            hint: diagnosis.hint || null, logs
          }, 502);
        }
        return reply({
          ok: true, deploymentId, state: nextState, discordReady,
          logs,
          message: discordReady
            ? "CAOS conectado ao Discord e confirmado pelos logs."
            : (nextState === "running"
              ? "O processo está rodando na hospedagem, mas o login do Discord ainda não foi confirmado. Confira os logs."
              : "A inicialização foi solicitada; o Estúdio continuará mostrando o estado real e os logs da hospedagem.")
        });
      } catch (error) {
        return reply({ error: error.message || "Falha ao instalar ou iniciar o pacote CAOS." }, 502);
      }
    }
    if (path === "/admin/caos/power" && request.method === "POST") {
      if (!ownerOnly(user)) return reply({ error: "Acesso restrito ao administrador principal." }, 403);
      const settings = await adminCaosSettings(env);
      if (!settings?.bot_token_enc || !settings.package_uploaded_at || !settings.hosting_deployment_id) {
        return reply({ error: "Salve o token e instale o pacote CAOS antes de iniciar." }, 409);
      }
      const action = String((await body(request)).action || "").toLowerCase();
      if (!["start","stop","restart"].includes(action)) return reply({ error: "Ação inválida." }, 400);
      try {
        const deploymentId = settings.hosting_deployment_id;
        if (action === "stop") {
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "stop", waitSeconds: 0 });
          await env.DB.prepare("UPDATE admin_caos_settings SET state='offline',updated_at=? WHERE id='main' AND owner_user_id=?")
            .bind(Date.now(), user.id).run();
          return reply({ ok: true, state: "offline", message: "Bot CAOS parado." });
        }
        const token = await decryptSecret(settings.bot_token_enc, env);
        if (!token) throw new Error("Não consegui abrir o token protegido. Salve novamente o token do Discord.");
        const identity = await validateDiscordBotToken(token);
        if (!identity.valid) throw new Error("O Discord não confirmou o token salvo. Atualize a credencial.");
        await setHostEnv(user.id, env, deploymentId, "DISCORD_TOKEN", token, true);
        await setHostEnv(user.id, env, deploymentId, "TOKEN", token, true);
        await setHostEnv(user.id, env, deploymentId, "PYTHONUNBUFFERED", "1", false);
        const caosStartCommand = "python -m pip install --disable-pip-version-check -r requirements.txt && python -u main.py";
        await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
          runtime: "python", runtimeVersion: "3.11", entryFile: "main.py", startCommand: caosStartCommand
        });
        let diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/apply", "POST", {
          restart: true, waitSeconds: 45
        });
        let currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        if (["offline","stopped","terminated","unknown",""].includes(currentState)) {
          await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/power", "POST", { action: "start", waitSeconds: 45 });
          diagnosis = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/diagnose?waitSeconds=45");
          currentState = String(diagnosis.state || diagnosis.deployment?.state || "").toLowerCase();
        }
        const rawLogs = Array.isArray(diagnosis.logs) ? diagnosis.logs : (Array.isArray(diagnosis.lines) ? diagnosis.lines : []);
        const logs = rawLogs.map(line => typeof line === "string" ? line : String(line?.message || line?.line || JSON.stringify(line))).slice(-30);
        const joinedLogs = logs.join("\\n");
        const discordReady = /CAOS conectado como|logged in as/i.test(joinedLogs);
        const startupError = /PrivilegedIntentsRequired|disallowed intents|4014/i.test(joinedLogs)
          ? "O Discord recusou as intents privilegiadas. Ative Server Members Intent e Message Content Intent em Discord Developer Portal → Bot → Privileged Gateway Intents."
          : /ModuleNotFoundError|No module named/i.test(joinedLogs)
            ? "Uma dependência Python não foi instalada. O painel agora instala requirements.txt antes de executar; confira o nome do módulo nos logs."
            : /LoginFailure|Improper token|401 Unauthorized/i.test(joinedLogs)
              ? "O Discord recusou o token do bot durante o login. Confira se o token salvo pertence a este bot."
              : /out of memory|oom|killed|exit code 137/i.test(joinedLogs)
                ? "A hospedagem encerrou o processo por falta de memória. O plano gratuito pode não comportar o CAOS completo."
                : String(diagnosis.hint || diagnosis.error || "");
        const nextState = currentState === "running" ? "running" : (currentState === "offline" ? "error" : "starting");
        await env.DB.prepare("UPDATE admin_caos_settings SET state=?,updated_at=? WHERE id='main' AND owner_user_id=?")
          .bind(nextState, Date.now(), user.id).run();
        if (nextState === "error") {
          return reply({
            ok: false, deploymentId, action, state: nextState, discordReady: false,
            error: startupError || logs.slice(-8).join(" | ") || "O Bot-Hosting recebeu o comando, mas o processo encerrou antes de ficar online.",
            hint: diagnosis.hint || null, logs
          }, 502);
        }
        return reply({
          ok: true, deploymentId, action, state: nextState, discordReady, logs,
          message: discordReady
            ? "CAOS conectado ao Discord e confirmado pelos logs."
            : (nextState === "running"
              ? "O processo do CAOS está rodando, mas o login do Discord ainda não foi confirmado. Confira os logs."
              : "A inicialização foi solicitada. O painel mostrará o estado e os logs reais da hospedagem.")
        });
      } catch (error) {
        return reply({ error: error.message || "Não foi possível iniciar o bot CAOS." }, 502);
      }
    }

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
    if (path === "/hosting/discloud/status" && request.method === "GET") {
      const row = await env.DB.prepare("SELECT encrypted_token,account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='discloud'").bind(user.id).first();
      if (!row) return reply({ connected: false, provider: "discloud" });
      try {
        const token = await decryptSecret(row.encrypted_token, env);
        const response = await fetch("https://api.discloud.app/v2/user", {
          headers: { "api-token": token, accept: "application/json" },
          signal: AbortSignal.timeout(12000)
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data?.status !== "ok" || !data?.user) {
          return reply({ connected: true, valid: false, provider: "discloud", accountLabel: row.account_label || null, plan: row.plan || null, error: "A Discloud não confirmou a chave salva. Atualize a API Key no painel." });
        }
        return reply({
          connected: true, valid: true, provider: "discloud",
          accountLabel: data.user.username || row.account_label || null,
          plan: data.user.plan || row.plan || null,
          appsCount: Array.isArray(data.user.apps) ? data.user.apps.length : null,
          updatedAt: row.updated_at
        });
      } catch (error) {
        return reply({ connected: true, valid: false, provider: "discloud", accountLabel: row.account_label || null, plan: row.plan || null, error: error.message || "Não consegui validar a conexão da Discloud." });
      }
    }
    if (path === "/hosting/discloud/connect" && request.method === "POST") {
      const b = await body(request);
      const token = String(b.apiToken || "").trim();
      if (token.length < 16 || token.length > 512) return reply({ error: "Informe uma API Key válida da Discloud." }, 400);
      try {
        const response = await fetch("https://api.discloud.app/v2/user", {
          headers: { "api-token": token, accept: "application/json" },
          signal: AbortSignal.timeout(12000)
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data?.status !== "ok" || !data?.user) {
          return reply({ error: "A Discloud recusou essa API Key. Confira a chave no Dashboard da Discloud e tente novamente." }, 401);
        }
        const encrypted = await encryptSecret(token, env);
        await env.DB.prepare(
          "INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'discloud',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at"
        ).bind(user.id, encrypted, String(data.user.username || ""), String(data.user.plan || ""), Date.now()).run();
        return reply({
          ok: true, connected: true, provider: "discloud",
          accountLabel: data.user.username || null, plan: data.user.plan || null,
          appsCount: Array.isArray(data.user.apps) ? data.user.apps.length : null,
          message: "Conta Discloud validada e chave guardada com criptografia."
        });
      } catch (error) {
        return reply({ error: error.message || "Não consegui validar a conta Discloud." }, 502);
      }
    }


    if (path === "/hosting/cogithost/connect" && request.method === "POST") {
      const b = await body(request), token = String(b.apiToken || "").trim();
      if (token.length < 20 || token.length > 512 || /\\s/.test(token)) return reply({ error: "Informe uma chave Client API do Cogithost válida." }, 400);
      try {
        const result = await cogitRequest(token, "");
        const servers = Array.isArray(result.data.data) ? result.data.data : [];
        const encrypted = await encryptSecret(JSON.stringify({ token }), env);
        await env.DB.prepare("INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'cogithost',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at")
          .bind(user.id, encrypted, "Cogithost", "Free / Pterodactyl", Date.now()).run();
        return reply({ ok: true, connected: true, provider: "cogithost", accountLabel: "Cogithost", serversCount: servers.length, message: "Chave Client API do Cogithost validada e criptografada." });
      } catch (error) { return reply({ error: error.message || "Não consegui validar a API Key do Cogithost." }, 401); }
    }
    if (path === "/hosting/cogithost/disconnect" && request.method === "POST") {
      const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='cogithost' AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id).first();
      if (linked) return reply({ error: "Há bots vinculados ao Cogithost. Desvincule os servidores antes de desconectar." }, 409);
      await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider='cogithost'").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }
    if (path === "/hosting/cogithost/servers" && request.method === "GET") {
      try {
        const config = await cogitConfig(user.id, env);
        if (!config) return reply({ code: "provider_not_connected", error: "Conecte o Cogithost em Configurações." }, 409);
        const result = await cogitRequest(config.token, "");
        const servers = (Array.isArray(result.data.data) ? result.data.data : []).map(item => {
          const a = item?.attributes || {};
          return { id: String(a.identifier || ""), name: String(a.name || "Servidor"), memoryMb: Number(a.limits?.memory || 0), diskMb: Number(a.limits?.disk || 0), suspended: !!a.is_suspended };
        }).filter(item => item.id);
        return reply({ connected: true, servers });
      } catch (error) { return reply({ error: error.message || "Não consegui listar os servidores Cogithost." }, 502); }
    }
    if (path === "/hosting/cogithost/attach" && request.method === "POST") {
      const b = await body(request), botId = String(b.botId || "");
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(botId)) return reply({ error: "Selecione um projeto válido do Estúdio." }, 400);
      const bot = await getOwnedBot(botId, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);
      if (bot.hosting_deployment_id || bot.provider_app_id) {
        return reply({ error: "Este projeto já está vinculado a uma hospedagem. Crie um novo projeto vazio no Estúdio para não perder a referência da hospedagem atual." }, 409);
      }
      try {
        const config = await cogitConfig(user.id, env);
        if (!config) return reply({ code: "provider_not_connected", error: "Conecte o Cogithost em Configurações." }, 409);
        const serverId = cogitIdentifier(b.serverId);
        const alreadyLinked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='cogithost' AND provider_app_id=? LIMIT 1").bind(user.id, serverId).first();
        if (alreadyLinked) return reply({ error: "Este servidor Cogithost já está vinculado a outro projeto do Estúdio." }, 409);
        const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId));
        const a = result.data?.attributes || {};
        if (String(a.identifier || "") !== serverId) return reply({ error: "O Cogithost não confirmou o identificador deste servidor." }, 502);
        const resources = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/resources");
        const current = String(resources.data?.attributes?.current_state || "").toLowerCase();
        const state = current === "running" ? "running" : "stopped";
        let discordTokenConfigured = false;
        if (bot.discord_token_enc) {
          try {
            const discordToken = await decryptSecret(bot.discord_token_enc, env);
            const startup = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/startup");
            const variables = Array.isArray(startup.data?.data) ? startup.data.data : [];
            const preferred = ["DISCORD_TOKEN","BOT_TOKEN","TOKEN"];
            const variable = variables.find(item => item?.attributes?.is_editable && preferred.includes(String(item.attributes.env_variable || "").toUpperCase()));
            if (discordToken && variable?.attributes?.env_variable) {
              await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", {
                key: variable.attributes.env_variable, value: discordToken
              });
              discordTokenConfigured = true;
            }
          } catch {}
        }
        const customProject = { packageName: bot.name, rootPath: "/", runtime: bot.runtime || "python", provider: "cogithost", linkedAt: Date.now() };
        await env.DB.prepare("UPDATE bots SET hosting_provider='cogithost',provider_app_id=?,hosting_deployment_id=NULL,project_type='custom',custom_project=?::jsonb,state=?,updated_at=? WHERE id=? AND user_id=?")
          .bind(serverId, JSON.stringify(customProject), state, Date.now(), botId, user.id).run();
        return reply({ ok: true, provider: "cogithost", providerAppId: serverId, serverName: String(a.name || "Servidor Cogithost"), state, message: "Servidor Cogithost vinculado. Arquivos e controles disponíveis no Estúdio." + (discordTokenConfigured ? " Token Discord salvo na variável de inicialização." : " Confira a variável de token e o arquivo principal no painel Cogithost antes de iniciar.") });
      } catch (error) { return reply({ error: error.message || "Não consegui vincular esse servidor Cogithost." }, 502); }
    }


    const pteroProviderRoute = path.match(/^\/hosting\/(sillydev|waifly|xsystems|torchlite|daki|unixsys|consolex1)\/(connect|disconnect|servers|attach)$/);
    if (pteroProviderRoute) {
      const providerId = pteroProviderRoute[1];
      const routeAction = pteroProviderRoute[2];
      const configs = {
        sillydev: { name: "Silly Development", plan: "Free · até 2 servidores · 256 MB RAM cada · 512 MB disco", request: sillydevRequest },
        waifly: { name: "Waifly", plan: "Free · 300 MB RAM · 1 GB · 1 servidor", request: waiflyRequest },
        xsystems: { name: "X Systems Hosting", plan: "1 servidor Free · 4 GB RAM · extras por créditos", request: xsystemsRequest },
        torchlite: { name: "Torchlite", plan: "Free Bot · 512 MB RAM · 3 GB disco · renovação a cada 24 horas", request: torchliteRequest },
        daki: { name: "Daki Hosting", plan: "Free Tier · 512 MB RAM · 1 GB disco · novas vagas podem estar fechadas", request: dakiRequest },
        unixsys: { name: "Unixsys", plan: "UniFree · 256 MB RAM · 512 MB disco · 1 servidor", request: unixsysRequest },
        consolex1: { name: "ConsoleX1", plan: "Free · 256 MB RAM · 512 MB disco · 40% CPU · 1 servidor", request: consolex1Request }
      };
      const config = configs[providerId];
      if (routeAction === "connect" && request.method === "POST") {
        const b = await body(request), token = String(b.apiToken || "").trim();
        if (token.length < 20 || token.length > 512 || /\s/.test(token)) return reply({ error: "Informe uma Client API Key válida de " + config.name + "." }, 400);
        try {
          const result = await config.request(token, "");
          const servers = Array.isArray(result.data?.data) ? result.data.data : [];
          let plan = config.plan;
          if (providerId === "sillydev") {
            const allowance = await config.request(token, "/server-creation");
            const a = allowance.data?.attributes || {};
            if (!Array.isArray(a.runtimes) || !a.runtimes.length) throw new Error("A chave precisa ter a permissão servers.create e o plano precisa estar com criação Free habilitada.");
            plan = "Free · " + Number(a.limit || 2) + " servidores · 256 MB RAM cada · 512 MB disco";
          }
          const encrypted = await encryptSecret(token, env);
          await env.DB.prepare("INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at")
            .bind(user.id, providerId, encrypted, config.name, plan, Date.now()).run();
          return reply({ ok: true, connected: true, provider: providerId, serversCount: servers.length, message: providerId === "sillydev" ? "Silly Development conectado. A chave foi validada e criptografada; o Estúdio poderá consultar e criar servidores Free quando houver vagas." : "Client API Key de " + config.name + " validada e salva com criptografia." });
        } catch (error) { return reply({ error: error.message || "Não consegui validar a Client API Key de " + config.name + "." }, 401); }
      }
      if (routeAction === "disconnect" && request.method === "POST") {
        const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider=? AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id, providerId).first();
        if (linked) return reply({ error: "Há bots vinculados à " + config.name + ". Desvincule os projetos antes de desconectar." }, 409);
        await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider=?").bind(user.id, providerId).run();
        return reply({ ok: true, connected: false });
      }
      if (routeAction === "servers" && request.method === "GET") {
        try {
          const token = await providerToken(user.id, providerId, env);
          if (!token) return reply({ code: "provider_not_connected", error: "Conecte a " + config.name + " primeiro." }, 409);
          const result = await config.request(token, "");
          const servers = (Array.isArray(result.data?.data) ? result.data.data : []).map(item => {
            const a = item?.attributes || {};
            return { id: String(a.identifier || ""), uuid: String(a.uuid || ""), name: String(a.name || "Servidor"), memoryMb: Number(a.limits?.memory || 0), diskMb: Number(a.limits?.disk || 0), suspended: !!a.is_suspended, installing: !!a.is_installing };
          }).filter(item => item.id);
          return reply({ connected: true, servers });
        } catch (error) { return reply({ error: error.message || "Não consegui listar servidores de " + config.name + "." }, 502); }
      }
      if (routeAction === "attach" && request.method === "POST") {
        const b = await body(request), botId = String(b.botId || "");
        if (!/^[A-Za-z0-9_-]{1,80}$/.test(botId)) return reply({ error: "Selecione um projeto válido do Estúdio." }, 400);
        const bot = await getOwnedBot(botId, user.id, env);
        if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);
        if (bot.hosting_deployment_id || bot.provider_app_id) return reply({ error: "Este projeto já está vinculado a uma hospedagem. Crie um projeto vazio no Estúdio para não perder a referência atual." }, 409);
        try {
          const token = await providerToken(user.id, providerId, env);
          if (!token) return reply({ code: "provider_not_connected", error: "Conecte a " + config.name + " em Configurações." }, 409);
          const serverId = keritIdentifier(b.serverId);
          const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider=? AND provider_app_id=? LIMIT 1").bind(user.id, providerId, serverId).first();
          if (linked) return reply({ error: "Este servidor já está vinculado a outro projeto do Estúdio." }, 409);
          const details = await config.request(token, "/servers/" + encodeURIComponent(serverId));
          const a = details.data?.attributes || {};
          if (String(a.identifier || "") !== serverId) return reply({ error: config.name + " não confirmou o identificador deste servidor." }, 502);
          const resourcesResult = await config.request(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
          const resource = resourcesResult.data?.attributes || {};
          const current = String(resource.current_state || "").toLowerCase();
          const state = resource.is_suspended ? "stopped" : (current === "running" ? "running" : (current === "starting" ? "starting" : "stopped"));
          let tokenConfigured = false;
          if (bot.discord_token_enc) {
            try {
              const discordToken = await decryptSecret(bot.discord_token_enc, env);
              const startup = await config.request(token, "/servers/" + encodeURIComponent(serverId) + "/startup");
              const variables = Array.isArray(startup.data?.data) ? startup.data.data : [];
              const variable = variables.find(item => item?.attributes?.is_editable && ["DISCORD_TOKEN","BOT_TOKEN","TOKEN"].includes(String(item.attributes.env_variable || "").toUpperCase()));
              if (discordToken && variable?.attributes?.env_variable) {
                await config.request(token, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", { key: variable.attributes.env_variable, value: discordToken });
                tokenConfigured = true;
              }
            } catch {}
          }
          const customProject = { packageName: bot.name, rootPath: "/", runtime: bot.runtime || "python", provider: providerId, providerName: config.name, linkedAt: Date.now() };
          await env.DB.prepare("UPDATE bots SET hosting_provider=?,provider_app_id=?,hosting_deployment_id=NULL,project_type='custom',custom_project=?::jsonb,state=?,updated_at=? WHERE id=? AND user_id=?")
            .bind(providerId, serverId, JSON.stringify(customProject), state, Date.now(), botId, user.id).run();
          return reply({ ok: true, provider: providerId, providerAppId: serverId, serverName: String(a.name || "Servidor"), state, message: "Servidor " + config.name + " vinculado ao Estúdio." + (tokenConfigured ? " Token Discord salvo na variável privada de inicialização." : " Envie o ZIP e confira a variável de token no painel.") });
        } catch (error) { return reply({ error: error.message || "Não consegui vincular esse servidor " + config.name + "." }, 502); }
      }
    }

    if (path === "/hosting/keritcloud/connect" && request.method === "POST") {
      const b = await body(request), token = String(b.apiToken || "").trim();
      if (token.length < 20 || token.length > 512 || /\\s/.test(token)) return reply({ error: "Informe uma Client API Key válida do Kerit Cloud." }, 400);
      try {
        const result = await keritRequest(token, "");
        const servers = Array.isArray(result.data?.data) ? result.data.data : [];
        const encrypted = await encryptSecret(token, env);
        await env.DB.prepare("INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'keritcloud',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at")
          .bind(user.id, encrypted, "Kerit Cloud", "Free · 256 MB · 1 servidor", Date.now()).run();
        return reply({ ok: true, connected: true, provider: "keritcloud", serversCount: servers.length, message: "Client API Key do Kerit Cloud validada e guardada com criptografia." });
      } catch (error) { return reply({ error: error.message || "Não consegui validar a Client API Key do Kerit Cloud." }, 401); }
    }
    if (path === "/hosting/keritcloud/disconnect" && request.method === "POST") {
      const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='keritcloud' AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id).first();
      if (linked) return reply({ error: "Há bots vinculados ao Kerit Cloud. Desvincule os servidores antes de desconectar." }, 409);
      await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider='keritcloud'").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }
    if (path === "/hosting/keritcloud/servers" && request.method === "GET") {
      try {
        const token = await providerToken(user.id, "keritcloud", env);
        if (!token) return reply({ code: "provider_not_connected", error: "Conecte o Kerit Cloud em Configurações." }, 409);
        const result = await keritRequest(token, "");
        const servers = (Array.isArray(result.data?.data) ? result.data.data : []).map(item => {
          const a = item?.attributes || {};
          return { id: String(a.identifier || ""), uuid: String(a.uuid || ""), name: String(a.name || "Servidor"), memoryMb: Number(a.limits?.memory || 0), diskMb: Number(a.limits?.disk || 0), suspended: !!a.is_suspended, installing: !!a.is_installing };
        }).filter(item => item.id);
        return reply({ connected: true, servers });
      } catch (error) { return reply({ error: error.message || "Não consegui listar servidores do Kerit Cloud." }, 502); }
    }
    if (path === "/hosting/keritcloud/attach" && request.method === "POST") {
      const b = await body(request), botId = String(b.botId || "");
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(botId)) return reply({ error: "Selecione um projeto válido do Estúdio." }, 400);
      const bot = await getOwnedBot(botId, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);
      if (bot.hosting_deployment_id || bot.provider_app_id) return reply({ error: "Este projeto já está vinculado a uma hospedagem. Crie um projeto vazio no Estúdio para não perder a referência atual." }, 409);
      try {
        const token = await providerToken(user.id, "keritcloud", env);
        if (!token) return reply({ code: "provider_not_connected", error: "Conecte o Kerit Cloud em Configurações." }, 409);
        const serverId = keritIdentifier(b.serverId);
        const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='keritcloud' AND provider_app_id=? LIMIT 1").bind(user.id, serverId).first();
        if (linked) return reply({ error: "Este servidor Kerit Cloud já está vinculado a outro projeto do Estúdio." }, 409);
        const details = await keritRequest(token, "/servers/" + encodeURIComponent(serverId));
        const a = details.data?.attributes || {};
        if (String(a.identifier || "") !== serverId) return reply({ error: "O Kerit Cloud não confirmou o identificador deste servidor." }, 502);
        const resourcesResult = await keritRequest(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
        const resource = resourcesResult.data?.attributes || {};
        const current = String(resource.current_state || "").toLowerCase();
        const state = current === "running" ? "running" : (current === "starting" ? "starting" : "stopped");
        let tokenConfigured = false;
        if (bot.discord_token_enc) {
          try {
            const discordToken = await decryptSecret(bot.discord_token_enc, env);
            const startup = await keritRequest(token, "/servers/" + encodeURIComponent(serverId) + "/startup");
            const variables = Array.isArray(startup.data?.data) ? startup.data.data : [];
            const preferred = ["DISCORD_TOKEN","BOT_TOKEN","TOKEN"];
            const variable = variables.find(item => item?.attributes?.is_editable && preferred.includes(String(item.attributes.env_variable || "").toUpperCase()));
            if (discordToken && variable?.attributes?.env_variable) {
              await keritRequest(token, "/servers/" + encodeURIComponent(serverId) + "/startup/variable", "PUT", { key: variable.attributes.env_variable, value: discordToken });
              tokenConfigured = true;
            }
          } catch {}
        }
        const customProject = { packageName: bot.name, rootPath: "/", runtime: bot.runtime || "python", provider: "keritcloud", linkedAt: Date.now(), panel: "Pterodactyl" };
        await env.DB.prepare("UPDATE bots SET hosting_provider='keritcloud',provider_app_id=?,hosting_deployment_id=NULL,project_type='custom',custom_project=?::jsonb,state=?,updated_at=? WHERE id=? AND user_id=?")
          .bind(serverId, JSON.stringify(customProject), state, Date.now(), botId, user.id).run();
        return reply({ ok: true, provider: "keritcloud", providerAppId: serverId, serverName: String(a.name || "Servidor Kerit Cloud"), state, tokenConfigured,
          message: "Servidor Kerit Cloud vinculado. O Estúdio já pode enviar arquivos e controlar a energia. " + (tokenConfigured ? "O token do Discord foi salvo na variável privada de inicialização." : "Configure uma variável editável DISCORD_TOKEN, BOT_TOKEN ou TOKEN no painel Kerit para o bot iniciar com segurança.") });
      } catch (error) { return reply({ error: error.message || "Não consegui vincular esse servidor Kerit Cloud." }, 502); }
    }

    if (path === "/hosting/aclclouds/connect" && request.method === "POST") {
      const b = await body(request), token = String(b.apiToken || "").trim();
      if (token.length < 20 || token.length > 1024 || /\s/.test(token)) return reply({ error: "Informe uma API Key ACLClouds válida." }, 400);
      try {
        const accountResult = await aclCloudsRequest(token, "/account");
        const account = aclCloudsAttributes(accountResult.data);
        const services = await aclCloudsServices(token);
        const encrypted = await encryptSecret(token, env);
        const label = String(account.username || account.email || "ACLClouds").slice(0, 120);
        await env.DB.prepare("INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'aclclouds',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at")
          .bind(user.id, encrypted, label, "Free · 1 bot Discord por conta", Date.now()).run();
        const bots = services.filter(item => String(item.service_type || "").toLowerCase() === "discord");
        return reply({ ok: true, connected: true, provider: "aclclouds", accountLabel: label, serversCount: services.length, botsCount: bots.length, message: "ACLClouds validada. A chave foi criptografada e os servidores Discord foram consultados." });
      } catch (error) { return reply({ error: error.message || "Não consegui validar a API Key ACLClouds." }, 401); }
    }
    if (path === "/hosting/aclclouds/disconnect" && request.method === "POST") {
      const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='aclclouds' AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id).first();
      if (linked) return reply({ error: "Há bots vinculados à ACLClouds. Desvincule os servidores antes de desconectar." }, 409);
      await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider='aclclouds'").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }
    if (path === "/hosting/aclclouds/servers" && request.method === "GET") {
      try {
        const token = await providerToken(user.id, "aclclouds", env);
        if (!token) return reply({ code: "provider_not_connected", error: "Conecte a ACLClouds em Configurações." }, 409);
        const services = await aclCloudsServices(token);
        const servers = services.filter(item => String(item.service_type || "").toLowerCase() === "discord").map(item => ({
          id: String(item.identifier || ""), uuid: String(item.uuid || ""), name: String(item.name || "Discord bot"),
          status: String(item.status || "active"), suspended: !!item.is_suspended,
          memoryMb: Number(item.limits?.memory || 0), diskMb: Number(item.limits?.disk || 0), cpu: Number(item.limits?.cpu || 0)
        })).filter(item => item.id);
        return reply({ connected: true, servers, total: servers.length, planLimit: 1 });
      } catch (error) { return reply({ error: error.message || "Não consegui listar servidores ACLClouds." }, 502); }
    }
    if (path === "/hosting/aclclouds/attach" && request.method === "POST") {
      const b = await body(request), botId = String(b.botId || "");
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(botId)) return reply({ error: "Selecione um projeto válido do Estúdio." }, 400);
      const bot = await getOwnedBot(botId, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);
      if (bot.hosting_deployment_id || bot.provider_app_id) return reply({ error: "Este projeto já está vinculado a uma hospedagem. Crie um projeto novo para vincular o servidor ACLClouds." }, 409);
      try {
        const token = await providerToken(user.id, "aclclouds", env);
        if (!token) return reply({ code: "provider_not_connected", error: "Conecte a ACLClouds em Configurações." }, 409);
        const serverId = aclCloudsIdentifier(b.serverId);
        const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='aclclouds' AND provider_app_id=? LIMIT 1").bind(user.id, serverId).first();
        if (linked) return reply({ error: "Este servidor ACLClouds já está vinculado a outro projeto do Estúdio." }, 409);
        const services = await aclCloudsServices(token);
        const service = services.find(item => String(item.identifier || "") === serverId);
        if (!service || String(service.service_type || "").toLowerCase() !== "discord") return reply({ error: "A API não encontrou um serviço Discord com esse identificador nesta conta." }, 404);
        const resourceResult = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
        const resource = aclCloudsAttributes(resourceResult.data);
        const current = String(resource.current_state || "").toLowerCase();
        const state = current === "running" ? "running" : "stopped";
        const customProject = { packageName: bot.name, rootPath: "/", runtime: bot.runtime || "python", provider: "aclclouds", linkedAt: Date.now() };
        await env.DB.prepare("UPDATE bots SET hosting_provider='aclclouds',provider_app_id=?,hosting_deployment_id=NULL,project_type='custom',custom_project=?::jsonb,state=?,updated_at=? WHERE id=? AND user_id=?")
          .bind(serverId, JSON.stringify(customProject), state, Date.now(), botId, user.id).run();
        return reply({ ok: true, provider: "aclclouds", providerAppId: serverId, serverName: String(service.name || "ACLClouds bot"), state,
          message: "Servidor ACLClouds vinculado. Confira no painel ACLClouds se o comando Startup aponta para o arquivo principal e configure DISCORD_TOKEN nas variáveis do servidor." });
      } catch (error) { return reply({ error: error.message || "Não consegui vincular o servidor ACLClouds." }, 502); }
    }
    if (path === "/hosting/cube/connect" && request.method === "POST") {
      const b = await body(request);
      const token = String(b.apiToken || "").trim();
      if (!/^cube_[A-Za-z0-9_-]{12,1020}$/.test(token)) return reply({ error: "Informe uma API Key Cube Hosting válida (ela começa com cube_)." }, 400);
      try {
        const usage = await cubeCloudRequest(token, "/account/usage");
        if (!usage?.plan || !usage?.projects) throw new Error("A Cube Hosting não retornou os dados do plano.");
        const encrypted = await encryptSecret(token, env);
        await env.DB.prepare(
          "INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'cubecloud',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at"
        ).bind(user.id, encrypted, String(usage.accountId || ""), String(usage.plan.name || ""), Date.now()).run();
        return reply({
          ok: true, connected: true, provider: "cubecloud",
          accountLabel: usage.accountId || null, plan: usage.plan.name || null,
          projectsCount: Number(usage.projects.total || 0),
          maxBots: Number(usage.plan.maxBots || 0),
          memoryAvailableMb: Number(usage.memory?.freeMb || 0),
          memoryLimitMb: Number(usage.plan.memoryMb || 0),
          fileManagerAvailable: String(usage.plan.id || "").toLowerCase() !== "free",
          message: "Conta Cube Hosting validada e API Key criptografada."
        });
      } catch (error) {
        return reply({ error: error.message || "Não consegui validar a API Key da Cube Hosting." }, 401);
      }
    }
    if (path === "/hosting/cube/disconnect" && request.method === "POST") {
      const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='cubecloud' AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id).first();
      if (linked) return reply({ error: "Há bots usando Cube Hosting. Mova ou exclua esses projetos antes de desconectar a conta." }, 409);
      await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider='cubecloud'").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }

    if (path === "/hosting/square/connect" && request.method === "POST") {
      const b = await body(request);
      const token = String(b.apiToken || "").trim();
      if (token.length < 64 || token.length > 1024) return reply({ error: "Informe uma API Key Square Cloud válida (64 a 1.024 caracteres)." }, 400);
      try {
        const data = await squareCloudRequest(token, "/users/me");
        const userData = data.user || {};
        const plan = userData.plan || {};
        const memory = plan.memory || {};
        const encrypted = await encryptSecret(token, env);
        await env.DB.prepare(
          "INSERT INTO provider_connections (user_id,provider,encrypted_token,account_label,plan,updated_at) VALUES (?,'squarecloud',?,?,?,?) ON CONFLICT (user_id,provider) DO UPDATE SET encrypted_token=EXCLUDED.encrypted_token,account_label=EXCLUDED.account_label,plan=EXCLUDED.plan,updated_at=EXCLUDED.updated_at"
        ).bind(user.id, encrypted, String(userData.name || ""), String(plan.name || ""), Date.now()).run();
        return reply({
          ok: true, connected: true, provider: "squarecloud",
          accountLabel: userData.name || null, plan: plan.name || null,
          applicationsCount: Array.isArray(data.applications) ? data.applications.length : null,
          memoryAvailableMb: Number(memory.available || 0),
          memoryLimitMb: Number(memory.limit || 0),
          message: "Conta Square Cloud validada. A chave foi criptografada e salva no servidor do Estúdio."
        });
      } catch (error) {
        return reply({ error: error.message || "Não consegui validar a API Key Square Cloud." }, 401);
      }
    }
    if (path === "/hosting/square/disconnect" && request.method === "POST") {
      const linked = await env.DB.prepare("SELECT id FROM bots WHERE user_id=? AND hosting_provider='squarecloud' AND provider_app_id IS NOT NULL LIMIT 1").bind(user.id).first();
      if (linked) return reply({ error: "Há bots usando a Square Cloud. Mova ou exclua esses projetos antes de desconectar a conta." }, 409);
      await env.DB.prepare("DELETE FROM provider_connections WHERE user_id=? AND provider='squarecloud'").bind(user.id).run();
      return reply({ ok: true, connected: false });
    }

    if (path === "/hosting/pool/status" && request.method === "GET") {
      const [discloudRow, squareRow, cubeRow, sillyRow, cogitRow, keritRow, aclRow, waiflyRow, xsystemsRow, torchliteRow, dakiRow, unixsysRow, consolex1Row, hostingRow] = await Promise.all([
        env.DB.prepare("SELECT user_id,account_label,plan,updated_at FROM provider_connections WHERE user_id IN (?,?) AND provider='discloud' ORDER BY CASE WHEN user_id=? THEN 0 ELSE 1 END LIMIT 1").bind(user.id, SHARED_HOSTING_OWNER_ID, user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='squarecloud'").bind(user.id).first(),
        env.DB.prepare("SELECT user_id,account_label,plan,updated_at FROM provider_connections WHERE user_id IN (?,?) AND provider='cubecloud' ORDER BY CASE WHEN user_id=? THEN 0 ELSE 1 END LIMIT 1").bind(user.id, SHARED_HOSTING_OWNER_ID, user.id).first(),
        env.DB.prepare("SELECT user_id,account_label,plan,updated_at FROM provider_connections WHERE user_id IN (?,?) AND provider='sillydev' ORDER BY CASE WHEN user_id=? THEN 0 ELSE 1 END LIMIT 1").bind(user.id, SHARED_HOSTING_OWNER_ID, user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='cogithost'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='keritcloud'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='aclclouds'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='waifly'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='xsystems'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='torchlite'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='daki'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='unixsys'").bind(user.id).first(),
        env.DB.prepare("SELECT account_label,plan,updated_at FROM provider_connections WHERE user_id=? AND provider='consolex1'").bind(user.id).first(),
        env.DB.prepare("SELECT scope,expires_at FROM hosting_connections WHERE user_id=?").bind(user.id).first()
      ]);
      let discloud = { connected: false, provider: "discloud" };
      if (discloudRow) {
        try {
          const token = await providerTokenForPool(user.id, "discloud", env);
          const data = token ? await discloudRequest(token, "/user") : null;
          if (data?.user) {
            const planName = String(data.user.plan || discloudRow.plan || "");
            const appsCount = Array.isArray(data.user.apps) ? data.user.apps.length : null;
            const totalRamMb = Number(data.user.totalRamMb || 0);
            const ramUsedMb = Number(data.user.ramUsedMb || 0);
            const isFreePlan = /\bfree\b/i.test(planName);
            const freeSlotAvailable = isFreePlan && appsCount === 0 && (totalRamMb - ramUsedMb) >= 100;
            discloud = {
              connected: true, valid: true, provider: "discloud",
              accountLabel: discloudRow.user_id !== user.id ? "Hospedagem compartilhada do Estúdio" : (data.user.username || discloudRow.account_label || null),
              sharedFromOwner: discloudRow.user_id !== user.id,
              plan: planName || null,
              appsCount, totalRamMb, ramUsedMb,
              canCreate: freeSlotAvailable,
              freeBotsLimit: isFreePlan ? 1 : null,
              detail: freeSlotAvailable
                ? (discloudRow.user_id !== user.id ? "Vaga Free compartilhada pelo Estúdio · o Estúdio pode enviar ZIP automaticamente." : "Vaga Free disponível · o Estúdio pode enviar ZIP automaticamente.")
                : (!isFreePlan
                  ? "A seleção automática só usa o plano Free."
                  : (appsCount !== 0
                    ? "A vaga Free já está ocupada por uma aplicação desta conta."
                    : "A conta não informou 100 MB livres para um novo bot."))
            };
          }
          else discloud = { connected: true, valid: false, provider: "discloud", error: "A Discloud não confirmou a chave salva." };
        } catch (error) {
          discloud = { connected: true, valid: false, provider: "discloud", error: error.message || "Falha de validação." };
        }
      }
      let square = { connected: false, provider: "squarecloud" };
      if (squareRow) {
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          const data = token ? await squareCloudRequest(token, "/users/me") : null;
          if (data?.user) {
            const memory = data.user.plan?.memory || {};
            const available = Number(memory.available || 0);
            const apps = Array.isArray(data.applications) ? data.applications : [];
            square = {
              connected: true, valid: true, provider: "squarecloud",
              accountLabel: data.user.name || squareRow.account_label || null,
              plan: data.user.plan?.name || squareRow.plan || null,
              applicationsCount: apps.length,
              memoryAvailableMb: available,
              memoryLimitMb: Number(memory.limit || 0),
              canCreate: available >= 256
            };
          } else square = { connected: true, valid: false, provider: "squarecloud", error: "A Square Cloud não confirmou a chave salva." };
        } catch (error) {
          square = { connected: true, valid: false, provider: "squarecloud", error: error.message || "Falha de validação." };
        }
      }

      let cube = { connected: false, provider: "cubecloud" };
      if (cubeRow) {
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          const usage = token ? await cubeCloudRequest(token, "/account/usage") : null;
          if (usage?.plan) {
            const plan = usage.plan || {};
            const projects = usage.projects || {};
            const maxBots = Number(plan.maxBots || 0);
            const projectCount = Number(projects.total || 0);
            const minMemory = Number(plan.minMemoryMb?.bot || (String(plan.id).toLowerCase() === "free" ? 100 : 256));
            const freeMb = Number(usage.memory?.freeMb || 0);
            cube = {
              connected: true, valid: true, provider: "cubecloud",
              accountLabel: cubeRow.user_id !== user.id ? "Hospedagem compartilhada do Estúdio" : (cubeRow.account_label || usage.accountId || null),
              sharedFromOwner: cubeRow.user_id !== user.id,
              plan: plan.name || cubeRow.plan || null,
              planId: plan.id || null,
              projectsCount: projectCount, maxBots,
              memoryAvailableMb: freeMb,
              memoryLimitMb: Number(plan.memoryMb || 0),
              zipMaxMb: Number(plan.zipMaxMb || 0),
              fileManagerAvailable: String(plan.id || "").toLowerCase() !== "free",
              canCreate: (maxBots <= 0 || projectCount < maxBots) && freeMb >= minMemory
            };
          } else cube = { connected: true, valid: false, provider: "cubecloud", error: "A Cube Hosting não retornou o uso do plano." };
        } catch (error) {
          cube = { connected: true, valid: false, provider: "cubecloud", error: error.message || "Falha de validação." };
        }
      }

      let sillydev = { connected: false, provider: "sillydev" };
      if (sillyRow) {
        try {
          const token = await providerTokenForPool(user.id, "sillydev", env);
          const allowanceResult = token ? await sillydevRequest(token, "/server-creation") : null;
          const allowance = allowanceResult?.data?.attributes || {};
          const serverResult = token ? await sillydevRequest(token, "") : null;
          const servers = Array.isArray(serverResult?.data?.data) ? serverResult.data.data : [];
          const limit = Number(allowance.limit || 2);
          const owned = Number(allowance.servers_owned ?? servers.length);
          sillydev = {
            connected: true, valid: !!token, provider: "sillydev",
            accountLabel: sillyRow.user_id !== user.id ? "Hospedagem compartilhada do Estúdio" : (sillyRow.account_label || "Silly Development"),
            sharedFromOwner: sillyRow.user_id !== user.id,
            plan: "Free · até " + limit + " servidores · 256 MB RAM cada · 512 MB disco",
            serversCount: servers.length, serversOwned: owned,
            freeServersLimit: limit, freeSlotsRemaining: Math.max(0, limit - owned),
            canCreate: !!allowance.can_create,
            canAttach: servers.length > 0,
            runtimes: Array.isArray(allowance.runtimes) ? allowance.runtimes.map(x => x.key) : [],
            detail: allowance.can_create
              ? (sillyRow.user_id !== user.id ? "Vaga Free compartilhada pelo Estúdio. A API confirmou que o Estúdio pode criar o servidor automaticamente." : "Há uma vaga Free confirmada pela API. O Estúdio pode criar o servidor automaticamente.")
              : "Limite Free: " + owned + "/" + limit + " servidores usados. Sem vaga para criar outro agora."
          };
        } catch (error) {
          sillydev = { connected: true, valid: false, provider: "sillydev", error: error.message || "Falha ao consultar a cota gratuita do Silly Development." };
        }
      }

      let cogithost = { connected: false, provider: "cogithost" };
      if (cogitRow) {
        try {
          const config = await cogitConfig(user.id, env);
          const result = config ? await cogitRequest(config.token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          cogithost = { connected: true, valid: true, provider: "cogithost", accountLabel: "Cogithost", plan: "Free / Pterodactyl", serversCount: servers.length, canCreate: false, canAttach: servers.length > 0 };
        } catch (error) { cogithost = { connected: true, valid: false, provider: "cogithost", error: error.message || "Falha de validação." }; }
      }
      let keritcloud = { connected: false, provider: "keritcloud" };
      if (keritRow) {
        try {
          const token = await providerToken(user.id, "keritcloud", env);
          const result = token ? await keritRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          const totalRamMb = servers.reduce((sum, item) => sum + Number(item?.attributes?.limits?.memory || 0), 0);
          keritcloud = {
            connected: true, valid: !!token, provider: "keritcloud",
            accountLabel: keritRow.account_label || "Kerit Cloud",
            plan: "Free · até 1 servidor por pessoa",
            serversCount: servers.length, totalRamMb,
            canCreate: false, canAttach: servers.length > 0,
            detail: servers.length ? "Servidor encontrado · selecione para vincular ao Estúdio." : "Conta conectada. Reivindique a vaga Free no painel Kerit e depois atualize esta tela."
          };
        } catch (error) { keritcloud = { connected: true, valid: false, provider: "keritcloud", error: error.message || "Falha ao validar Kerit Cloud." }; }
      }

      let waifly = { connected: false, provider: "waifly" };
      if (waiflyRow) {
        try {
          const token = await providerToken(user.id, "waifly", env);
          const result = token ? await waiflyRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          waifly = { connected: true, valid: !!token, provider: "waifly", accountLabel: waiflyRow.account_label || "Waifly", plan: "Free · 1 servidor", serversCount: servers.length, totalRamMb: servers.reduce((sum,item)=>sum+Number(item?.attributes?.limits?.memory||0),0), canCreate: false, canAttach: servers.length > 0, detail: servers.length ? "Servidor disponível para vincular · 300 MB RAM / 1 GB disco." : "Conta conectada. Crie o servidor Free no painel Waifly." };
        } catch (error) { waifly = { connected: true, valid: false, provider: "waifly", error: error.message || "Falha de validação Waifly." }; }
      }
      let xsystems = { connected: false, provider: "xsystems" };
      if (xsystemsRow) {
        try {
          const token = await providerToken(user.id, "xsystems", env);
          const result = token ? await xsystemsRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          const totalRamMb = servers.reduce((sum,item)=>sum+Number(item?.attributes?.limits?.memory||0),0);
          const freeSizedServer = servers.some(item => Number(item?.attributes?.limits?.memory||0) >= 4000 && Number(item?.attributes?.limits?.disk||0) >= 10000);
          xsystems = { connected: true, valid: !!token, provider: "xsystems", accountLabel: xsystemsRow.account_label || "X Systems Hosting", plan: "1 servidor Free · 4 GB RAM", serversCount: servers.length, totalRamMb, freeSizedServer, canCreate: false, canAttach: servers.length > 0, detail: freeSizedServer ? "Servidor Free de 4 GB encontrado. Servidores extras usam créditos ganhos gratuitamente (3 créditos/dia no servidor básico)." : (servers.length ? "Servidor(es) encontrado(s). Confira o custo diário e os créditos antes de iniciar servidores extras." : "Conta conectada. Crie o primeiro servidor Free de 4 GB no painel X Systems.") };
        } catch (error) { xsystems = { connected: true, valid: false, provider: "xsystems", error: error.message || "Falha de validação X Systems." }; }
      }

      let torchlite = { connected: false, provider: "torchlite" };
      if (torchliteRow) {
        try {
          const token = await providerToken(user.id, "torchlite", env);
          const result = token ? await torchliteRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          const botServers = servers.filter(item => /discord|bot/i.test(String(item?.attributes?.name || "")));
          torchlite = {
            connected: true, valid: !!token, provider: "torchlite",
            accountLabel: torchliteRow.account_label || "Torchlite",
            plan: "Free Bot · 512 MB RAM · 3 GB disco · renovação diária",
            serversCount: servers.length, botServersCount: botServers.length,
            canCreate: false, canAttach: servers.length > 0,
            detail: servers.length
              ? "Servidor encontrado. O plano Bot exige renovação gratuita a cada 24 horas e login no painel pelo menos a cada 5 dias."
              : "Conta conectada. Crie um servidor Discord Bot no painel Torchlite. Cada conta aceita até 2 servidores no total."
          };
        } catch (error) { torchlite = { connected: true, valid: false, provider: "torchlite", error: error.message || "Falha de validação Torchlite." }; }
      }
      let daki = { connected: false, provider: "daki" };
      if (dakiRow) {
        try {
          const token = await providerToken(user.id, "daki", env);
          const result = token ? await dakiRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          daki = {
            connected: true, valid: !!token, provider: "daki",
            accountLabel: dakiRow.account_label || "Daki Hosting",
            plan: "Free Tier · 512 MB RAM · 1 GB disco",
            serversCount: servers.length,
            canCreate: false, canAttach: servers.length > 0,
            detail: servers.length
              ? "Servidor Daki encontrado e pronto para vincular ao Estúdio."
              : "A Daki informa que os nós gratuitos estão sem vagas no momento. A conexão serve para vincular servidores Free que você já tenha."
          };
        } catch (error) { daki = { connected: true, valid: false, provider: "daki", error: error.message || "Falha de validação Daki." }; }
      }

      let unixsys = { connected: false, provider: "unixsys" };
      if (unixsysRow) {
        try {
          const token = await providerToken(user.id, "unixsys", env);
          const result = token ? await unixsysRequest(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          unixsys = {
            connected: true, valid: !!token, provider: "unixsys",
            accountLabel: unixsysRow.account_label || "Unixsys",
            plan: "UniFree · 1 servidor · 256 MB RAM · até 512 MB com indicações",
            serversCount: servers.length,
            totalRamMb: servers.reduce((sum,item)=>sum+Number(item?.attributes?.limits?.memory||0),0),
            canCreate: false, canAttach: servers.length > 0,
            detail: servers.length
              ? "Servidor encontrado. Unixsys avisa que a máquina pode ser removida se a conta ficar 24h sem retornar à comunidade."
              : "Conta conectada. Crie o servidor com /create-server no Discord Unixsys e depois volte para vincular."
          };
        } catch (error) { unixsys = { connected: true, valid: false, provider: "unixsys", error: error.message || "Falha ao validar Unixsys." }; }
      }
      let consolex1 = { connected: false, provider: "consolex1" };
      if (consolex1Row) {
        try {
          const token = await providerToken(user.id, "consolex1", env);
          const result = token ? await consolex1Request(token, "") : null;
          const servers = Array.isArray(result?.data?.data) ? result.data.data : [];
          consolex1 = {
            connected: true, valid: !!token, provider: "consolex1",
            accountLabel: consolex1Row.account_label || "ConsoleX1",
            plan: "Free · 1 servidor · 256 MB RAM · 512 MB disco",
            serversCount: servers.length,
            totalRamMb: servers.reduce((sum,item)=>sum+Number(item?.attributes?.limits?.memory||0),0),
            canCreate: false, canAttach: servers.length > 0,
            detail: servers.length
              ? "Servidor encontrado. No Free, altere um arquivo pelo menos a cada 7 dias para evitar suspensão."
              : "Conta conectada. Crie o servidor pelo Discord ConsoleX1 e depois volte para vincular."
          };
        } catch (error) { consolex1 = { connected: true, valid: false, provider: "consolex1", error: error.message || "Falha ao validar ConsoleX1." }; }
      }
      let aclclouds = { connected: false, provider: "aclclouds" };
      if (aclRow) {
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          const accountResult = token ? await aclCloudsRequest(token, "/account") : null;
          const account = aclCloudsAttributes(accountResult?.data);
          const services = token ? await aclCloudsServices(token) : [];
          const bots = services.filter(item => String(item.service_type || "").toLowerCase() === "discord");
          aclclouds = {
            connected: true, valid: !!token, provider: "aclclouds",
            accountLabel: account.username || account.email || aclRow.account_label || "ACLClouds",
            plan: "Free · 1 Discord bot por conta",
            serversCount: services.length, botsCount: bots.length,
            canCreate: false, canAttach: bots.length > 0
          };
        } catch (error) {
          aclclouds = { connected: true, valid: false, provider: "aclclouds", error: error.message || "Falha ao validar ACLClouds." };
        }
      }
      const scopes = String(hostingRow?.scope || "").split(/\s+/).filter(Boolean);
      return reply({
        providers: [
          { id: "bot-hosting", name: "Bot-Hosting", connected: !!hostingRow, canCreate: !!hostingRow && scopes.includes("deployments:write") && scopes.includes("credits:spend"), role: "principal" },
          { id: "sillydev", name: "Silly Development", role: "reserva", ...sillydev, canCreate: !!sillydev.valid && !!sillydev.canCreate, canAttach: !!sillydev.valid && !!sillydev.canAttach },
          { id: "cogithost", name: "Cogithost", role: "servidor-conectado", ...cogithost, canCreate: false },
          { id: "keritcloud", name: "Kerit Cloud", role: "servidor-conectado", ...keritcloud, canCreate: false, canAttach: !!keritcloud.valid && !!keritcloud.canAttach },
          { id: "waifly", name: "Waifly", role: "servidor-conectado", ...waifly, canCreate: false, canAttach: !!waifly.valid && !!waifly.canAttach },
          { id: "xsystems", name: "X Systems Hosting", role: "servidor-conectado", ...xsystems, canCreate: false, canAttach: !!xsystems.valid && !!xsystems.canAttach },
          { id: "torchlite", name: "Torchlite", role: "servidor-conectado", ...torchlite, canCreate: false, canAttach: !!torchlite.valid && !!torchlite.canAttach },
          { id: "daki", name: "Daki Hosting", role: "servidor-conectado", ...daki, canCreate: false, canAttach: !!daki.valid && !!daki.canAttach },
          { id: "unixsys", name: "Unixsys", role: "servidor-conectado", ...unixsys, canCreate: false, canAttach: !!unixsys.valid && !!unixsys.canAttach },
          { id: "consolex1", name: "ConsoleX1", role: "servidor-conectado", ...consolex1, canCreate: false, canAttach: !!consolex1.valid && !!consolex1.canAttach },
          { id: "aclclouds", name: "ACLClouds", role: "servidor-conectado", ...aclclouds, canCreate: false, canAttach: !!aclclouds.valid && !!aclclouds.canAttach },
          { id: "cubecloud", name: "Cube Hosting", role: "reserva", ...cube, canCreate: !!cube.valid && !!cube.canCreate },
          { id: "squarecloud", name: "Square Cloud", role: "paga-fora-do-pool", ...square, canCreate: false },
          { id: "discloud", name: "Discloud", connected: !!discloud.connected, valid: !!discloud.valid, ...discloud, canCreate: !!discloud.canCreate, role: discloud.canCreate ? "reserva" : "compatibilidade-parcial" },
          { id: "fadehost", name: "FadeHost", connected: false, valid: true, canCreate: false, canAttach: false, deploymentMode: "manual", role: "deploy-manual", plan: "Free · 1 app por conta", detail: "Deploy pelo painel FadeHost; não é uma vaga conectada ao Estúdio.", url: "https://laplace.fadehost.com" },
          { id: "quaxly", name: "Quaxly", connected: false, valid: true, canCreate: false, canAttach: false, deploymentMode: "manual", role: "deploy-manual", plan: "Free · até 3 bots", detail: "Deploy pelo painel Quaxly; não é uma vaga conectada ao Estúdio.", url: "https://quaxly.com" },
          { id: "fpsms", name: "FPS.ms", connected: false, valid: true, canCreate: false, canAttach: false, deploymentMode: "manual", role: "deploy-manual", plan: "Free · 128 MB RAM · 250 MB SSD", detail: "Plano muito pequeno, com renovação diária; indicado apenas para bots leves.", url: "https://fps.ms/free-discord-bot-hosting" },

        ]
      });
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
        "SELECT id,name,runtime,state,modules,project_type,custom_project,created_at,updated_at,(discord_token_enc IS NOT NULL) AS has_discord_token,discord_bot_id,discord_bot_name,hosting_deployment_id,hosting_provider,provider_app_id,schedule_enabled,schedule_start,schedule_end,schedule_timezone,guild_id FROM bots WHERE user_id=? ORDER BY created_at DESC"
      ).bind(user.id).all();
      return reply({ deployments: rows.map(row => ({
        ...row,
        modules: typeof row.modules === "string" ? JSON.parse(row.modules) : row.modules,
        customProject: typeof row.custom_project === "string" ? JSON.parse(row.custom_project || "null") : (row.custom_project || null),
        projectType: row.project_type === "custom" || row.custom_project ? "custom" : "standard",
        hasDiscordToken: !!row.has_discord_token,
        discordBotId: row.discord_bot_id || null,
        discordBotName: row.discord_bot_name || null,
        hostingDeploymentId: row.provider_app_id || row.hosting_deployment_id || null,
        hostingProvider: row.hosting_provider || "bot-hosting",
        providerAppId: row.provider_app_id || null,
        scheduleEnabled: !!row.schedule_enabled,
        scheduleStart: row.schedule_start || "00:00",
        scheduleEnd: row.schedule_end || "23:59",
        scheduleTimezone: row.schedule_timezone || "America/Bahia",
        guildId: row.guild_id || "",
        executionAvailable: !!(row.hosting_deployment_id || row.provider_app_id)
      })) });
    }
    if (path === "/bots" && request.method === "POST") {
      const b = await body(request);
      let name = String(b.name || "").trim().slice(0, 48);
      const projectType = b.projectType === "custom" ? "custom" : "standard";
      const runtime = projectType === "custom" && b.runtime === "nodejs" ? "nodejs" : "python";
      if (b.runtime && !["python","nodejs"].includes(b.runtime)) {
        return reply({ error: "Escolha Python ou Node.js para o seu próprio bot." }, 400);
      }
      if (name.length < 2) return reply({ error: "Digite um nome com pelo menos 2 caracteres." }, 400);

      // Create the project first; Discord credentials have their own save flow.
      const rawToken = String(b.discordToken || "").trim();
      let prepared = null;
      if (rawToken) {
        prepared = await prepareDiscordBotToken(rawToken, env);
        if (!prepared.ok) return reply({ error: prepared.error }, prepared.status);
      }
      if (prepared) {
        const claimed = await env.DB.prepare(
          "SELECT id,user_id,name FROM bots WHERE discord_bot_id=? LIMIT 1"
        ).bind(prepared.identity.botId).first();
        if (claimed) {
          return reply({ error: "Este bot Discord já está cadastrado no Estúdio. Cada Bot Token só pode pertencer a um projeto." }, 409);
        }
        const central = await verificationBotSettings(env);
        if (central?.bot_id && String(central.bot_id) === String(prepared.identity.botId)) {
          return reply({ error: "Este Bot Token pertence ao bot central do Estúdio e não pode ser usado em outro projeto." }, 409);
        }
      }
      if (!name) name = String(prepared?.identity?.botName || "Meu bot").trim().slice(0, 48) || "Meu bot";
      if (name.length < 2) return reply({ error: "O nome identificado do bot é inválido. Informe um nome com pelo menos 2 caracteres." }, 400);

      const id = randomToken(12);
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO bots (id,user_id,name,runtime,project_type,state,modules,discord_token_enc,discord_bot_id,discord_bot_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        id, user.id, name, runtime, projectType, "draft", JSON.stringify({}),
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
        id, name, runtime, projectType, state: "draft", modules: {},
        hasDiscordToken: !!prepared,
        discordBotId: persisted.discord_bot_id || null,
        discordBotName: persisted.discord_bot_name || null,
        executionAvailable: false,
        message: prepared
          ? "Projeto criado e token Discord armazenado com segurança."
          : "Projeto criado. Agora salve e valide o Bot Token para poder iniciar."
      }, 201);
    }

    const match = path.match(/^\/bots\/([A-Za-z0-9_-]{1,80})(?:\/(logs|power|upload-url|upload-chunk|auto-upload|extract|import|config|resources|files|shell|schedule|diagnose|backups)(?:\/([A-Za-z0-9._-]{1,120})(?:\/(restore))?)?)?$/);
    if (match) {
      const id = match[1];
      const action = match[2] || "";
      const subPath = match[3] || "";
      const suffix = match[4] || "";
      const bot = await getOwnedBot(id, user.id, env);
      if (!bot) return reply({ error: "Projeto não encontrado nesta conta." }, 404);

      if (action === "upload-chunk" && request.method === "POST") {
        if (bot.project_type !== "custom" && !bot.custom_project) {
          return reply({ code: "custom_project_required", error: "Este projeto precisa ser criado como Meu próprio bot antes de importar um ZIP." }, 409);
        }
        try {
          const b = await body(request);
          const uploadId = String(b.uploadId || "");
          const index = Number(b.index);
          const totalChunks = Number(b.totalChunks);
          const chunkBase64 = String(b.chunkBase64 || "");
          if (!/^[A-Za-z0-9_-]{16,80}$/.test(uploadId)) return reply({ error: "Identificador de envio inválido." }, 400);
          if (!Number.isInteger(index) || !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > 100 || index < 0 || index >= totalChunks) {
            return reply({ error: "Índice ou quantidade de partes inválida." }, 400);
          }
          if (!chunkBase64 || chunkBase64.length > 360000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(chunkBase64)) {
            return reply({ error: "Parte do ZIP vazia ou maior que o limite de 256 KB." }, 413);
          }
          let decodedLength = 0;
          try { decodedLength = atob(chunkBase64).length; } catch { return reply({ error: "Parte do ZIP em Base64 inválida." }, 400); }
          if (decodedLength > 256 * 1024) return reply({ error: "Cada parte do ZIP pode ter no máximo 256 KB." }, 413);
          await env.DB.prepare("DELETE FROM bot_upload_chunks WHERE created_at<?").bind(Date.now() - 6 * 60 * 60 * 1000).run();
          await env.DB.prepare(
            "INSERT INTO bot_upload_chunks (user_id,bot_id,upload_id,chunk_index,total_chunks,chunk_base64,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT (user_id,bot_id,upload_id,chunk_index) DO UPDATE SET total_chunks=EXCLUDED.total_chunks,chunk_base64=EXCLUDED.chunk_base64,created_at=EXCLUDED.created_at"
          ).bind(user.id, id, uploadId, index, totalChunks, chunkBase64, Date.now()).run();
          return reply({ ok: true, uploadId, index, totalChunks, received: decodedLength });
        } catch (error) {
          return reply({ error: error.message || "Não consegui guardar esta parte do ZIP." }, 500);
        }
      }

      if (!action && request.method === "DELETE") {
        let deploymentDeleted = false;
        let externalServerRetained = false;
        if (["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
          try {
            const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
            const requestFn = providerRequestForId(providerId);
            const providerName = providerDisplayName(providerId);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte " + providerName + " antes de remover este projeto para que o Estúdio consiga parar o servidor." }, 409);
            await requestFn(token, "/servers/" + encodeURIComponent(keritIdentifier(bot.provider_app_id)) + "/power", "POST", { signal: "stop" });
            externalServerRetained = true;
          } catch (error) {
            return reply({ error: "Não consegui parar o servidor externo. O projeto continua salvo no Estúdio. " + (error.message || "") }, 502);
          }
        }
        if (bot.hosting_provider === "discloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "discloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Discloud antes de excluir a aplicação para não deixar recursos abandonados." }, 409);
            await discloudRequest(token, "/app/" + encodeURIComponent(bot.provider_app_id) + "/delete", "DELETE");
            deploymentDeleted = true;
          } catch (error) {
            return reply({ error: "Não consegui remover a aplicação da Discloud. O projeto continua salvo no painel. " + (error.message || "") }, 502);
          }
        }
        if (bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "cubecloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting antes de excluir este projeto." }, 409);
            await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)), "DELETE");
            deploymentDeleted = true;
          } catch (error) {
            return reply({ error: "Não consegui remover o projeto da Cube Hosting. O projeto continua salvo no Estúdio. " + (error.message || "") }, 502);
          }
        }
        if (bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
          try {
            const token = await providerToken(user.id, "squarecloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud antes de excluir a aplicação para não deixar recursos abandonados." }, 409);
            await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)), "DELETE");
            deploymentDeleted = true;
          } catch (error) {
            return reply({ error: "Não consegui remover a aplicação da Square Cloud. O projeto continua salvo no painel. " + (error.message || "") }, 502);
          }
        }
        if (bot.hosting_deployment_id && bot.hosting_provider !== "discloud") {
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
        return reply({ ok: true, deleted: true, deploymentDeleted, externalServerRetained, sharedDeploymentRetained: !!bot.hosting_deployment_id && !deploymentDeleted });
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
        if (bot.hosting_provider === "discloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "discloud", env);
            if (!token) throw new Error("Conta Discloud desconectada.");
            const status = await discloudRequest(token, "/app/" + encodeURIComponent(bot.provider_app_id) + "/status");
            runtimeInfo = status.apps || status;
            const container = String(status.apps?.container || "").toLowerCase();
            state = container === "online" || container === "running" ? "running" : (container === "offline" || container === "stopped" ? "stopped" : "starting");
          } catch (error) {
            runtimeInfo = { error: error.message || "Falha ao consultar Discloud." };
          }
        } else if (bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
          try {
            const token = await providerToken(user.id, "squarecloud", env);
            if (!token) throw new Error("Conta Square Cloud desconectada.");
            const status = await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/status");
            runtimeInfo = status;
            state = String(status.status || (status.running ? "running" : "stopped")).toLowerCase();
          } catch (error) {
            runtimeInfo = { error: error.message || "Falha ao consultar Square Cloud." };
          }

        } else if (bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
          try {
            const token = await providerToken(user.id, "aclclouds", env);
            if (!token) throw new Error("Conta ACLClouds desconectada.");
            const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/resources");
            runtimeInfo = aclCloudsAttributes(result.data);
            const current = String(runtimeInfo.current_state || "").toLowerCase();
            state = current === "running" ? "running" : (current === "starting" ? "starting" : "stopped");
          } catch (error) { runtimeInfo = { error: error.message || "Falha ao consultar ACLClouds." }; }
        } else if (bot.hosting_provider === "cogithost" && bot.provider_app_id) {
          try {
            const config = await cogitConfig(user.id, env);
            if (!config) throw new Error("Conta Cogithost desconectada.");
            const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/resources");
            runtimeInfo = result.data?.attributes || result.data;
            const current = String(runtimeInfo.current_state || "").toLowerCase();
            state = current === "running" ? "running" : (current === "starting" ? "starting" : "stopped");
          } catch (error) { runtimeInfo = { error: error.message || "Falha ao consultar Cogithost." }; }
        } else if (["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
          try {
            const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
            const requestFn = providerRequestForId(providerId);
            if (!token) throw new Error("Conta de hospedagem desconectada.");
            const result = await requestFn(token, "/servers/" + encodeURIComponent(keritIdentifier(bot.provider_app_id)) + "/resources");
            runtimeInfo = result.data?.attributes || result.data;
            const current = String(runtimeInfo.current_state || "").toLowerCase();
            state = runtimeInfo.is_suspended ? "stopped" : (current === "running" ? "running" : (current === "starting" ? "starting" : "stopped"));
          } catch (error) { runtimeInfo = { error: error.message || "Falha ao consultar hospedagem Pterodactyl." }; }
        } else if (bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "cubecloud", env);
            if (!token) throw new Error("Conta Cube Hosting desconectada.");
            const data = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)));
            runtimeInfo = data.project || data;
            state = String(runtimeInfo.status || state).toLowerCase();
          } catch (error) {
            runtimeInfo = { error: error.message || "Falha ao consultar Cube Hosting." };
          }
        } else if (bot.hosting_deployment_id) {
          try {
            runtimeInfo = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/diagnose?waitSeconds=0");
            state = runtimeInfo.state || state;
          } catch (error) {
            runtimeInfo = { error: error.message };
          }
          const customProjectMode = bot.project_type === "custom" || !!bot.custom_project;
          discordStatus = customProjectMode ? null : await readDiscordRuntimeStatus(user.id, env, bot.hosting_deployment_id);
        }
        const scheduleAllowed = !bot.schedule_enabled ||
          isInsideSchedule(bot.schedule_start || "00:00", bot.schedule_end || "23:59", bot.schedule_timezone || "America/Bahia");
        const discordOnline = state === "running" && scheduleAllowed && recentDiscordStatus(discordStatus);
        const modules = typeof bot.modules === "string" ? JSON.parse(bot.modules || "{}") : (bot.modules || {});
        return reply({
          id: bot.id, name: bot.name, runtime: bot.runtime, state,
          modules, customProject: typeof bot.custom_project === "string" ? JSON.parse(bot.custom_project || "null") : (bot.custom_project || null),
          projectType: bot.project_type === "custom" || bot.custom_project ? "custom" : "standard",
          hasDiscordToken: hasToken,
          discordBotId, discordBotName,
          hostingDeploymentId: bot.provider_app_id || bot.hosting_deployment_id || null,
          hostingProvider: bot.hosting_provider || "bot-hosting",
          providerAppId: bot.provider_app_id || null,
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
          executionAvailable: !!(bot.hosting_deployment_id || bot.provider_app_id),
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
        if (bot.hosting_deployment_id && bot.hosting_provider !== "discloud") {
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
        if (bot.hosting_provider === "discloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "discloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "A conexão Discloud não está disponível. Reconecte o provedor em Configurações." }, 409);
            const appId = encodeURIComponent(bot.provider_app_id);
            const result = await discloudRequest(token, "/app/" + appId + "/" + signal, "PUT");
            const status = await discloudRequest(token, "/app/" + appId + "/status");
            const container = String(status.apps?.container || status.app?.container || "").toLowerCase();
            const online = container === "online" || container === "running";
            const state = signal === "stop" ? "stopped" : (online ? "running" : "starting");
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?")
              .bind(state, Date.now(), id, user.id).run();
            return reply({
              ok: true, action: signal, state, provider: "discloud",
              providerAppId: bot.provider_app_id,
              discordOnline: false,
              hint: signal === "stop" ? "Parada solicitada à Discloud." : "Comando enviado à Discloud. Confira os logs para confirmar a conexão do bot com o Discord.",
              providerMessage: result.message || null
            });
          } catch (error) {
            return reply({ ok: false, code: "provider_action_failed", error: error.message || "Falha ao controlar a aplicação na Discloud." }, 502);
          }
        }
        if (bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
          try {
            const token = await providerToken(user.id, "aclclouds", env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
            const serverId = aclCloudsIdentifier(bot.provider_app_id);
            await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
            const check = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
            const resource = aclCloudsAttributes(check.data);
            const current = String(resource.current_state || "").toLowerCase();
            const state = signal === "stop" ? "stopped" : (current === "running" ? "running" : "starting");
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?").bind(state, Date.now(), id, user.id).run();
            return reply({ ok: true, action: signal, state, provider: "aclclouds", providerAppId: serverId, discordOnline: false,
              resources: resource.resources || null, hint: signal === "stop" ? "Servidor parado na ACLClouds." : "Comando enviado à ACLClouds. Confira os logs para confirmar a conexão do Discord." });
          } catch (error) { return reply({ ok: false, error: error.message || "Falha ao controlar servidor ACLClouds." }, 502); }
        }
        if (bot.hosting_provider === "cogithost" && bot.provider_app_id) {
          try {
            const config = await cogitConfig(user.id, env);
            if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
            const serverId = cogitIdentifier(bot.provider_app_id);
            await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
            const resource = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/resources");
            const current = String(resource.data?.attributes?.current_state || "").toLowerCase();
            const state = signal === "stop" ? "stopped" : (current === "running" ? "running" : "starting");
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?").bind(state, Date.now(), id, user.id).run();
            return reply({ ok: true, action: signal, state, provider: "cogithost", providerAppId: serverId, discordOnline: false,
              resources: resource.data?.attributes?.resources || null,
              hint: signal === "stop" ? "Servidor parado no Cogithost." : "Comando enviado. Confira o console do painel Cogithost para confirmar a inicialização." });
          } catch (error) { return reply({ ok: false, error: error.message || "Falha ao controlar o servidor Cogithost." }, 502); }
        }
        if (["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
          try {
            const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
            const requestFn = providerRequestForId(providerId);
            const providerName = providerDisplayName(providerId);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte " + providerName + " nas Configurações." }, 409);
            const serverId = keritIdentifier(bot.provider_app_id);
            await requestFn(token, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
            const resource = await requestFn(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
            const current = String(resource.data?.attributes?.current_state || "").toLowerCase();
            const state = signal === "stop" ? "stopped" : (current === "running" ? "running" : "starting");
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?").bind(state, Date.now(), id, user.id).run();
            return reply({ ok: true, action: signal, state, provider: providerId, providerAppId: serverId, discordOnline: false,
              resources: resource.data?.attributes?.resources || null,
              hint: signal === "stop" ? "Servidor parado em " + providerName + "." : "Comando enviado. Confira o console " + providerName + " para confirmar a inicialização." });
          } catch (error) { return reply({ ok: false, error: error.message || "Falha ao controlar o servidor externo." }, 502); }
        }
        if (bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
          try {
            const token = await providerTokenForPool(user.id, "cubecloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
            const projectId = cubeProjectId(bot.provider_app_id);
            const result = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(projectId) + "/" + signal, "POST");
            const project = result.project || {};
            const state = String(project.status || (signal === "stop" ? "stopped" : "running")).toLowerCase();
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?")
              .bind(state, Date.now(), id, user.id).run();
            return reply({
              ok: true, action: signal, state, provider: "cubecloud",
              providerAppId: projectId, discordOnline: false,
              resources: project.usage || null,
              hint: signal === "stop" ? "Projeto parado na Cube Hosting." : "Comando enviado à Cube Hosting. Confira os logs para confirmar a conexão do Discord."
            });
          } catch (error) {
            return reply({ ok: false, code: "provider_action_failed", error: error.message || "Falha ao controlar o projeto na Cube Hosting." }, 502);
          }
        }
        if (bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
          try {
            const token = await providerToken(user.id, "squarecloud", env);
            if (!token) return reply({ code: "provider_not_connected", error: "A conexão Square Cloud não está disponível. Reconecte em Configurações." }, 409);
            const appId = encodeURIComponent(squareAppId(bot.provider_app_id));
            let actionResult = null;
            try {
              actionResult = await squareCloudRequest(token, "/apps/" + appId + "/" + signal, "POST");
            } catch (error) {
              const code = String(error?.code || "");
              if (!((signal === "start" && code === "CONTAINER_ALREADY_STARTED") ||
                    (signal === "stop" && code === "CONTAINER_ALREADY_STOPPED"))) throw error;
            }
            const status = await squareCloudRequest(token, "/apps/" + appId + "/status");
            const state = signal === "stop" ? "stopped" : String(status.status || (status.running ? "running" : "starting")).toLowerCase();
            await env.DB.prepare("UPDATE bots SET state=?,updated_at=? WHERE id=? AND user_id=?")
              .bind(state, Date.now(), id, user.id).run();
            return reply({
              ok: true, action: signal, state, provider: "squarecloud",
              providerAppId: bot.provider_app_id, discordOnline: false,
              resources: { cpu: status.cpu ?? null, ram: status.ram ?? null, storage: status.storage ?? null, uptime: status.uptime ?? null },
              hint: signal === "stop" ? "Processo parado na Square Cloud." : "Comando enviado à Square Cloud. Confira os logs para confirmar a conexão do Discord.",
              providerMessage: actionResult?.message || null
            });
          } catch (error) {
            return reply({ ok: false, code: "provider_action_failed", error: error.message || "Falha ao controlar a aplicação na Square Cloud." }, 502);
          }
        }
        // Se o upload da Discloud sofreu timeout, não volte a tentar provisionar
        // no Bot-Hosting por engano: primeiro recupere a aplicação ou informe que
        // ainda é preciso confirmar/reimportar o mesmo ZIP.
        if ((signal === "start" || signal === "restart") && bot.hosting_provider === "bot-hosting" &&
            !bot.provider_app_id && !bot.hosting_deployment_id) {
          let pendingProject = bot.custom_project;
          if (typeof pendingProject === "string") {
            try { pendingProject = JSON.parse(pendingProject || "null"); } catch { pendingProject = null; }
          }
          if (pendingProject?.discloudUploadPending) {
            try {
              const recovery = await recoverPendingDiscloudBot(bot, user.id, env);
              if (recovery.recovered) {
                return reply({
                  ok: true, action: signal, state: "starting", provider: "discloud",
                  providerAppId: recovery.providerAppId, discordOnline: false,
                  message: recovery.message, hint: recovery.message
                });
              }
              if (recovery.pending) {
                return reply({
                  ok: false, code: "discloud_upload_pending",
                  error: recovery.error || "A Discloud ainda não confirmou a tentativa anterior."
                }, 409);
              }
            } catch (error) {
              return reply({
                ok: false, code: "discloud_recovery_failed",
                error: "O Estúdio não vai tentar criar outro servidor enquanto a tentativa Discloud anterior não for verificada. " + String(error?.message || "")
              }, 409);
            }
          }
        }
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

          const customProjectMode = bot.project_type === "custom" || !!bot.custom_project;
          if (signal !== "stop" && !customProjectMode) {
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

          const discordStatus = signal === "stop" || customProjectMode
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
          const rawMessage = String(error?.message || "");
          const noSlots = /HTTP 402\b|all slots|plan.*in use|slots.*use/i.test(rawMessage);
          return reply({
            ok: false,
            code: noSlots ? "free_hosting_capacity_full" : "provider_action_failed",
            error: noSlots
              ? "A hospedagem gratuita atual está sem vagas (HTTP 402). O Estúdio não vai contratar plano pago nem mexer nos seus outros bots. Tente novamente quando uma vaga gratuita estiver disponível; seus arquivos e configurações continuam preservados."
              : (rawMessage || "Falha ao controlar o bot na hospedagem.")
          }, noSlots ? 402 : 502);
        }
      }

      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && bot.hosting_provider === "discloud" && bot.provider_app_id) {
        try {
          const token = await providerTokenForPool(user.id, "discloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Discloud nas Configurações." }, 409);
          const appId = encodeURIComponent(bot.provider_app_id);
          if (action === "logs") {
            const result = await discloudRequest(token, "/app/" + appId + "/logs");
            const terminal = result.apps?.terminal || result.terminal || {};
            const raw = String(terminal.big || terminal.small || result.message || "");
            const lines = raw.split(/\\r?\\n/).filter(Boolean).slice(-200);
            return reply({ provider: "discloud", lines, logs: lines, raw });
          }
          if (action === "diagnose") {
            return reply(await discloudRequest(token, "/app/" + appId + "/status"));
          }
          return reply({ provider: "discloud", resources: null, note: "A API pública da Discloud não fornece os mesmos limites detalhados de CPU e armazenamento do Bot-Hosting." });
        } catch (error) {
          return reply({ error: error.message || "Não consegui consultar a Discloud." }, 502);
        }
      }
      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const serverId = aclCloudsIdentifier(bot.provider_app_id);
          if (action === "logs") {
            const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/logs?lines=100");
            const payload = result.data || {};
            const rawLines = Array.isArray(payload.data) ? payload.data : (Array.isArray(payload) ? payload : []);
            const lines = rawLines.map(line => String(typeof line === "string" ? line : (line?.attributes?.line || line?.line || line?.message || JSON.stringify(line)))).slice(-100);
            return reply({ provider: "aclclouds", lines, logs: lines });
          }
          const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
          const attributes = aclCloudsAttributes(result.data);
          if (action === "diagnose") return reply({ provider: "aclclouds", ...attributes });
          const usage = attributes.resources || {};
          return reply({ provider: "aclclouds", resources: {
            currentState: attributes.current_state || null, cpu: usage.cpu_absolute ?? null,
            memoryBytes: usage.memory_bytes ?? null, diskBytes: usage.disk_bytes ?? null,
            networkRxBytes: usage.network_rx_bytes ?? null, networkTxBytes: usage.network_tx_bytes ?? null,
            uptime: usage.uptime ?? null
          } });
        } catch (error) { return reply({ error: error.message || "Não consegui consultar ACLClouds." }, 502); }
      }
      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const serverId = cogitIdentifier(bot.provider_app_id);
          if (action === "logs") return reply({ provider: "cogithost", lines: [], note: "O console ao vivo do Cogithost usa WebSocket; abra o console no painel Cogithost para ver a saída em tempo real." });
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/resources");
          const data = result.data?.attributes || {};
          if (action === "diagnose") return reply({ provider: "cogithost", ...data });
          return reply({ provider: "cogithost", resources: {
            currentState: data.current_state || null, cpu: data.resources?.cpu_absolute ?? null,
            memoryBytes: data.resources?.memory_bytes ?? null, diskBytes: data.resources?.disk_bytes ?? null,
            networkRxBytes: data.resources?.network_rx_bytes ?? null, networkTxBytes: data.resources?.network_tx_bytes ?? null,
            uptime: data.resources?.uptime ?? null
          } });
        } catch (error) { return reply({ error: error.message || "Não consegui consultar o Cogithost." }, 502); }
      }
      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && ["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
        try {
          const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
          const requestFn = providerRequestForId(providerId);
          const providerName = providerDisplayName(providerId);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte " + providerName + " nas Configurações." }, 409);
          const serverId = keritIdentifier(bot.provider_app_id);
          if (action === "logs") return reply({ provider: providerId, lines: [], note: "O console ao vivo usa WebSocket. Abra o Console no painel " + providerName + " para acompanhar a saída." });
          const result = await requestFn(token, "/servers/" + encodeURIComponent(serverId) + "/resources");
          const data = result.data?.attributes || {};
          if (action === "diagnose") return reply({ provider: providerId, currentState: data.current_state || null, resources: data.resources || null });
          return reply({ provider: providerId, resources: {
            currentState: data.current_state || null,
            cpu: data.resources?.cpu_absolute ?? null,
            memoryBytes: data.resources?.memory_bytes ?? null,
            diskBytes: data.resources?.disk_bytes ?? null,
            networkRxBytes: data.resources?.network_rx_bytes ?? null,
            networkTxBytes: data.resources?.network_tx_bytes ?? null,
            uptime: data.resources?.uptime ?? null
          } });
        } catch (error) { return reply({ error: error.message || "Não consegui consultar o hospedagem Pterodactyl." }, 502); }
      }
      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          const projectId = cubeProjectId(bot.provider_app_id);
          if (action === "logs") return reply(await cubeCloudLogs(token, projectId));
          if (action === "diagnose") {
            const data = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(projectId));
            return reply({ provider: "cubecloud", ...(data.project || data) });
          }
          const metrics = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(projectId) + "/metrics?window=15m");
          const point = (Array.isArray(metrics.points) ? metrics.points : []).slice(-1)[0] || {};
          return reply({
            provider: "cubecloud",
            resources: {
              cpu: point.cpuPercent ?? null,
              ram: point.memoryMb ?? null,
              memoryLimitMb: metrics.memoryLimitMb ?? null,
              networkInBps: point.networkInBps ?? null,
              networkOutBps: point.networkOutBps ?? null
            },
            metrics
          });
        } catch (error) {
          return reply({ error: error.message || "Não consegui consultar a Cube Hosting." }, 502);
        }
      }
      if ((action === "logs" || action === "diagnose" || action === "resources") && request.method === "GET" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          const appId = encodeURIComponent(squareAppId(bot.provider_app_id));
          if (action === "logs") {
            const result = await squareCloudRequest(token, "/apps/" + appId + "/logs");
            const raw = String(result.logs || "");
            const lines = raw.split(/\r?\n/).filter(Boolean).slice(-200);
            return reply({ provider: "squarecloud", lines, logs: lines, raw });
          }
          const status = await squareCloudRequest(token, "/apps/" + appId + "/status");
          if (action === "diagnose") return reply({ provider: "squarecloud", ...status });
          return reply({
            provider: "squarecloud",
            resources: { cpu: status.cpu ?? null, ram: status.ram ?? null, status: status.status ?? null, storage: status.storage ?? null, network: status.network ?? null, uptime: status.uptime ?? null }
          });
        } catch (error) {
          return reply({ error: error.message || "Não consegui consultar a Square Cloud." }, 502);
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

      if (action === "files" && ["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
        try {
          const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
          const requestFn = providerRequestForId(providerId);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a hospedagem nas Configurações." }, 409);
          const serverId = keritIdentifier(bot.provider_app_id);
          const base = "/servers/" + encodeURIComponent(serverId) + "/files";
          if (!subPath && request.method === "GET") {
            const directory = safeVolumePath(url.searchParams.get("path") || "/");
            const result = await requestFn(token, base + "/list?directory=" + encodeURIComponent(directory));
            const values = Array.isArray(result.data?.data) ? result.data.data : [];
            const entries = values.map(item => {
              const a = item?.attributes || {};
              return { name: String(a.name || ""), type: a.is_file ? "file" : "directory", sizeBytes: Number(a.size || 0), modifiedAt: a.modified_at || null };
            }).filter(item => item.name);
            return reply({ provider: providerId, path: directory, entries });
          }
          if (subPath === "download-url" && request.method === "GET") {
            const filePath = safeVolumePath(url.searchParams.get("path") || "/");
            const result = await requestFn(token, base + "/download?file=" + encodeURIComponent(filePath));
            const downloadUrl = String(result.data?.attributes?.url || result.data?.url || "");
            if (!downloadUrl.startsWith("https://")) return reply({ error: "A hospedagem não retornou link HTTPS para download." }, 502);
            return reply({ provider: providerId, url: downloadUrl, filename: filePath.split("/").pop() || "download.bin" });
          }
          if (subPath === "content" && request.method === "GET") {
            const filePath = safeVolumePath(url.searchParams.get("path") || "/main.py");
            if (/\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf|zip|pdf|db|sqlite)$/i.test(filePath)) return reply({ error: "Arquivo binário. Use Baixar." }, 415);
            const result = await requestFn(token, base + "/contents?file=" + encodeURIComponent(filePath));
            return reply({ provider: providerId, path: filePath, content: result.raw, totalLines: result.raw.split("\n").length });
          }
          if (subPath === "content" && request.method === "POST") {
            const b = await body(request), filePath = safeVolumePath(b.path), content = String(b.content ?? "");
            if (content.length > 450000) return reply({ error: "O arquivo é grande demais para o editor." }, 413);
            const result = await requestFn(token, base + "/write?file=" + encodeURIComponent(filePath), "POST", content, true);
            return reply({ ok: true, provider: providerId, status: result.status });
          }
          if (subPath === "delete" && request.method === "POST") {
            const b = await body(request), filePath = safeVolumePath(b.path);
            if (filePath === "/") return reply({ error: "A pasta raiz não pode ser removida." }, 400);
            const root = filePath.split("/").slice(0, -1).join("/") || "/";
            const name = filePath.split("/").pop();
            const result = await requestFn(token, base + "/delete", "POST", { root, files: [name] });
            return reply(result.data || { ok: true });
          }
          if (subPath === "compress" && request.method === "POST") {
            const b = await body(request), root = safeVolumePath(b.root || "/");
            const items = Array.isArray(b.files) ? b.files.map(item => String(item || "").replace(/^\/+/, "")) : [];
            if (!items.length || items.length > 60 || items.some(item => !item || item.split("/").some(part => part === ".."))) {
              return reply({ error: "Selecione de 1 a 60 arquivos ou pastas válidos para exportar." }, 400);
            }
            const result = await requestFn(token, base + "/compress", "POST", { root, files: items });
            const archive = String(result.data?.attributes?.name || result.data?.name || "");
            if (!archive) return reply({ error: "A hospedagem não retornou o nome do ZIP criado." }, 502);
            return reply({ provider: providerId, archive, filesCount: items.length });
          }
        } catch (error) {
          return reply({ error: error.message || "Falha ao acessar os arquivos da hospedagem." }, 502);
        }
      }

      if (action === "files" && !subPath && request.method === "GET" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const directory = safeVolumePath(url.searchParams.get("path") || "/");
          const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/files/list?directory=" + encodeURIComponent(directory));
          const payload = result.data || {};
          const values = Array.isArray(payload.data) ? payload.data : (Array.isArray(payload) ? payload : []);
          const entries = values.map(item => {
            const a = item?.attributes || item || {};
            return { name: String(a.name || ""), type: a.is_file ? "file" : "directory", sizeBytes: Number(a.size || 0), modifiedAt: a.modified_at || null };
          }).filter(item => item.name);
          return reply({ provider: "aclclouds", path: directory, entries });
        } catch (error) { return reply({ error: error.message || "Falha ao listar arquivos ACLClouds." }, 502); }
      }
      if (action === "files" && !subPath && request.method === "GET" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const directory = safeVolumePath(url.searchParams.get("path") || "/");
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/list?directory=" + encodeURIComponent(directory));
          const entries = (Array.isArray(result.data?.data) ? result.data.data : []).map(item => {
            const a = item?.attributes || {};
            return { name: String(a.name || ""), type: a.is_file ? "file" : "directory", sizeBytes: Number(a.size || 0), modifiedAt: a.modified_at || null };
          }).filter(item => item.name);
          return reply({ provider: "cogithost", path: directory, entries });
        } catch (error) { return reply({ error: error.message || "Falha ao listar arquivos Cogithost." }, 502); }
      }
      if (action === "files" && !subPath && request.method === "GET" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          const root = safeVolumePath(url.searchParams.get("path") || "/");
          const relativeRoot = cubeRelativePath(root);
          const query = relativeRoot ? "?path=" + encodeURIComponent(relativeRoot) : "";
          const data = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)) + "/files" + query);
          const entries = (Array.isArray(data.items) ? data.items : []).map(item => ({
            name: String(item.name || ""),
            type: String(item.type || "").toLowerCase() === "directory" ? "directory" : "file",
            sizeBytes: Number(item.sizeBytes || 0),
            modifiedAt: item.modifiedAt || null,
            isProtected: !!item.isProtected
          })).filter(item => item.name);
          return reply({ provider: "cubecloud", path: root, entries, isTruncated: !!data.isTruncated });
        } catch (error) {
          return reply({ error: error.message || "Falha ao listar arquivos da Cube Hosting." }, 502);
        }
      }
      if (action === "files" && !subPath && request.method === "GET" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          const root = safeVolumePath(url.searchParams.get("path") || "/");
          const result = await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files?path=" + encodeURIComponent(root));
          const entries = (Array.isArray(result) ? result : []).map(item => ({
            name: String(item.name || ""),
            type: String(item.type || "").toLowerCase() === "directory" ? "directory" : "file",
            sizeBytes: Number(item.size || 0),
            modifiedAt: item.lastModified ? Number(item.lastModified) : null
          })).filter(item => item.name);
          return reply({ provider: "squarecloud", path: root, entries });
        } catch (error) {
          return reply({ error: error.message || "Falha ao listar arquivos na Square Cloud." }, 502);
        }
      }
      if (action === "files" && !subPath && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de abrir os arquivos." }, 409);
        try {
          const root = safeVolumePath(url.searchParams.get("path") || "/");
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files?path=" + encodeURIComponent(root)));
        } catch (error) { return reply({ error: error.message || "Falha ao listar arquivos." }, 502); }
      }

      if (action === "files" && subPath === "download-url" && request.method === "GET" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const filePath = safeVolumePath(url.searchParams.get("path") || "/");
          const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/files/download?file=" + encodeURIComponent(filePath));
          const downloadUrl = String(aclCloudsAttributes(result.data).url || result.data?.url || "");
          if (!downloadUrl.startsWith("https://")) return reply({ error: "ACLClouds não retornou uma URL de download segura." }, 502);
          const response = await fetch(downloadUrl, { signal: AbortSignal.timeout(60000) });
          if (!response.ok) throw new Error("Download ACLClouds · HTTP " + response.status);
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.byteLength > 4 * 1024 * 1024) return reply({ error: "O arquivo passa de 4 MB. Use o painel ACLClouds para baixar arquivos maiores." }, 413);
          let binary = ""; for (let i=0;i<bytes.length;i+=0x8000) binary += String.fromCharCode(...bytes.subarray(i,i+0x8000));
          return reply({ provider: "aclclouds", base64: btoa(binary), filename: filePath.split("/").pop() || "download.bin" });
        } catch (error) { return reply({ error: error.message || "Falha ao baixar arquivo ACLClouds." }, 502); }
      }
      if (action === "files" && subPath === "download-url" && request.method === "GET" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const filePath = safeVolumePath(url.searchParams.get("path") || "/");
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/download?file=" + encodeURIComponent(filePath));
          const signedUrl = String(result.data?.attributes?.url || result.data?.url || "");
          if (!signedUrl.startsWith("https://")) return reply({ error: "O Cogithost não retornou link de download seguro." }, 502);
          const response = await fetch(signedUrl, { signal: AbortSignal.timeout(60000) });
          if (!response.ok) throw new Error("Falha ao baixar arquivo Cogithost: HTTP " + response.status);
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.byteLength > 4 * 1024 * 1024) return reply({ error: "O arquivo passa de 4 MB. Use o painel Cogithost para baixar arquivos maiores." }, 413);
          let binary = ""; for (let i=0;i<bytes.length;i+=0x8000) binary += String.fromCharCode(...bytes.subarray(i,i+0x8000));
          return reply({ provider: "cogithost", base64: btoa(binary), filename: filePath.split("/").pop() || "download.bin" });
        } catch (error) { return reply({ error: error.message || "Falha ao baixar arquivo Cogithost." }, 502); }
      }
      if (action === "files" && subPath === "download-url" && request.method === "GET" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          const projectId = cubeProjectId(bot.provider_app_id);
          const filePath = cubeRelativePath(url.searchParams.get("path") || "/");
          const signed = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(projectId) + "/files/download", "POST", { path: filePath });
          const downloadUrl = String(signed.url || "");
          if (!downloadUrl.startsWith("/projects/")) return reply({ error: "A Cube Hosting não retornou um link de download válido." }, 502);
          const response = await fetch("https://app.cubehosting.com.br/api" + downloadUrl, {
            headers: { Authorization: "Bearer " + token }, signal: AbortSignal.timeout(60000)
          });
          if (!response.ok) throw new Error("Cube Hosting · download · HTTP " + response.status);
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.byteLength > 4 * 1024 * 1024) return reply({ error: "O arquivo passa de 4 MB para download pelo Estúdio. Use o painel Cube Hosting para baixar arquivos maiores." }, 413);
          let binary = "";
          for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
          return reply({ provider: "cubecloud", base64: btoa(binary), filename: filePath.split("/").pop() || "download.bin" });
        } catch (error) {
          return reply({ error: error.message || "Falha ao baixar arquivo da Cube Hosting." }, 502);
        }
      }
      if (action === "files" && subPath === "download-url" && request.method === "GET" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          const filePath = safeVolumePath(url.searchParams.get("path"));
          const result = await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files/content?path=" + encodeURIComponent(filePath) + "&encoding=base64");
          if (!result?.data) return reply({ error: "O provedor não retornou o conteúdo do arquivo." }, 502);
          return reply({ provider: "squarecloud", base64: result.data, filename: filePath.split("/").pop() || "download.bin" });
        } catch (error) {
          return reply({ error: error.message || "Falha ao baixar arquivo da Square Cloud." }, 502);
        }
      }
      if (action === "files" && subPath === "download-url" && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Hospedagem não preparada." }, 409);
        try {
          const filePath = safeVolumePath(url.searchParams.get("path"));
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/download-url?path=" + encodeURIComponent(filePath)));
        } catch (error) { return reply({ error: error.message || "Falha ao preparar download." }, 502); }
      }

      if (action === "files" && subPath === "compress" && request.method === "POST" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        try {
          const b = await body(request);
          const items = Array.isArray(b.files) ? b.files : [];
          if (!items.length || items.length > 60) return reply({ error: "Selecione de 1 a 60 arquivos para exportar de uma vez." }, 400);
          const root = safeVolumePath(b.root || "/");
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          const zip = new JSZip();
          let totalBytes = 0;
          for (const item of items) {
            const rawPath = String(item || "");
            const filePath = safeVolumePath(rawPath.startsWith("/") ? rawPath : (root === "/" ? "/" + rawPath : root + "/" + rawPath));
            const content = await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files/content?path=" + encodeURIComponent(filePath) + "&encoding=base64");
            if (!content?.data) continue;
            const binary = atob(content.data);
            totalBytes += binary.length;
            if (totalBytes > 8 * 1024 * 1024) return reply({ error: "O ZIP selecionado passa de 8 MB. Exporte menos arquivos por vez." }, 413);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            const relative = filePath.replace(/^\/+/, "");
            zip.file(relative, bytes);
          }
          const archiveBase64 = await zip.generateAsync({ type: "base64", compression: "DEFLATE", compressionOptions: { level: 6 } });
          return reply({ provider: "squarecloud", archiveBase64, filename: "black-zone-export.zip", filesCount: items.length });
        } catch (error) {
          return reply({ error: error.message || "Falha ao compactar os arquivos na Square Cloud." }, 502);
        }
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

      if (action === "files" && subPath === "content" && request.method === "GET" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const filePath = safeVolumePath(url.searchParams.get("path") || "/main.py");
          if (/\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf|zip|pdf|db|sqlite)$/i.test(filePath)) return reply({ error: "Arquivo binário. Use Baixar." }, 415);
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/contents?file=" + encodeURIComponent(filePath));
          return reply({ provider: "cogithost", path: filePath, content: result.raw, totalLines: result.raw.split("\n").length });
        } catch (error) { return reply({ error: error.message || "Falha ao ler arquivo Cogithost." }, 502); }
      }
      if (action === "files" && subPath === "content" && request.method === "GET" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        try {
          const filePath = cubeRelativePath(url.searchParams.get("path") || "/main.py");
          if (/\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf|zip|pdf|db|sqlite)$/i.test(filePath)) {
            return reply({ error: "Este arquivo é binário e não pode ser aberto no editor. Use Baixar." }, 415);
          }
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          const data = await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)) + "/files/content?path=" + encodeURIComponent(filePath));
          const content = String(data.content || "");
          return reply({ provider: "cubecloud", path: "/" + filePath, content, totalLines: content.split("\n").length });
        } catch (error) {
          return reply({ error: error.message || "Falha ao ler arquivo da Cube Hosting." }, 502);
        }
      }
      if (action === "files" && subPath === "content" && request.method === "GET" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        try {
          const filePath = safeVolumePath(url.searchParams.get("path") || "/main.py");
          if (/\.(?:png|jpe?g|gif|webp|svg|ico|avif|bmp|tif?f|mp3|wav|ogg|m4a|flac|mp4|webm|mov|woff2?|ttf|otf|zip|pdf|db|sqlite)$/i.test(filePath)) {
            return reply({ error: "Este arquivo é binário e não pode ser aberto no editor de texto. Use o botão Baixar." }, 415);
          }
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          const result = await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files/content?path=" + encodeURIComponent(filePath) + "&encoding=base64");
          const content = decodeBase64Text(result?.data || "");
          return reply({ provider: "squarecloud", path: filePath, content, totalLines: content.split("\n").length });
        } catch (error) {
          return reply({ error: error.message || "Falha ao ler arquivo da Square Cloud." }, 502);
        }
      }
      if (action === "files" && subPath === "content" && request.method === "GET") {
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Inicie o bot antes de ler arquivos." }, 409);
        try {
          const filePath = safeVolumePath(url.searchParams.get("path") || "/main.py");
          const params = new URLSearchParams({ path: filePath, offset: String(Math.max(0, Number(url.searchParams.get("offset") || 0) || 0)), limit: String(Math.min(1000, Math.max(1, Number(url.searchParams.get("limit") || 400) || 400))) });
          return reply(await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?" + params.toString()));
        } catch (error) { return reply({ error: error.message || "Falha ao ler arquivo." }, 502); }
      }

      if (action === "files" && subPath === "content" && request.method === "POST" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        const b = await body(request), filePath = safeVolumePath(b.path), content = String(b.content ?? "");
        if (content.length > 450000) return reply({ error: "O arquivo é grande demais para o editor." }, 413);
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/write?file=" + encodeURIComponent(filePath), "POST", content, true);
          return reply({ ok: true, status: result.status });
        } catch (error) { return reply({ error: error.message || "Falha ao salvar arquivo Cogithost." }, 502); }
      }
      if (action === "files" && subPath === "content" && request.method === "POST" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        const b = await body(request);
        const filePath = cubeRelativePath(b.path);
        const content = String(b.content ?? "");
        if (!filePath) return reply({ error: "Escolha um arquivo para salvar." }, 400);
        if (content.length > 450000) return reply({ error: "O arquivo é grande demais para o editor de texto. Use o envio de arquivos." }, 413);
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          return reply(await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)) + "/files/content", "PUT", { path: filePath, content }));
        } catch (error) {
          return reply({ error: error.message || "Falha ao salvar arquivo na Cube Hosting." }, 502);
        }
      }
      if (action === "files" && subPath === "content" && request.method === "POST" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        const b = await body(request);
        const filePath = safeVolumePath(b.path);
        const content = String(b.content ?? "");
        if (content.length > 450000) return reply({ error: "O arquivo é grande demais para o editor de texto. Use o envio de arquivos." }, 413);
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          return reply(await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files", "PUT", { path: filePath, content }));
        } catch (error) {
          return reply({ error: error.message || "Falha ao salvar arquivo na Square Cloud." }, 502);
        }
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

      if (action === "files" && subPath === "delete" && request.method === "POST" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        const b = await body(request), filePath = safeVolumePath(b.path);
        if (filePath === "/") return reply({ error: "A pasta raiz não pode ser removida." }, 400);
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const root = filePath.split("/").slice(0, -1).join("/") || "/";
          const name = filePath.split("/").pop();
          const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/files/delete", "POST", { root, files: [name] });
          return reply(result.data || {});
        } catch (error) { return reply({ error: error.message || "Falha ao excluir arquivo ACLClouds." }, 502); }
      }
      if (action === "files" && subPath === "delete" && request.method === "POST" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        const b = await body(request), filePath = safeVolumePath(b.path);
        if (filePath === "/") return reply({ error: "A pasta raiz não pode ser removida." }, 400);
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          return reply((await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/delete", "POST", { root: "/", files: [filePath] })).data);
        } catch (error) { return reply({ error: error.message || "Falha ao excluir arquivo Cogithost." }, 502); }
      }
      if (action === "files" && subPath === "delete" && request.method === "POST" && bot.hosting_provider === "cubecloud" && bot.provider_app_id) {
        const b = await body(request);
        const filePath = cubeRelativePath(b.path);
        if (!filePath || ["main.py","runner.py","index.js"].includes(filePath)) return reply({ error: "A raiz ou o arquivo principal do bot não pode ser removido pelo Estúdio." }, 400);
        try {
          const token = await providerTokenForPool(user.id, "cubecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações." }, 409);
          return reply(await cubeCloudRequest(token, "/projects/" + encodeURIComponent(cubeProjectId(bot.provider_app_id)) + "/files?path=" + encodeURIComponent(filePath), "DELETE"));
        } catch (error) {
          return reply({ error: error.message || "Falha ao excluir arquivo da Cube Hosting." }, 502);
        }
      }
      if (action === "files" && subPath === "delete" && request.method === "POST" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        const b = await body(request);
        const filePath = safeVolumePath(b.path);
        if (filePath === "/") return reply({ error: "A pasta raiz não pode ser removida." }, 400);
        try {
          const token = await providerToken(user.id, "squarecloud", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte a Square Cloud nas Configurações." }, 409);
          return reply(await squareCloudRequest(token, "/apps/" + encodeURIComponent(squareAppId(bot.provider_app_id)) + "/files", "DELETE", { path: filePath }));
        } catch (error) {
          return reply({ error: error.message || "Falha ao excluir arquivo na Square Cloud." }, 502);
        }
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

      if (action === "auto-upload" && request.method === "POST") {
        try {
          const b = await body(request);
          const generatedStandard = b.generatedStandard === true &&
            bot.project_type !== "custom" && !bot.custom_project;
          if (!generatedStandard && bot.project_type !== "custom" && !bot.custom_project) {
            return reply({ code: "custom_project_required", error: "Este projeto precisa ser um bot padrão gerado pelo Estúdio ou um projeto próprio com ZIP." }, 409);
          }
          if (generatedStandard && !bot.discord_token_enc) {
            return reply({ code: "discord_token_missing", error: "Salve e valide primeiro o Bot Token do Discord." }, 409);
          }
          const archiveName = generatedStandard
            ? "black-zone-caos.zip"
            : String(b.filename || "meu-bot.zip").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 120);
          if (!/\.zip$/i.test(archiveName)) return reply({ error: "Envie um arquivo ZIP válido." }, 400);
          const isAclCloudsTarget = String(bot.hosting_provider || "").toLowerCase() === "aclclouds" && !!bot.provider_app_id;
          const isPterodactylTarget = ["cogithost","sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(String(bot.hosting_provider || "").toLowerCase()) && !!bot.provider_app_id;
          const sillydevConnection = await env.DB.prepare("SELECT id FROM provider_connections WHERE user_id IN (?,?) AND provider='sillydev' LIMIT 1").bind(user.id, SHARED_HOSTING_OWNER_ID).first();
          const maxArchiveBytes = (isAclCloudsTarget || isPterodactylTarget || !!sillydevConnection) ? 25 * 1024 * 1024 : 5 * 1024 * 1024;
          let archiveBytes;
          if (generatedStandard) {
            if (!CAOS_MAIN_PY || CAOS_MAIN_PY.length < 10000 || !CAOS_REQUIREMENTS) {
              return reply({ code: "standard_template_missing", error: "O modelo padrão do bot não está disponível nesta publicação. Atualize o Estúdio e tente novamente." }, 503);
            }
            const template = new JSZip();
            template.file("main.py", CAOS_MAIN_PY);
            template.file("requirements.txt", CAOS_REQUIREMENTS);
            template.file(".env", [
              "CAOS_MODULES={}",
              "CAOS_SCHEDULE_ENABLED=0",
              "CAOS_SCHEDULE_START=00:00",
              "CAOS_SCHEDULE_END=23:59",
              "TZ=America/Bahia",
              "APP_URL=https://black-zone-estudio.vercel.app",
              "BOT_NAME=" + String(bot.name || "Meu bot").replace(/[\\r\\n]/g, " ").slice(0, 80)
            ].join("\\n") + "\\n");
            archiveBytes = await template.generateAsync({
              type: "uint8array",
              compression: "DEFLATE",
              compressionOptions: { level: 6 }
            });
          } else {
          const uploadId = String(b.uploadId || "");
          if (uploadId) {
            if (!/^[A-Za-z0-9_-]{16,80}$/.test(uploadId)) return reply({ error: "Identificador de envio inválido." }, 400);
            const chunks = await env.DB.prepare(
              "SELECT chunk_index,total_chunks,chunk_base64 FROM bot_upload_chunks WHERE user_id=? AND bot_id=? AND upload_id=? ORDER BY chunk_index ASC"
            ).bind(user.id, id, uploadId).all();
            const rows = Array.isArray(chunks) ? chunks : (Array.isArray(chunks?.results) ? chunks.results : []);
            if (!rows.length) return reply({ code: "upload_chunks_missing", error: "Não encontrei as partes deste ZIP. Selecione o arquivo e tente novamente." }, 409);
            const totalChunks = Number(rows[0].total_chunks || 0);
            if (!Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > 100 || rows.length !== totalChunks) {
              return reply({ code: "upload_chunks_incomplete", error: "O envio do ZIP ficou incompleto (" + rows.length + "/" + totalChunks + " partes). Tente novamente." }, 409);
            }
            const decoded = [];
            let totalBytes = 0;
            for (let i = 0; i < rows.length; i++) {
              if (Number(rows[i].chunk_index) !== i || Number(rows[i].total_chunks) !== totalChunks) {
                return reply({ code: "upload_chunks_incomplete", error: "As partes do ZIP chegaram fora de ordem. Tente novamente." }, 409);
              }
              const part = decodeBase64Bytes(rows[i].chunk_base64);
              totalBytes += part.byteLength;
              if (totalBytes > maxArchiveBytes) return reply({ code: "fallback_zip_too_large", error: "O ZIP limpo ultrapassa o limite gratuito desta hospedagem. O arquivo original continua intacto." }, 413);
              decoded.push(part);
            }
            archiveBytes = new Uint8Array(totalBytes);
            let offset = 0;
            for (const part of decoded) { archiveBytes.set(part, offset); offset += part.byteLength; }
            await env.DB.prepare("DELETE FROM bot_upload_chunks WHERE user_id=? AND bot_id=? AND upload_id=?")
              .bind(user.id, id, uploadId).run();
          } else {
            archiveBytes = decodeBase64Bytes(b.archiveBase64);
          }
          }
          if (archiveBytes.byteLength > maxArchiveBytes) {
            return reply({
              code: "fallback_zip_too_large",
              error: "O ZIP limpo passa do limite de " + Math.round(maxArchiveBytes / (1024 * 1024)) + " MB desta rota gratuita. O arquivo original continua intacto."
            }, 413);
          }

          const currentProvider = String(bot.hosting_provider || "bot-hosting");
          const currentAppId = bot.provider_app_id ? String(bot.provider_app_id) : "";
          const squareToken = await providerToken(user.id, "squarecloud", env);
          // Para a frota compartilhada, tente primeiro as credenciais privadas
          // do Estúdio quando o membro ainda não conectou uma conta própria.
          const discloudToken = await providerTokenForPool(user.id, "discloud", env);
          const cubeToken = await providerTokenForPool(user.id, "cubecloud", env);
          const sillydevToken = await providerTokenForPool(user.id, "sillydev", env);

          // Preserve projetos existentes no provedor atual. Para novos projetos,
          // use somente provedores gratuitos autorizados e com vaga real.
          if (["cogithost","sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(currentProvider) && currentAppId) {
            const providerConfigs = {
              sillydev: { name: "Silly Development", request: sillydevRequest },
              cogithost: { name: "Cogithost", request: cogitRequest },
              keritcloud: { name: "Kerit Cloud", request: keritRequest },
              waifly: { name: "Waifly", request: waiflyRequest },
              xsystems: { name: "X Systems Hosting", request: xsystemsRequest },
              torchlite: { name: "Torchlite", request: torchliteRequest },
              daki: { name: "Daki Hosting", request: dakiRequest },
              unixsys: { name: "Unixsys", request: unixsysRequest },
              consolex1: { name: "ConsoleX1", request: consolex1Request }
            };
            const providerConfig = providerConfigs[currentProvider];
            const cogit = currentProvider === "cogithost" ? await cogitConfig(user.id, env) : null;
            const token = currentProvider === "cogithost" ? (cogit?.token || null) : await providerTokenForPool(user.id, currentProvider, env);
            if (!token) return reply({ code: "provider_not_connected", error: "Reconecte " + providerConfig.name + " nas Configurações." }, 409);
            try {
              if (currentProvider === "sillydev") {
                const serverResult = await sillydevRequest(token, "/servers/" + encodeURIComponent(keritIdentifier(currentAppId)));
                const serverState = serverResult.data?.attributes || {};
                if (serverState.status === "install_failed" || serverState.status === "reinstall_failed") {
                  return reply({ code: "sillydev_install_failed", error: "A instalação inicial do servidor Silly Development falhou. O servidor continua vinculado; abra o painel Silly Development, reinstale o runtime e depois envie o ZIP novamente." }, 409);
                }
                if (serverState.status === "installing" || serverState.status === "restoring_backup" || serverState.is_transferring || serverState.is_installing) {
                  return reply({ code: "sillydev_server_installing", error: "O servidor Silly Development ainda está instalando ou sendo movido. Aguarde terminar e envie o mesmo ZIP novamente; o Estúdio manterá a mesma vaga." }, 409);
                }
              }
              const deployed = currentProvider === "keritcloud"
                ? await keritDeployZip(token, currentAppId, archiveBytes, archiveName, bot, b.runtime, user.id, env)
                : await pterodactylDeployZip(token, currentAppId, archiveBytes, archiveName, bot, b.runtime, user.id, env, currentProvider, providerConfig.name, providerConfig.request);
              return reply(deployed);
            } catch (error) {
              return reply({ code: "pterodactyl_upload_failed", error: error.message || "Falha ao publicar o bot em " + providerConfig.name + ". Os arquivos anteriores foram preservados." }, 502);
            }
          }
          if (currentProvider === "aclclouds" && currentAppId) {
            const aclToken = await providerToken(user.id, "aclclouds", env);
            if (!aclToken) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações para atualizar este bot." }, 409);
            const prepared = await prepareDiscloudProject(archiveBytes, bot, b.runtime, env);
            const serverId = aclCloudsIdentifier(currentAppId);
            let archiveToUpload = prepared.bytes;
            const tokenConfigured = await aclCloudsSetDiscordToken(aclToken, serverId, bot, env);
            if (tokenConfigured) {
              try {
                const projectZip = await JSZip.loadAsync(archiveToUpload, { checkCRC32: false });
                const envFile = projectZip.file(".env");
                if (envFile) {
                  const envText = await envFile.async("string");
                  const safeEnv = envText.split(/\r?\n/).filter(line =>
                    !/^\s*(?:DISCORD_TOKEN|BOT_TOKEN|TOKEN)\s*=/.test(line)
                  ).join("\n") + "\n";
                  projectZip.file(".env", safeEnv);
                  archiveToUpload = await projectZip.generateAsync({
                    type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 }
                  });
                }
              } catch {}
            }
            if (archiveToUpload.byteLength > maxArchiveBytes) {
              throw new Error("O ZIP preparado ultrapassa o limite gratuito desta hospedagem. O arquivo original continua intacto.");
            }
            const uploadResponse = await aclCloudsRequest(aclToken, "/servers/" + encodeURIComponent(serverId) + "/files/upload");
            const uploadInfo = aclCloudsAttributes(uploadResponse.data);
            const uploadUrl = String(uploadInfo.url || uploadResponse.data?.url || "");
            if (!/^https:\/\//i.test(uploadUrl)) throw new Error("A ACLClouds não retornou uma URL segura para enviar o ZIP.");
            const target = new URL(uploadUrl);
            target.searchParams.set("directory", "/");
            const form = new FormData();
            const archiveFile = archiveName.replace(/\.zip$/i, "-black-zone.zip");
            form.append("files", new Blob([archiveToUpload], { type: "application/zip" }), archiveFile);
            const uploaded = await fetch(target.href, { method: "POST", body: form, signal: AbortSignal.timeout(60000) });
            if (!uploaded.ok) throw new Error("O envio do ZIP à ACLClouds falhou: HTTP " + uploaded.status);
            const deployResult = await aclCloudsRequest(aclToken, "/servers/" + encodeURIComponent(serverId) + "/files/deploy", "POST", {
              directory: "/", clean: false, keep: [], archive: archiveFile
            });
            const currentResource = aclCloudsAttributes((await aclCloudsRequest(aclToken, "/servers/" + encodeURIComponent(serverId) + "/resources")).data);
            const signal = String(currentResource.current_state || "").toLowerCase() === "running" ? "restart" : "start";
            await aclCloudsRequest(aclToken, "/servers/" + encodeURIComponent(serverId) + "/power", "POST", { signal });
            await env.DB.prepare("UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='aclclouds',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?")
              .bind(serverId, prepared.runtime, JSON.stringify(prepared.customProject), Date.now(), id, user.id).run();
            return reply({ ok: true, provider: "aclclouds", providerAppId: serverId, runtime: prepared.runtime,
              customProject: prepared.customProject, deployment: deployResult.data || null, tokenConfigured,
              message: "ZIP enviado, implantado e comando de início/reinício enviado à ACLClouds. " +
                (tokenConfigured
                  ? "O token Discord foi gravado na variável privada de inicialização."
                  : "O token foi mantido no arquivo .env privado do projeto; confirme no painel o arquivo/comando de inicialização se o servidor não iniciar sozinho.") });
          }

          if (currentProvider === "cubecloud" && currentAppId) {
            if (!cubeToken) return reply({ code: "provider_not_connected", error: "Reconecte a Cube Hosting nas Configurações para atualizar este bot." }, 409);
            const prepared = await prepareCubeCloudProject(archiveBytes, bot, b.runtime, env);
            const form = new FormData();
            form.append("file", new Blob([prepared.bytes], { type: "application/zip" }), archiveName.replace(/\.zip$/i, "-black-zone.zip"));
            await cubeCloudRequest(cubeToken, "/projects/" + encodeURIComponent(cubeProjectId(currentAppId)) + "/code", "POST", null, form);
            const existingVars = await cubeCloudRequest(cubeToken, "/projects/" + encodeURIComponent(cubeProjectId(currentAppId)) + "/variables");
            const existingNames = (Array.isArray(existingVars.variables) ? existingVars.variables : []).map(item => String(item.name || "")).filter(Boolean);
            const variables = existingNames.map(name => Object.prototype.hasOwnProperty.call(prepared.envs, name) ? { name, value: prepared.envs[name] } : { name });
            for (const [name, value] of Object.entries(prepared.envs)) if (!existingNames.includes(name)) variables.push({ name, value });
            if (variables.length) await cubeCloudRequest(cubeToken, "/projects/" + encodeURIComponent(cubeProjectId(currentAppId)) + "/variables", "PUT", { variables });
            await env.DB.prepare(
              "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='cubecloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='installing',updated_at=? WHERE id=? AND user_id=?"
            ).bind(currentAppId, prepared.runtime, JSON.stringify(prepared.customProject), Date.now(), id, user.id).run();
            return reply({
              ok: true, provider: "cubecloud", providerAppId: currentAppId,
              runtime: prepared.runtime, customProject: prepared.customProject,
              message: "Código enviado à Cube Hosting; a instalação foi solicitada e as variáveis salvas foram preservadas."
            });
          }

          if (currentProvider === "squarecloud" && currentAppId) {
            if (!squareToken) return reply({ code: "provider_not_connected", error: "Reconecte a conta Square Cloud nas Configurações para atualizar este bot." }, 409);
            const prepared = await prepareSquareCloudProject(archiveBytes, bot, b.runtime, env);
            const form = new FormData();
            form.append("file", new Blob([prepared.bytes], { type: "application/zip" }), archiveName.replace(/\.zip$/i, "-black-zone.zip"));
            await squareCloudRequest(squareToken, "/apps/" + encodeURIComponent(squareAppId(currentAppId)) + "/commit", "POST", null, form);
            if (Object.keys(prepared.envs).length) {
              await squareCloudRequest(squareToken, "/apps/" + encodeURIComponent(squareAppId(currentAppId)) + "/envs", "POST", { envs: prepared.envs });
            }
            await env.DB.prepare(
              "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='squarecloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?"
            ).bind(currentAppId, prepared.runtime, JSON.stringify(prepared.customProject), Date.now(), id, user.id).run();
            await squareCloudRequest(squareToken, "/apps/" + encodeURIComponent(squareAppId(currentAppId)) + "/restart", "POST");
            return reply({
              ok: true, provider: "squarecloud", providerAppId: currentAppId,
              runtime: prepared.runtime, customProject: prepared.customProject,
              message: "Arquivos atualizados na Square Cloud, variáveis seguras aplicadas e reinicialização solicitada."
            });
          }

          if (currentProvider === "discloud" && currentAppId) {
            if (!discloudToken) return reply({ code: "provider_not_connected", error: "Reconecte a Discloud nas Configurações para atualizar este bot." }, 409);
            const prepared = await prepareDiscloudProject(archiveBytes, bot, b.runtime, env);
            const form = new FormData();
            form.append("file", new Blob([prepared.bytes], { type: "application/zip" }), archiveName.replace(/\.zip$/i, "-black-zone.zip"));
            const uploaded = await discloudRequest(discloudToken, "/app/" + encodeURIComponent(currentAppId) + "/commit", "PUT", form);
            await env.DB.prepare(
              "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='discloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?"
            ).bind(currentAppId, prepared.runtime, JSON.stringify(prepared.customProject), Date.now(), id, user.id).run();
            try { await discloudRequest(discloudToken, "/app/" + encodeURIComponent(currentAppId) + "/restart", "PUT"); }
            catch (error) {
              if (!/already|online|running|process|in process|409/i.test(String(error?.message || ""))) throw error;
            }
            return reply({
              ok: true, provider: "discloud", providerAppId: currentAppId,
              runtime: prepared.runtime, customProject: prepared.customProject,
              app: uploaded.app || null,
              message: "Arquivos atualizados na Discloud e reinicialização solicitada."
            });
          }

          let cubeCapacityMessage = cubeToken
            ? ""
            : "Cube Hosting não conectada nesta conta.";
          if (cubeToken) {
            try {
              const usage = await cubeCloudRequest(cubeToken, "/account/usage");
              const plan = usage.plan || {};
              const planId = String(plan.id || "").trim().toLowerCase();
              const planName = String(plan.name || "").trim().toLowerCase();
              const projects = usage.projects || {};
              const maxBots = Number(plan.maxBots || 0);
              const minMemory = Number(plan.minMemoryMb?.bot || (planId === "free" ? 100 : 256));
              const freeMb = Number(usage.memory?.freeMb || 0);
              const isFree = planId === "free" || planName === "free";
              const canCreate = isFree && (maxBots <= 0 || Number(projects.total || 0) < maxBots) && freeMb >= minMemory;
              if (canCreate) {
                const prepared = await prepareCubeCloudProject(archiveBytes, bot, b.runtime, env);
                const zipLimitMb = Number(plan.zipMaxMb || 5);
                if (zipLimitMb > 0 && prepared.bytes.byteLength > zipLimitMb * 1024 * 1024) {
                  const sizeMb = (prepared.bytes.byteLength / 1024 / 1024).toFixed(2).replace(".", ",");
                  const error = new Error("Depois da limpeza automática, o ZIP ficou com " + sizeMb + " MB, acima do limite de " + zipLimitMb + " MB do plano Cube Free. Remova arquivos pesados, vídeos, backups ou bibliotecas incluídas no ZIP e tente novamente.");
                  error.code = "cube_zip_limit_reached";
                  throw error;
                }
                const form = new FormData();
                const uploadName = archiveName.replace(/\.zip$/i, "-black-zone.zip");
                form.append("file", new Blob([prepared.bytes], { type: "application/zip" }), uploadName);
                form.append("start", "true");
                form.append("variables", JSON.stringify(Object.entries(prepared.envs).map(([name, value]) => ({ name, value }))));
                const created = await cubeCloudRequest(cubeToken, "/projects", "POST", null, form);
                const projectId = String(created.project?.id || "");
                if (!projectId) throw new Error("A Cube Hosting recebeu o ZIP, mas não retornou o ID do projeto.");
                await env.DB.prepare(
                  "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='cubecloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state=?,updated_at=? WHERE id=? AND user_id=?"
                ).bind(projectId, prepared.runtime, JSON.stringify(prepared.customProject), String(created.project?.status || "installing"), Date.now(), id, user.id).run();
                return reply({
                  ok: true, provider: "cubecloud", providerAppId: projectId,
                  runtime: prepared.runtime, customProject: prepared.customProject,
                  project: created.project || null,
                  message: "Projeto criado na Cube Hosting. A instalação e a inicialização foram solicitadas."
                });
              }
              cubeCapacityMessage = !isFree
                ? "Cube Hosting ignorada: esta conta não está no plano Free; o Estúdio não iniciará cobrança."
                : "Cube Hosting: " + Number(projects.total || 0) + "/" + (maxBots || "sem limite informado") + " projetos e " + freeMb + " MB livres; sem capacidade para outro bot agora.";
            } catch (error) {
              const capacityCodes = new Set(["project_limit_reached","insufficient_memory","free_slot_required","free_slot_lost","plan_limit_reached"]);
              if (String(error?.code || "") === "cube_zip_limit_reached") {
                cubeCapacityMessage = error.message;
              } else if (capacityCodes.has(String(error?.code || "")) || /free_slot_required|project_limit_reached|insufficient_memory|plan_limit_reached/i.test(String(error?.message || ""))) {
                cubeCapacityMessage = error.message || "Cube Hosting não tem uma vaga disponível. No plano Free, resgate a vaga com /free no Discord da Cube.";
              } else {
                cubeCapacityMessage = "Cube Hosting não confirmou a vaga: " + String(error?.message || "falha na consulta.");
              }
            }
          }

          let sillydevCapacityMessage = sillydevToken
            ? ""
            : "Silly Development não conectada nesta conta.";
          if (sillydevToken) {
            let createdServerId = "";
            try {
              const allowanceResult = await sillydevRequest(sillydevToken, "/server-creation");
              const allowance = allowanceResult.data?.attributes || {};
              const limit = Number(allowance.limit || 2);
              const owned = Number(allowance.servers_owned || 0);
              if (!allowance.can_create) {
                sillydevCapacityMessage = "Silly Development: " + owned + "/" + limit + " servidores Free usados; não há outra vaga gratuita disponível nesta conta.";
              } else {
                const preparedForSilly = await prepareDiscloudProject(archiveBytes, bot, b.runtime, env);
                if (preparedForSilly.bytes.byteLength > 25 * 1024 * 1024) {
                  throw new Error("O ZIP preparado ultrapassa 25 MB, limite de segurança para essa hospedagem.");
                }
                const serverName = String(bot.name || "Discord Bot").replace(/[^A-Za-z0-9 _.-]/g, "").trim().slice(0, 48) || "Discord Bot";
                const runtimeKey = preparedForSilly.runtime === "nodejs" ? "nodejs" : (preparedForSilly.runtime === "bun" ? "bun" : "python");
                const created = await sillydevRequest(sillydevToken, "/server-creation", "POST", {
                  name: serverName,
                  description: "Bot gerenciado pelo Black Zone Estúdio",
                  runtime: runtimeKey
                });
                const server = created.data?.attributes || {};
                createdServerId = String(server.identifier || "");
                if (!createdServerId) throw new Error("A API criou a solicitação, mas não retornou o identificador do servidor. Atualize a conexão e confira o painel Silly Development antes de tentar criar outro.");
                const pendingProject = {
                  ...preparedForSilly.customProject,
                  runtime: preparedForSilly.runtime,
                  provider: "sillydev",
                  providerName: "Silly Development",
                  serverCreationPending: true,
                  createdAt: Date.now()
                };
                await env.DB.prepare(
                  "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='sillydev',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='installing',updated_at=? WHERE id=? AND user_id=?"
                ).bind(createdServerId, preparedForSilly.runtime, JSON.stringify(pendingProject), Date.now(), id, user.id).run();

                let latest = server;
                let ready = latest.status !== "installing" && !latest.is_installing && !latest.is_transferring;
                for (let attempt = 0; !ready && attempt < 15; attempt++) {
                  await new Promise(resolve => setTimeout(resolve, 2000));
                  const statusResult = await sillydevRequest(sillydevToken, "/servers/" + encodeURIComponent(createdServerId));
                  latest = statusResult.data?.attributes || {};
                  if (latest.status === "install_failed") {
                    throw new Error("A Silly Development informou falha na instalação inicial do servidor. O servidor continua vinculado ao projeto; verifique o painel e tente reinstalar antes de reenviar o ZIP.");
                  }
                  ready = latest.status !== "installing" && !latest.is_installing && !latest.is_transferring;
                }
                if (!ready) {
                  return reply({
                    ok: false,
                    code: "sillydev_server_installing",
                    provider: "sillydev",
                    providerAppId: createdServerId,
                    error: "O servidor gratuito foi criado e vinculado ao projeto, mas a instalação ainda não terminou. Aguarde um pouco e envie o mesmo ZIP novamente. Não crie outro servidor: esta vaga já está reservada para este bot."
                  }, 409);
                }
                const deployed = await pterodactylDeployZip(
                  sillydevToken, createdServerId, archiveBytes, archiveName, bot,
                  preparedForSilly.runtime, user.id, env, "sillydev", "Silly Development", sillydevRequest
                );
                return reply({
                  ...deployed,
                  message: "Servidor gratuito criado pelo Estúdio e bot enviado à Silly Development. " + String(deployed.message || "")
                });
              }
            } catch (error) {
              const message = String(error?.message || "Falha ao consultar ou criar um servidor Silly Development.");
              if (createdServerId) {
                return reply({
                  ok: false,
                  code: "sillydev_created_upload_failed",
                  provider: "sillydev",
                  providerAppId: createdServerId,
                  error: "O servidor gratuito já foi criado e vinculado ao projeto, mas o envio não terminou: " + message + " Reenvie o ZIP para continuar no mesmo servidor, sem consumir outra vaga."
                }, 502);
              }
              if (Number(error?.status || 0) === 409 || Number(error?.status || 0) === 503 || /no capacity|no node has room|free server limit|already have a server/i.test(message)) {
                sillydevCapacityMessage = "Silly Development sem vaga no momento: " + message;
              } else if (Number(error?.status || 0) === 403) {
                sillydevCapacityMessage = "Silly Development: a chave não tem todas as permissões necessárias. Gere outra com servers.create, leitura/edição de arquivos, startup e controle de energia.";
              } else {
                sillydevCapacityMessage = "Silly Development não confirmou uma vaga: " + message;
              }
            }
          }

          let discloudCapacityMessage = discloudToken
            ? ""
            : "Discloud não conectada nesta conta.";
          if (discloudToken) {
            try {
              const account = (await discloudRequest(discloudToken, "/user"))?.user || null;
              if (!account) throw new Error("A Discloud não retornou os dados da conta.");
              const planName = String(account.plan || "");
              const apps = Array.isArray(account.apps) ? account.apps.map(value => String(value || "")).filter(Boolean) : null;
              const freeRam = Number(account.totalRamMb || 0) - Number(account.ramUsedMb || 0);
              if (!/\bfree\b/i.test(planName)) {
                discloudCapacityMessage = "Discloud ignorada: esta conta não está no plano Free; o Estúdio não iniciará cobrança.";
              } else if (!apps) {
                discloudCapacityMessage = "A Discloud não informou a lista de aplicativos; não vou arriscar criar um bot duplicado.";
              } else if (apps.length > 0) {
                discloudCapacityMessage = "Discloud: a vaga Free desta conta já está ocupada (" + apps.length + " aplicativo(s)).";
              } else if (freeRam < 100) {
                discloudCapacityMessage = "Discloud: a conta não confirmou 100 MB livres para outro bot.";
              } else {
                const prepared = await prepareDiscloudProject(archiveBytes, bot, b.runtime, env);
                if (prepared.bytes.byteLength > 5 * 1024 * 1024) {
                  throw new Error("O ZIP preparado ultrapassa 5 MB, limite de envio do Estúdio para esta hospedagem. O arquivo original continua preservado.");
                }
                const expectedName = discloudExpectedProjectName(bot);
                const expectedMainFile = discloudLauncherForRuntime(prepared.runtime);
                const uploadName = archiveName.replace(/\.zip$/i, "-black-zone.zip");
                const pendingProject = {
                  ...prepared.customProject,
                  runtime: prepared.runtime,
                  discloudUploadPending: {
                    baselineAppIds: apps,
                    expectedName,
                    expectedMainFile,
                    startedAt: Date.now()
                  }
                };
                await env.DB.prepare(
                  "UPDATE bots SET hosting_provider='bot-hosting',custom_project=?::jsonb,state='installing',updated_at=? WHERE id=? AND user_id=?"
                ).bind(JSON.stringify(pendingProject), Date.now(), id, user.id).run();

                const form = new FormData();
                form.append(uploadName, new Blob([prepared.bytes], { type: "application/zip" }), uploadName);
                const uploaded = await discloudRequest(discloudToken, "/upload", "POST", form);
                const app = uploaded.app || uploaded.apps || null;
                const appId = String(app?.id || "");
                if (!appId) {
                  throw new Error("A Discloud recebeu a solicitação, mas não retornou o ID do aplicativo. O Estúdio guardou a tentativa e verificará antes de repetir o envio.");
                }
                const customProject = {
                  ...prepared.customProject,
                  runtime: prepared.runtime,
                  provider: "discloud",
                  providerName: "Discloud",
                  deployedAt: Date.now()
                };
                await env.DB.prepare(
                  "UPDATE bots SET hosting_deployment_id=NULL,hosting_provider='discloud',provider_app_id=?,runtime=?,project_type='custom',custom_project=?::jsonb,state='starting',updated_at=? WHERE id=? AND user_id=?"
                ).bind(appId, prepared.runtime, JSON.stringify(customProject), Date.now(), id, user.id).run();
                let startNote = "O upload foi concluído; a inicialização foi solicitada.";
                try {
                  await discloudRequest(discloudToken, "/app/" + encodeURIComponent(appId) + "/start", "PUT");
                } catch (startError) {
                  if (!/already|online|running|process|in process|409/i.test(String(startError?.message || ""))) {
                    startNote = "O upload foi concluído, mas a Discloud não confirmou o início: " + String(startError?.message || "falha ao iniciar");
                  }
                }
                return reply({
                  ok: true, provider: "discloud", providerAppId: appId,
                  runtime: prepared.runtime, customProject, app,
                  message: "Bot criado na Discloud Free (100 MB). " + startNote
                });
              }
            } catch (error) {
              const message = String(error?.message || "Falha ao criar aplicação na Discloud.");
              if (/HTTP 402|capacity|limit|ram|quota|application.*limit|maximum|free.*slot/i.test(message)) {
                discloudCapacityMessage = "Discloud: " + message;
              } else {
                return reply({
                  ok: false,
                  code: "discloud_upload_failed",
                  error: message + " A tentativa foi registrada para evitar duplicidade se o provedor tiver recebido o ZIP."
                }, 502);
              }
            }
          }

          // Square Cloud exige assinatura e fica fora da seleção automática de novos bots.
          const providerIssues = [cubeCapacityMessage, sillydevCapacityMessage, discloudCapacityMessage].filter(Boolean);
          const anyFreeProviderConnected = !!cubeToken || !!sillydevToken || !!discloudToken;
          return reply({
            code: anyFreeProviderConnected ? "provider_capacity_full" : "provider_not_connected",
            error: anyFreeProviderConnected
              ? providerIssues.join(" ") + " Nenhum bot existente foi substituído. Conecte outro provedor gratuito ou libere uma vaga na conta."
              : "Conecte pelo menos um provedor gratuito: Cube Hosting, Silly Development ou Discloud. Depois de validar a API Key uma vez, o Estúdio tentará a primeira vaga livre automaticamente. Nenhum plano pago será iniciado."
          }, anyFreeProviderConnected ? 402 : 409);
        } catch (error) {
          const message = error?.message || "Falha ao enviar o ZIP para a hospedagem alternativa.";
          const code = String(error?.code || "");
          const capacity = [
            "APPLICATIONS_LIMIT_REACHED","INSUFFICIENT_MEMORY","CLUSTER_SELECTION_FAILED",
            "CLUSTER_MAINTENANCE_TRY_LATER","CLUSTER_UNAVAILABLE","LOAD_BALANCER_LIMIT_REACHED"
          ].includes(code) || /capacity|limit|maximum|plan|app limit|ram|quota|slots|applications/i.test(message);
          return reply({
            code: capacity ? "provider_capacity_full" : "provider_upload_failed",
            error: capacity
              ? "Os provedores conectados estão sem memória ou vagas para este bot. Nenhuma implantação existente foi substituída. Verifique os limites ou conecte outro provedor compatível."
              : message
          }, capacity ? 402 : 502);
        }
      }

      if (action === "upload-url" && request.method === "POST" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const b = await body(request), directory = safeVolumePath(b.path || "/");
          const signed = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/files/upload");
          const upload = aclCloudsAttributes(signed.data);
          const uploadUrl = String(upload.url || signed.data?.url || "");
          if (!uploadUrl.startsWith("https://")) return reply({ error: "ACLClouds não retornou URL de upload válida." }, 502);
          const target = new URL(uploadUrl);
          target.searchParams.set("directory", directory);
          return reply({ url: target.href, field: "files", path: directory, provider: "aclclouds" });
        } catch (error) { return reply({ error: error.message || "Falha ao preparar upload ACLClouds." }, 502); }
      }
      if (action === "upload-url" && request.method === "POST" && ["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
        try {
          const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
          const requestFn = providerRequestForId(providerId);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte sua hospedagem nas Configurações." }, 409);
          const b = await body(request), directory = safeVolumePath(b.path || "/");
          const result = await requestFn(token, "/servers/" + encodeURIComponent(keritIdentifier(bot.provider_app_id)) + "/files/upload");
          const url = String(result.data?.attributes?.url || result.data?.url || "");
          if (!url.startsWith("https://")) return reply({ error: "O provedor não retornou URL de upload válida." }, 502);
          const target = new URL(url);
          target.searchParams.set("directory", directory);
          return reply({ url: target.href, field: "files", path: directory, provider: providerId });
        } catch (error) { return reply({ error: error.message || "Falha ao preparar upload Pterodactyl." }, 502); }
      }
      if (action === "upload-url" && request.method === "POST" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const b = await body(request), directory = safeVolumePath(b.path || "/");
          const result = await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/upload?directory=" + encodeURIComponent(directory));
          const url = String(result.data?.attributes?.url || result.data?.url || "");
          if (!url.startsWith("https://")) return reply({ error: "O Cogithost não retornou URL de upload válida." }, 502);
          return reply({ url, field: "files", path: directory, provider: "cogithost" });
        } catch (error) { return reply({ error: error.message || "Falha ao preparar upload Cogithost." }, 502); }
      }
      if (action === "upload-url" && request.method === "POST") {
        if (bot.project_type !== "custom" && !bot.custom_project) return reply({ error: "Envio de código próprio só está disponível em projetos criados como \"Meu próprio bot\"." }, 409);
        try {
          const b = await body(request);
          const root = safeVolumePath(b.path || "/");
          const requestedRuntime = String(b.runtime || bot.runtime || "python").toLowerCase();
          if (!["python","nodejs"].includes(requestedRuntime)) return reply({ error: "Escolha Python ou Node.js para este pacote." }, 400);
          let deploymentId = bot.hosting_deployment_id || null;
          let waitForReady = false;
          if (!deploymentId) {
            const hosting = await env.DB.prepare("SELECT scope FROM hosting_connections WHERE user_id=?").bind(user.id).first();
            if (!hosting) return reply({ code: "hosting_not_connected", error: "Conecte o Bot-Hosting antes de enviar o pacote do bot." }, 409);
            const scopes = String(hosting.scope || "").split(/\s+/).filter(Boolean);
            if (!scopes.includes("deployments:write") || !scopes.includes("credits:spend") || !scopes.includes("files:write")) {
              return reply({ code: "hosting_scope_missing", error: "A autorização do Bot-Hosting precisa liberar criação e envio de arquivos. Reconecte a hospedagem nas Configurações." }, 403);
            }
            const safeName = ("black-zone-" + String(bot.name || "bot").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) + "-" + String(bot.id).slice(0, 5)).replace(/-+/g, "-");

            // Recover a deployment created by an earlier attempt for this exact bot.
            // This avoids consuming another plan slot when the first request succeeded
            // at the provider but the browser/session did not finish the import.
            let recovered = null;
            try {
              const existing = await hostRequest(user.id, env, "/deployments?name=" + encodeURIComponent(safeName) + "&brief=true");
              const matches = Array.isArray(existing.deployments) ? existing.deployments : [];
              recovered = matches.find(item =>
                item && item.name === safeName && item.owned !== false && item.id &&
                String(item.runtime || "").toLowerCase() === requestedRuntime
              ) || null;
            } catch {}

            if (recovered) {
              deploymentId = String(recovered.id);
            } else {
              let created;
              try {
                created = await hostRequest(user.id, env, "/deployments", "POST", {
                  name: safeName, source: "blank", runtime: requestedRuntime,
                  runtimeVersion: requestedRuntime === "nodejs" ? "22" : "3.11"
                });
              } catch (createError) {
                if (/HTTP 402\b/.test(String(createError?.message || ""))) {
                  return reply({
                    code: "hosting_capacity_full",
                    error: "O plano da sua conta Bot-Hosting está sem vagas livres. O bot central do ADM já tem uma implantação vinculada e o provedor recusou a criação de outro servidor. Seu ZIP não foi enviado nem alterado. Para manter os dois bots ativos, libere uma vaga adicional no Bot-Hosting ou altere o plano."
                  }, 402);
                }
                throw createError;
              }
              deploymentId = String((created.deployment || created).id || "");
            }
            if (!deploymentId) throw new Error("O Bot-Hosting não retornou o ID do servidor para receber arquivos.");
            await env.DB.prepare("UPDATE bots SET hosting_deployment_id=?,runtime=?,project_type='custom',state='draft',updated_at=? WHERE id=? AND user_id=?")
              .bind(deploymentId, requestedRuntime, Date.now(), id, user.id).run();
            waitForReady = true;
          } else if (requestedRuntime !== String(bot.runtime || "python").toLowerCase()) {
            // O provedor apaga o volume ao trocar o runtime. Troque primeiro e espere
            // a reinstalação terminar ANTES de emitir a URL de upload.
            await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/startup", "PATCH", {
              runtime: requestedRuntime, runtimeVersion: requestedRuntime === "nodejs" ? "22" : "3.11",
              entryFile: requestedRuntime === "nodejs" ? "index.js" : "main.py",
              startCommand: null, wipeFiles: true
            });
            await env.DB.prepare("UPDATE bots SET runtime=?,custom_project=NULL,state='draft',updated_at=? WHERE id=? AND user_id=?")
              .bind(requestedRuntime, Date.now(), id, user.id).run();
            waitForReady = true;
          }
          if (deploymentId) await waitForHostReinstall(user.id, env, deploymentId);
          const signed = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(deploymentId) + "/files/upload-url", "POST", { path: root });
          return reply({ ...signed, deploymentId, path: root, runtime: requestedRuntime });
        } catch (error) {
          if (error?.code === "hosting_installing") {
            return reply({ code: "hosting_installing", error: error.message, retryAfterMs: Number(error.retryAfterMs || 1800) }, 202);
          }
          return reply({ error: error.message || "Falha ao preparar envio." }, 502);
        }
      }

      if (action === "extract" && request.method === "POST" && bot.hosting_provider === "aclclouds" && bot.provider_app_id) {
        const b = await body(request), file = String(b.file || "");
        if (!/^[A-Za-z0-9._-]{1,140}\.zip$/i.test(file) || file.includes("..")) return reply({ error: "Nome de ZIP inválido." }, 400);
        try {
          const token = await providerToken(user.id, "aclclouds", env);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte ACLClouds nas Configurações." }, 409);
          const result = await aclCloudsRequest(token, "/servers/" + encodeURIComponent(aclCloudsIdentifier(bot.provider_app_id)) + "/files/deploy", "POST", {
            directory: safeVolumePath(b.path || "/"), clean: false, keep: [], archive: file
          });
          return reply({ ...(result.data || {}), provider: "aclclouds" });
        } catch (error) { return reply({ error: error.message || "Falha ao extrair ZIP na ACLClouds." }, 502); }
      }
      if (action === "extract" && request.method === "POST" && ["sillydev","keritcloud","waifly","xsystems","torchlite","daki","unixsys","consolex1"].includes(bot.hosting_provider) && bot.provider_app_id) {
        const b = await body(request), file = String(b.file || "");
        if (!/^[A-Za-z0-9._-]{1,140}\\.zip$/i.test(file) || file.includes("..")) return reply({ error: "Nome de ZIP inválido." }, 400);
        try {
          const providerId = bot.hosting_provider, token = await providerTokenForPool(user.id, providerId, env);
          const requestFn = providerRequestForId(providerId);
          if (!token) return reply({ code: "provider_not_connected", error: "Reconecte sua hospedagem nas Configurações." }, 409);
          const result = await requestFn(token, "/servers/" + encodeURIComponent(keritIdentifier(bot.provider_app_id)) + "/files/decompress", "POST", { root: safeVolumePath(b.path || "/"), file });
          return reply({ provider: providerId, status: result.status });
        } catch (error) { return reply({ error: error.message || "Falha ao extrair ZIP Pterodactyl." }, 502); }
      }
      if (action === "extract" && request.method === "POST" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        const b = await body(request), file = String(b.file || "");
        if (!/^[A-Za-z0-9._-]{1,140}\.zip$/i.test(file) || file.includes("..")) return reply({ error: "Nome de ZIP inválido." }, 400);
        try {
          const config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          return reply((await cogitRequest(config.token, "/servers/" + encodeURIComponent(cogitIdentifier(bot.provider_app_id)) + "/files/decompress", "POST", { root: safeVolumePath(b.path || "/"), file })).data);
        } catch (error) { return reply({ error: error.message || "Falha ao extrair ZIP Cogithost." }, 502); }
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

      if (action === "import" && request.method === "POST" && bot.hosting_provider === "cogithost" && bot.provider_app_id) {
        try {
          const b = await body(request), config = await cogitConfig(user.id, env);
          if (!config) return reply({ code: "provider_not_connected", error: "Reconecte o Cogithost nas Configurações." }, 409);
          const serverId = cogitIdentifier(bot.provider_app_id), queue = ["/"], seen = new Set(), files = [];
          let directories = 0;
          while (queue.length && files.length < 12000) {
            const directory = queue.shift();
            if (seen.has(directory)) continue; seen.add(directory);
            const listing = await cogitRequest(config.token, "/servers/" + encodeURIComponent(serverId) + "/files/list?directory=" + encodeURIComponent(directory));
            for (const item of (Array.isArray(listing.data?.data) ? listing.data.data : [])) {
              const a = item?.attributes || {}, name = String(a.name || "");
              if (!name || name === "." || name === ".." || name === ".DS_Store" || name.startsWith("._")) continue;
              const full = safeVolumePath((directory === "/" ? "" : directory) + "/" + name);
              const parts = full.toLowerCase().split("/");
              if (!a.is_file) {
                if (parts.some(x => ["node_modules",".git","venv",".venv","__pycache__"].includes(x))) continue;
                directories++; if (parts.length < 12) queue.push(full);
              } else if (!parts.some(x => ["node_modules",".git","venv",".venv","__pycache__"].includes(x))) files.push(full);
            }
          }
          if (queue.length) throw new Error("O projeto tem pastas demais para análise automática.");
          const names = files.map(file => file.slice(1));
          const hasNode = names.some(file => /(^|\/)package\.json$/i.test(file)) || names.some(file => /\.(?:js|mjs|cjs)$/i.test(file));
          const runtime = hasNode ? "nodejs" : "python";
          const entryFile = hasNode
            ? names.find(file => /^(?:index|main|bot|app)\.(?:js|mjs|cjs)$/i.test(file)) || names.find(file => /\.(?:js|mjs|cjs)$/i.test(file)) || ""
            : names.find(file => /^(?:main|bot|runner|app|index)\.py$/i.test(file)) || names.find(file => /\.py$/i.test(file)) || "";
          if (!entryFile) throw new Error("Não encontrei o arquivo principal Node.js ou Python.");
          const customProject = { packageName: String(b.packageName || bot.name || "Meu bot").slice(0,64), rootPath:"/", runtime, entryFile, startCommand:null, dependencyFile:names.find(file=>/^(?:package\.json|requirements\.txt|pyproject\.toml)$/i.test(file))||null, fileCount:files.length, directoryCount:directories, provider:"cogithost", importedAt:Date.now() };
          await env.DB.prepare("UPDATE bots SET runtime=?,project_type='custom',custom_project=?::jsonb,state='stopped',updated_at=? WHERE id=? AND user_id=?")
            .bind(runtime, JSON.stringify(customProject), Date.now(), id, user.id).run();
          return reply({ ok:true, imported:true, customProject, message:"Arquivos analisados. O comando de inicialização e as variáveis continuam configurados no painel Cogithost." });
        } catch (error) { return reply({ error:error.message || "Falha ao analisar os arquivos Cogithost." },502); }
      }
      if (action === "import" && request.method === "POST") {
        if (bot.project_type !== "custom" && !bot.custom_project) return reply({ error: "Este é um projeto do bot padrão do Estúdio. Para importar seu próprio código, crie um projeto na opção \"Meu próprio bot\"." }, 409);
        if (!bot.hosting_deployment_id) return reply({ code: "not_deployed", error: "Envie o pacote para preparar a hospedagem primeiro." }, 409);
        try {
          const importBody = await body(request);
          const packageName = String(importBody.packageName || bot.name || "meu-bot").trim().slice(0, 64) || String(bot.name || "meu-bot");
          const analysis = await scanImportedProject(user.id, env, bot.hosting_deployment_id);
          if (!analysis.ok) return reply(analysis, 422);
          if (analysis.runtime !== String(bot.runtime || "python").toLowerCase()) {
            // Python <-> Node.js usa o mesmo tipo de ambiente de execução no provedor.
            // A troca não deve apagar o pacote que acabou de ser enviado.
            await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/startup", "PATCH", {
              runtime: analysis.runtime,
              runtimeVersion: analysis.runtime === "nodejs" ? "22" : "3.11",
              entryFile: analysis.entryFile,
              startCommand: analysis.startCommand || null
            });
          }
          const customProject = {
            packageName, rootPath: "/", runtime: analysis.runtime, entryFile: analysis.entryFile,
            startCommand: analysis.startCommand || null, dependencyFile: analysis.dependencyFile || null,
            fileCount: analysis.fileCount, directoryCount: analysis.directoryCount,
            imageCount: analysis.imageCount, resourceCount: analysis.resourceCount || 0,
            commandFileCount: analysis.commandFileCount || 0,
            detectedFolders: analysis.detectedFolders || [], importedAt: Date.now()
          };
          try {
            const marker = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?path=%2Fcaos-version.txt");
            if (String(marker.content || "").trim()) {
              const main = await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/content?path=%2Fmain.py");
              if (String(main.content || "") === CAOS_MAIN_PY) await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/delete", "POST", { root: "/", files: ["/main.py"] });
              await hostRequest(user.id, env, "/deployments/" + encodeURIComponent(bot.hosting_deployment_id) + "/files/delete", "POST", { root: "/", files: ["/runner.py", "/caos-version.txt"] });
            }
          } catch {}
          await env.DB.prepare("UPDATE bots SET runtime=?,project_type='custom',custom_project=?::jsonb,state='stopped',updated_at=? WHERE id=? AND user_id=?")
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

      if (action === "shell" && request.method === "POST" && bot.hosting_provider === "squarecloud" && bot.provider_app_id) {
        return reply({ code: "shell_not_supported", error: "A Square Cloud não expõe terminal de comandos na API pública. O gerenciador de arquivos, logs e controles do processo estão disponíveis no Estúdio." }, 409);
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
        "CREATE TABLE IF NOT EXISTS admin_caos_settings (id TEXT PRIMARY KEY,owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,bot_token_enc TEXT,bot_id TEXT,bot_name TEXT,hosting_deployment_id TEXT,package_uploaded_at BIGINT,state TEXT NOT NULL DEFAULT 'draft',updated_at BIGINT NOT NULL DEFAULT 0)",
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
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS hosting_provider TEXT NOT NULL DEFAULT 'bot-hosting'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS provider_app_id TEXT");
      await db.raw(`CREATE TABLE IF NOT EXISTS provider_connections (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        encrypted_token TEXT NOT NULL,
        account_label TEXT,
        plan TEXT,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, provider)
      )`);
      await db.raw(`CREATE TABLE IF NOT EXISTS bot_upload_chunks (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
        upload_id TEXT NOT NULL,
        chunk_index INTEGER NOT NULL,
        total_chunks INTEGER NOT NULL,
        chunk_base64 TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, bot_id, upload_id, chunk_index)
      )`);
      await db.raw("CREATE INDEX IF NOT EXISTS idx_bot_upload_chunks_created ON bot_upload_chunks(created_at)");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_start TEXT NOT NULL DEFAULT '00:00'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_end TEXT NOT NULL DEFAULT '23:59'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS schedule_timezone TEXT NOT NULL DEFAULT 'America/Bahia'");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS guild_id TEXT");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS custom_project JSONB");
      await db.raw("ALTER TABLE bots ADD COLUMN IF NOT EXISTS project_type TEXT NOT NULL DEFAULT 'standard'");
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
