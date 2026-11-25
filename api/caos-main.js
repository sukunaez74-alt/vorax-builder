export const CAOS_MAIN_PY = String.raw`import os, json, asyncio, logging
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import discord
from discord import app_commands
from discord.ext import commands, tasks

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
MODULES = json.loads(os.getenv("CAOS_MODULES", "{}") or "{}")
STATUS = Path("caos-status.json")
DATA_FILE = Path("caos-data.json")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("black-zone-caos")
lock = asyncio.Lock()
data = {"attendance": {}, "goals": {}, "warnings": [], "applications": [], "events": []}

def stamp():
    return datetime.now(timezone.utc).isoformat()

def save_data():
    tmp = DATA_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(DATA_FILE)

def status(value, **extra):
    payload = {"status": value, "updatedAt": stamp(), "guilds": len(bot.guilds) if "bot" in globals() else 0,
               "commandsTotal": len(bot.tree.get_commands()) if "bot" in globals() else 0,
               "commandsRegistered": len(bot.tree.get_commands()) if "bot" in globals() else 0,
               "commandsSyncedGuilds": 0, **extra}
    try:
        tmp = STATUS.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(STATUS)
    except OSError as exc:
        log.warning("Heartbeat não gravado: %s", type(exc).__name__)

async def event(kind, message, guild_id=None):
    async with lock:
        data.setdefault("events", []).append({"at": stamp(), "kind": kind, "message": str(message)[:250], "guildId": str(guild_id or "")})
        data["events"] = data["events"][-200:]
        save_data()

def active(name):
    return bool(MODULES.get(name))

def manager(user):
    p = getattr(user, "guild_permissions", None)
    return bool(p and (p.administrator or p.manage_guild or p.manage_messages))

def manager_check():
    async def predicate(interaction):
        if not manager(interaction.user):
            raise app_commands.CheckFailure("Este comando é exclusivo da equipe autorizada.")
        return True
    return app_commands.check(predicate)

intents = discord.Intents.default()
intents.guilds = True
intents.members = False
intents.message_content = False

class CaosBot(commands.Bot):
    async def setup_hook(self):
        try:
            synced = await self.tree.sync()
            log.info("Comandos publicados: %s", len(synced))
            status("starting", commandsRegistered=len(synced))
        except Exception as exc:
            log.exception("Falha ao publicar comandos")
            status("command_sync_error", error=type(exc).__name__ + ": " + str(exc)[:200])
    async def on_ready(self):
        log.info("ONLINE: %s (%s), guilds=%s", self.user, self.user.id, len(self.guilds))
        status("online", botId=str(self.user.id), botName=str(self.user), guilds=len(self.guilds))
        if not heartbeat.is_running():
            heartbeat.start()
        await event("ready", "Bot conectado ao Discord.")
    async def on_resumed(self):
        status("online", botId=str(self.user.id), botName=str(self.user))
    async def on_disconnect(self):
        status("reconnecting", botId=str(self.user.id) if self.user else None)

bot = CaosBot(command_prefix="!", intents=intents, help_command=None)

@tasks.loop(seconds=30)
async def heartbeat():
    if bot.user:
        status("online", botId=str(bot.user.id), botName=str(bot.user), guilds=len(bot.guilds))
@heartbeat.before_loop
async def wait_ready():
    await bot.wait_until_ready()

@bot.tree.command(name="caos", description="Mostra o estado do bot BLACK ZONE.")
async def caos(interaction: discord.Interaction):
    embed = discord.Embed(title="CAOS • BLACK ZONE", description="Seu bot está conectado ao Discord.", color=discord.Color.blurple())
    embed.add_field(name="Estado", value="Online" if bot.is_ready() else "Conectando")
    embed.add_field(name="Servidores", value=str(len(bot.guilds)))
    embed.add_field(name="Módulos", value=", ".join(k for k,v in MODULES.items() if v) or "Nenhum", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

if active("tickets"):
    @bot.tree.command(name="ticket", description="Abre um canal privado de atendimento.")
    async def ticket(interaction: discord.Interaction):
        g = interaction.guild
        if not g:
            return await interaction.response.send_message("Use dentro de um servidor.", ephemeral=True)
        name = "ticket-" + str(interaction.user.id)
        old = discord.utils.get(g.text_channels, name=name)
        if old:
            return await interaction.response.send_message("Seu ticket já está aberto: " + old.mention, ephemeral=True)
        overwrites = {g.default_role: discord.PermissionOverwrite(view_channel=False),
                      interaction.user: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)}
        if g.me:
            overwrites[g.me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True)
        channel = await g.create_text_channel(name, overwrites=overwrites, topic="Atendimento " + str(interaction.user))
        await channel.send("Olá " + interaction.user.mention + "! A equipe atenderá você aqui. Use /fechar_ticket para encerrar.")
        await interaction.response.send_message("Ticket criado: " + channel.mention, ephemeral=True)
        await event("ticket", "Ticket aberto por " + str(interaction.user), g.id)

    @bot.tree.command(name="fechar_ticket", description="Fecha o ticket atual.")
    async def fechar_ticket(interaction: discord.Interaction):
        ch = interaction.channel
        if not isinstance(ch, discord.TextChannel) or not ch.name.startswith("ticket-"):
            return await interaction.response.send_message("Use dentro de um canal de ticket.", ephemeral=True)
        if not manager(interaction.user) and ch.name != "ticket-" + str(interaction.user.id):
            return await interaction.response.send_message("Você não pode fechar este ticket.", ephemeral=True)
        await interaction.response.send_message("Ticket encerrado.")
        await ch.delete(reason="Fechado pelo CAOS")

if active("attendance"):
    @bot.tree.command(name="ponto", description="Registra entrada ou saída do expediente.")
    @app_commands.choices(acao=[app_commands.Choice(name="Entrada", value="entrada"), app_commands.Choice(name="Saída", value="saida")])
    async def ponto(interaction: discord.Interaction, acao: app_commands.Choice[str]):
        key = str(interaction.guild_id) + ":" + str(interaction.user.id)
        async with lock:
            row = data.setdefault("attendance", {}).get(key, {})
            if acao.value == "entrada":
                if row.get("startedAt"):
                    return await interaction.response.send_message("Você já tem um ponto aberto.", ephemeral=True)
                row = {"startedAt": stamp(), "endedAt": None}
            else:
                if not row.get("startedAt"):
                    return await interaction.response.send_message("Registre a entrada primeiro.", ephemeral=True)
                row["endedAt"] = stamp()
                row["duration"] = str(datetime.now(timezone.utc) - datetime.fromisoformat(row["startedAt"]))
            data["attendance"][key] = row
            save_data()
        await interaction.response.send_message("Ponto de " + acao.value + " registrado.", ephemeral=True)
        await event("attendance", str(interaction.user) + " registrou " + acao.value, interaction.guild_id)

if active("goals"):
    @bot.tree.command(name="meta", description="Consulta ou define uma meta da equipe.")
    async def meta(interaction: discord.Interaction, nome: str, valor: app_commands.Range[int, 0, 100000] = 0):
        key = str(interaction.guild_id) + ":" + nome.lower()[:60]
        async with lock:
            current = int(data.setdefault("goals", {}).get(key, 0))
            if valor:
                if not manager(interaction.user):
                    return await interaction.response.send_message("Somente a equipe pode alterar metas.", ephemeral=True)
                current = valor
                data["goals"][key] = valor
                save_data()
        await interaction.response.send_message("Meta **" + nome[:60] + "**: **" + str(current) + "**.", ephemeral=True)
        if valor:
            await event("goal", "Meta atualizada: " + nome, interaction.guild_id)

if active("warnings"):
    @bot.tree.command(name="advertencia", description="Registra uma advertência.")
    @manager_check()
    async def advertencia(interaction: discord.Interaction, membro: discord.Member, motivo: str):
        item = {"guildId": str(interaction.guild_id), "userId": str(membro.id), "moderatorId": str(interaction.user.id), "reason": motivo[:500], "at": stamp()}
        async with lock:
            data.setdefault("warnings", []).append(item)
            data["warnings"] = data["warnings"][-500:]
            save_data()
        await interaction.response.send_message("Advertência registrada para " + membro.mention + ".", ephemeral=True)
        await event("warning", "Advertência para " + str(membro), interaction.guild_id)

if active("team"):
    @bot.tree.command(name="equipe", description="Mostra os cargos e permissões do usuário.")
    async def equipe(interaction: discord.Interaction):
        roles = getattr(interaction.user, "roles", [])
        names = [r.mention for r in roles if r.name != "@everyone"]
        await interaction.response.send_message("**Cargos:** " + (", ".join(names) or "Nenhum") + "\n**Equipe autorizada:** " + ("Sim" if manager(interaction.user) else "Não"), ephemeral=True)

if active("recruitment"):
    class RecruitmentModal(discord.ui.Modal, title="Inscrição • BLACK ZONE"):
        nome = discord.ui.TextInput(label="Nome ou apelido", max_length=80)
        idade = discord.ui.TextInput(label="Idade", max_length=3)
        motivo = discord.ui.TextInput(label="Por que deseja entrar?", style=discord.TextStyle.paragraph, max_length=700)
        async def on_submit(self, interaction: discord.Interaction):
            item = {"guildId": str(interaction.guild_id), "userId": str(interaction.user.id), "name": str(self.nome), "age": str(self.idade), "reason": str(self.motivo), "at": stamp()}
            async with lock:
                data.setdefault("applications", []).append(item)
                data["applications"] = data["applications"][-300:]
                save_data()
            await interaction.response.send_message("Inscrição recebida. A equipe analisará sua resposta.", ephemeral=True)
            await event("recruitment", "Inscrição recebida de " + str(interaction.user), interaction.guild_id)
    @bot.tree.command(name="recrutar", description="Abre o formulário de recrutamento.")
    async def recrutar(interaction: discord.Interaction):
        await interaction.response.send_modal(RecruitmentModal())

if active("logs"):
    @bot.tree.command(name="logs", description="Mostra as últimas atividades do CAOS.")
    @manager_check()
    async def logs_command(interaction: discord.Interaction):
        rows = data.get("events", [])[-10:]
        if not rows:
            return await interaction.response.send_message("Ainda não há atividades.", ephemeral=True)
        lines = ["• " + str(x.get("kind")) + " — " + str(x.get("message")) for x in reversed(rows)]
        await interaction.response.send_message("\n".join(lines)[:1900], ephemeral=True)

if active("music"):
    try:
        import yt_dlp
        import imageio_ffmpeg
        music_queue = defaultdict(list)
        ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
        ydl_opts = {"format": "bestaudio/best", "noplaylist": True, "quiet": True, "default_search": "ytsearch"}
        async def next_track(guild_id):
            voice = discord.utils.get(bot.voice_clients, guild__id=guild_id)
            if not voice or not music_queue[guild_id]:
                return
            track = music_queue[guild_id].pop(0)
            audio = discord.FFmpegPCMAudio(track["url"], executable=ffmpeg, before_options="-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5", options="-vn")
            voice.play(audio, after=lambda error: asyncio.run_coroutine_threadsafe(next_track(guild_id), bot.loop))
        @bot.tree.command(name="musica", description="Toca uma música por nome ou URL.")
        async def musica(interaction: discord.Interaction, busca: str):
            voice_state = getattr(interaction.user, "voice", None)
            if not voice_state or not voice_state.channel:
                return await interaction.response.send_message("Entre em um canal de voz primeiro.", ephemeral=True)
            await interaction.response.defer(ephemeral=True)
            def extract():
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    info = ydl.extract_info(busca, download=False)
                    if "entries" in info:
                        info = next((x for x in info["entries"] if x), None)
                    return {"url": info["url"], "title": info.get("title", "Áudio")}
            try:
                track = await asyncio.get_running_loop().run_in_executor(None, extract)
                voice = discord.utils.get(bot.voice_clients, guild__id=interaction.guild_id)
                if voice and voice.channel != voice_state.channel:
                    await voice.move_to(voice_state.channel)
                elif not voice:
                    voice = await voice_state.channel.connect()
                music_queue[interaction.guild_id].append(track)
                if not voice.is_playing():
                    await next_track(interaction.guild_id)
                await interaction.followup.send("Adicionado à fila: **" + track["title"][:140] + "**.", ephemeral=True)
            except Exception as exc:
                log.exception("Erro no módulo de música")
                await interaction.followup.send("Falha ao tocar áudio: " + type(exc).__name__, ephemeral=True)
        @bot.tree.command(name="parar_musica", description="Para a reprodução.")
        async def parar_musica(interaction: discord.Interaction):
            voice = discord.utils.get(bot.voice_clients, guild__id=interaction.guild_id)
            music_queue[interaction.guild_id].clear()
            if voice:
                if voice.is_playing():
                    voice.stop()
                await voice.disconnect()
            await interaction.response.send_message("Reprodução encerrada.", ephemeral=True)
    except Exception as exc:
        log.exception("Módulo de música indisponível: %s", type(exc).__name__)

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    log.exception("Erro em comando Discord")
    message = str(error) if isinstance(error, app_commands.CheckFailure) else "O comando falhou. Confira os logs do bot."
    if not interaction.response.is_done():
        await interaction.response.send_message(message[:1800], ephemeral=True)
    else:
        await interaction.followup.send(message[:1800], ephemeral=True)

if not TOKEN:
    status("token_missing")
    raise SystemExit("DISCORD_TOKEN não configurado.")

try:
    stored = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    if isinstance(stored, dict):
        data.update(stored)
except (OSError, ValueError):
    pass
for key, default in {"attendance": {}, "goals": {}, "warnings": [], "applications": [], "events": []}.items():
    data.setdefault(key, default)
save_data()
status("starting")
log.info("Iniciando CAOS; módulos ativos: %s", ", ".join(k for k,v in MODULES.items() if v) or "nenhum")
try:
    bot.run(TOKEN, log_handler=None)
except discord.LoginFailure:
    status("token_error", error="O Discord recusou o token. Gere um novo Bot Token.")
    raise
except Exception as exc:
    status("error", error=type(exc).__name__ + ": " + str(exc)[:250])
    raise
finally:
    status("offline")
`;
