import os
import re
import asyncio
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import discord
from discord import AuditLogAction, Forbidden, HTTPException, NotFound
from discord.ext import commands

# ---------- Konfiguration ----------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
BOT_ADMIN_ID = 843180408152784936
BOT_OWNER_ID = 662596869221908480  # Deine Nutzer-ID (für DM-Alerts)

# Invite-Settings
INVITE_SPAM_WINDOW_SECONDS = 45
INVITE_SPAM_THRESHOLD = 5
INVITE_TIMEOUT_HOURS = 1

# Anti-Webhook Settings
WEBHOOK_STRIKES_BEFORE_KICK = 3

# Anti Ban/Kick Spamm Settings
ANTI_BAN_KICK_WINDOW_SECONDS = 60
ANTI_BAN_KICK_THRESHOLD = 3

# Anti Mention Spam Settings
MENTION_SPAM_WINDOW_SECONDS = 30
MENTION_SPAM_THRESHOLD = 3

VERBOSE = True

# ---------- Embed Farbe & Log Channel Konfiguration ----------
EMBED_COLOR = discord.Color.from_rgb(0, 110, 255)  # Dunkel Neon Blau
LOG_CHANNELS = {
    "moderation": "trustgate-logs-mod",
    "security": "trustgate-logs-security",
    "errors": "trustgate-logs-errors",
    "joins": "trustgate-logs-joins",
}

# ---------- Bot & Intents ----------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True
intents.bans = True
intents.webhooks = True
intents.guild_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- Hilfsvariablen ----------
INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[A-Za-z0-9\-]+",
    re.IGNORECASE,
)

whitelists: dict[int, set[int]] = defaultdict(set)
blacklists: dict[int, set[int]] = defaultdict(set)

invite_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=50))
webhook_strikes: defaultdict[int, int] = defaultdict(int)
existing_webhooks: dict[int, set[int]] = defaultdict(set)

ban_kick_actions: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
mention_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
mention_messages: dict[int, deque[discord.Message]] = defaultdict(lambda: deque(maxlen=10))

# ---------- Logging / Embed Hilfsfunktionen ----------

def log(*args):
    if VERBOSE:
        print("[LOG]", *args)

async def send_embed(destination, title: str, description: str, *, ephemeral: bool = False):
    embed = discord.Embed(title=title, description=description, color=EMBED_COLOR, timestamp=datetime.now(timezone.utc))
    try:
        await destination.send(embed=embed)
    except Exception as e:
        log(f"Fehler beim Senden eines Embeds an {destination}: {e}")

async def dm_owner(title: str, description: str):
    try:
        owner = await bot.fetch_user(BOT_OWNER_ID)
        if owner:
            await send_embed(owner, title, description)
    except Exception as e:
        log(f"Fehler beim Senden einer DM an Owner: {e}")

async def get_or_create_log_channel(guild: discord.Guild, name: str) -> discord.TextChannel | None:
    chan = discord.utils.get(guild.text_channels, name=name)
    if chan:
        return chan
    try:
        chan = await guild.create_text_channel(name)
        log(f"Log-Channel '{name}' in {guild.name} erstellt.")
        return chan
    except Exception as e:
        log(f"Konnte Log-Channel '{name}' in {guild.name} nicht erstellen: {e}")
        return None

async def setup_log_channels(guild: discord.Guild):
    for key, name in LOG_CHANNELS.items():
        await get_or_create_log_channel(guild, name)

async def log_to_channel(guild: discord.Guild, log_type: str, title: str, message: str):
    name = LOG_CHANNELS.get(log_type)
    if not name:
        return
    chan = discord.utils.get(guild.text_channels, name=name)
    if not chan:
        chan = await get_or_create_log_channel(guild, name)
    if chan:
        await send_embed(chan, title, message)

# ---------- Utility Funktionen (Moderation Actions) ----------
async def safe_delete_message(msg: discord.Message):
    try:
        await msg.delete()
    except (NotFound, Forbidden, HTTPException):
        pass

def is_whitelisted(member: discord.Member | discord.User) -> bool:
    gid = getattr(getattr(member, "guild", None), "id", None)
    if gid is None:
        return False
    return member.id in whitelists[gid]

def is_blacklisted(member: discord.Member | discord.User) -> bool:
    gid = getattr(getattr(member, "guild", None), "id", None)
    if gid is None:
        return False
    return member.id in blacklists[gid]

def is_bot_admin(interaction: discord.Interaction) -> bool:
    return interaction.user.id == BOT_ADMIN_ID or (interaction.guild and interaction.user.id == interaction.guild.owner_id)

async def kick_member(guild: discord.Guild, member: discord.Member | discord.User, reason: str):
    if not member or (isinstance(member, discord.Member) and is_whitelisted(member)):
        return
    if member.id == bot.user.id:
        return
    try:
        await guild.kick(discord.Object(id=member.id), reason=reason)
        log(f"Kicked {member} | Reason: {reason}")
        await log_to_channel(guild, "moderation", "🚨 Kick", f"{member} | {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Kick failed for {member}: {e}")

async def ban_member(guild: discord.Guild, member: discord.Member | discord.User, reason: str, delete_days: int = 0):
    if not member or (isinstance(member, discord.Member) and is_whitelisted(member)):
        return
    if member.id == bot.user.id:
        return
    try:
        await guild.ban(discord.Object(id=member.id), reason=reason, delete_message_days=delete_days)
        log(f"Banned {member} | Reason: {reason}")
        await log_to_channel(guild, "moderation", "⛔ Ban", f"{member} | {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Ban failed for {member}: {e}")

async def timeout_member(member: discord.Member, hours: int, reason: str):
    if not member or is_whitelisted(member):
        return
    if member.id == bot.user.id:
        return
    try:
        until = datetime.now(timezone.utc) + timedelta(hours=hours)
        await member.edit(timed_out_until=until, reason=reason)
        log(f"Timed out {member} until {until} | Reason: {reason}")
        await log_to_channel(member.guild, "moderation", "⏱️ Timeout", f"{member} bis {until} | {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Timeout failed for {member}: {e}")

async def actor_from_audit_log(guild: discord.Guild, action: AuditLogAction, target_id: int | None = None, within_seconds: int = 10):
    await asyncio.sleep(0.35)
    try:
        now = datetime.now(timezone.utc)
        async for entry in guild.audit_logs(limit=15, action=action):
            if (now - entry.created_at).total_seconds() > within_seconds:
                continue
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            return entry.user
    except Forbidden:
        log("Keine Berechtigung, Audit-Logs zu lesen.")
    except NotFound:
        log(f"Audit Log Fehler: Guild {guild.id} nicht gefunden.")
    except HTTPException as e:
        log(f"Audit Log HTTP-Fehler: {e}")
    return None

# ---------- Nachricht an Eigentümer nach Neustart ----------
async def notify_owner_after_restart():
    await asyncio.sleep(3)
    for guild in bot.guilds:
        message_text = (
            "🛡️TrustGate🛡️\n"
            "@User*, lieber Eigentümer des Servers **(servername)*,\n"
            "aufgrund dessen, dass mein Besitzer regelmäßig einen neuen Free-Plan bei einer Hosting-Website beantragen muss, "
            "wurde ich neu gestartet.\n"
            "Dabei werden leider die Nutzer in der Whitelist und Blacklist gelöscht.\n"
            "Bitte stelle daher deine Whitelist und Blacklist erneut ein.\n\n"
            "*Mit freundlichen Grüßen,*\n"
            "_TrustGate_"
        )
        try:
            owner = guild.owner or await bot.fetch_user(guild.owner_id)
            if owner:
                try:
                    await send_embed(owner, f"Neustart: {guild.name}", message_text.replace("@User", owner.mention).replace("(servername)", guild.name))
                    log(f"Neustart-Nachricht an {owner} per DM gesendet ({guild.name})")
                except (Forbidden, HTTPException):
                    channel = discord.utils.get(guild.text_channels, name=LOG_CHANNELS.get("moderation"))
                    if channel:
                        await send_embed(channel, f"Neustart: {guild.name}", message_text.replace("@User", owner.mention).replace("(servername)", guild.name))
                        log(f"Neustart-Nachricht an #{channel.name} in {guild.name} gesendet")
                    else:
                        log(f"Kein geeigneter Kanal in {guild.name} gefunden.")
        except Exception as e:
            log(f"Fehler beim Benachrichtigen des Eigentümers in {guild.name}: {e}")

# ---------- Events ----------
@bot.event
async def on_ready():
    log(f"Bot online als {bot.user} (ID: {bot.user.id})")
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Game("Bereit zum Beschützen!")
    )

    for guild in bot.guilds:
        try:
            await setup_log_channels(guild)
        except Exception as e:
            log(f"Fehler beim Setup der Log-Channels in {guild.name}: {e}")

    asyncio.create_task(notify_owner_after_restart())

    try:
        await bot.tree.sync()
        log("Alle Slash Commands global synchronisiert ✅")
    except Exception as e:
        log(f"Fehler beim globalen Slash Command Sync: {e}")

# ---------- Anti Ban/Kick Spamm ----------
async def track_ban_kick(actor: discord.Member, action_type: str):
    now = asyncio.get_event_loop().time()
    dq = ban_kick_actions[actor.id]
    dq.append(now)
    while dq and (now - dq[0]) > ANTI_BAN_KICK_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= ANTI_BAN_KICK_THRESHOLD:
        guild = actor.guild
        await kick_member(guild, actor, f"Anti Ban/Kick Spamm: {len(dq)} Aktionen in kurzer Zeit")
        ban_kick_actions[actor.id].clear()

@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    actor = await actor_from_audit_log(guild, AuditLogAction.ban, target_id=user.id, within_seconds=30)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await track_ban_kick(actor, "ban")

@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.kick, target_id=member.id, within_seconds=30)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await track_ban_kick(actor, "kick")

# ---------- Anti Webhook / Anti Invite / Anti Mention Spam ----------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # --- Anti Invite Spam ---
    if INVITE_REGEX.search(message.content):
        if not is_whitelisted(message.author):
            await safe_delete_message(message)
            now_ts = asyncio.get_event_loop().time()
            dq = invite_timestamps[message.author.id]
            dq.append(now_ts)
            while dq and (now_ts - dq[0]) > INVITE_SPAM_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= INVITE_SPAM_THRESHOLD:
                await kick_member(message.guild, message.author, "Invite-Link-Spam (Kick nach mehreren Links)")
                invite_timestamps[message.author.id].clear()
                await log_to_channel(
                    message.guild,
                    "security",
                    "🚫 Invite Spam erkannt",
                    f"{message.author} wurde gekickt wegen Invite Spam."
                )

    # --- Anti Mention Spam ---
    if not is_whitelisted(message.author):
        if message.mention_everyone or any(role.mentionable for role in message.role_mentions):
            now_ts = asyncio.get_event_loop().time()
            dq = mention_timestamps[message.author.id]
            msg_list = mention_messages[message.author.id]
            dq.append(now_ts)
            msg_list.append(message)

            while dq and (now_ts - dq[0]) > MENTION_SPAM_WINDOW_SECONDS:
                dq.popleft()
                if msg_list:
                    msg_list.popleft()

            if len(dq) >= MENTION_SPAM_THRESHOLD:
                await kick_member(
                    message.guild,
                    message.author,
                    f"Massenping-Spam: {len(dq)} @everyone/@here/@Role Erwähnungen in kurzer Zeit"
                )
                for msg in list(msg_list):
                    await safe_delete_message(msg)
                mention_timestamps[message.author.id].clear()
                mention_messages[message.author.id].clear()
                await log_to_channel(
                    message.guild,
                    "security",
                    "📢 Mention Spam erkannt",
                    f"{message.author} wurde gekickt wegen Massen-Pings."
                )

    await bot.process_commands(message)

# ---------- Anti Webhook ----------
@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.webhook_create, within_seconds=30)
    try:
        hooks = await channel.webhooks()
    except (Forbidden, HTTPException):
        hooks = []
    for hook in hooks:
        if hook.id in existing_webhooks[guild.id]:
            continue
        existing_webhooks[guild.id].add(hook.id)
        member = guild.get_member(hook.user.id) if hook.user else None
        if member and is_whitelisted(member):
            continue
        try:
            await hook.delete(reason="Anti-Webhook aktiv")
            log(f"Webhook {hook.name} gelöscht in #{channel.name}")
            await log_to_channel(guild, "security", "🧩 Webhook gelöscht", f"Webhook {hook.name} in #{channel.name} wurde gelöscht.")
        except (Forbidden, HTTPException, NotFound):
            pass
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        webhook_strikes[actor.id] += 1
        if webhook_strikes[actor.id] >= WEBHOOK_STRIKES_BEFORE_KICK:
            await kick_member(guild, actor, "Zu viele Webhook-Erstellungen (3)")
            webhook_strikes[actor.id] = 0

# ---------- Anti Bot Join ----------
@bot.event
async def on_member_join(member: discord.Member):
    if member.bot:
        inviter = None
        try:
            async for entry in member.guild.audit_logs(limit=10, action=AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    break
        except Exception:
            pass
        if inviter and not is_whitelisted(inviter):
            await kick_member(member.guild, member, "Bot wurde von nicht-whitelisted User eingeladen")
            await kick_member(member.guild, inviter, "Bot eingeladen ohne Whitelist-Berechtigung")
            await log_to_channel(member.guild, "joins", "🤖 Unautorisierter Bot eingeladen", f"Bot {member} wurde entfernt und Einladender {inviter} gekickt.")

# ---------- Anti Channel Delete ----------
@bot.event
async def on_guild_channel_delete(channel):
    actor = await actor_from_audit_log(channel.guild, AuditLogAction.channel_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(channel.guild, actor, "Kanal gelöscht ohne Berechtigung")
        await log_to_channel(channel.guild, "security", "🗑️ Kanal gelöscht", f"{actor} hat einen Kanal gelöscht.")

# ---------- Anti Role Delete ----------
@bot.event
async def on_guild_role_delete(role):
    actor = await actor_from_audit_log(role.guild, AuditLogAction.role_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(role.guild, actor, "Rolle gelöscht ohne Berechtigung")
        await log_to_channel(role.guild, "security", "🔐 Rolle gelöscht", f"{actor} hat eine Rolle gelöscht.")

# ---------- 🆕 Anti Channel Create ----------
@bot.event
async def on_guild_channel_create(channel):
    actor = await actor_from_audit_log(channel.guild, AuditLogAction.channel_create, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(channel.guild, actor, "Kanal erstellt ohne Whitelist-Berechtigung")
        await log_to_channel(channel.guild, "security", "📂 Kanal erstellt", f"{actor} hat einen Kanal erstellt.")

# ---------- Slash Commands (alle Antworten als Embed) ----------
@bot.tree.command(name="addwhitelist", description="Fügt einen User zur Whitelist hinzu (Owner/Admin Only)")
async def add_whitelist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(embed=discord.Embed(title="❌ Keine Berechtigung.", description="Du bist kein Bot-Admin.", color=EMBED_COLOR), ephemeral=True)
    whitelists[interaction.guild.id].add(user.id)
    await interaction.response.send_message(embed=discord.Embed(title="✅ Whitelist", description=f"User {user} wurde in *{interaction.guild.name}* zur Whitelist hinzugefügt.", color=EMBED_COLOR), ephemeral=True)
    await log_to_channel(interaction.guild, "moderation", "Whitelist Update", f"{user} wurde zur Whitelist hinzugefügt von {interaction.user}.")

@bot.tree.command(name="removewhitelist", description="Entfernt einen User von der Whitelist (Owner/Admin Only)")
async def remove_whitelist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(embed=discord.Embed(title="❌ Keine Berechtigung.", description="Du bist kein Bot-Admin.", color=EMBED_COLOR), ephemeral=True)
    whitelists[interaction.guild.id].discard(user.id)
    await interaction.response.send_message(embed=discord.Embed(title="✅ Whitelist", description=f"User {user} wurde in *{interaction.guild.name}* von der Whitelist entfernt.", color=EMBED_COLOR), ephemeral=True)
    await log_to_channel(interaction.guild, "moderation", "Whitelist Update", f"{user} wurde von der Whitelist entfernt von {interaction.user}.")

@bot.tree.command(name="showwhitelist", description="Zeigt alle User in der Whitelist")
async def show_whitelist(interaction: discord.Interaction):
    users = whitelists[interaction.guild.id]
    if not users:
        return await interaction.response.send_message(embed=discord.Embed(title="ℹ Whitelist ist leer.", color=EMBED_COLOR), ephemeral=True)
    resolved = []
    for uid in users:
        try:
            user = interaction.guild.get_member(uid) or await bot.fetch_user(uid)
            resolved.append(user.name if user else str(uid))
        except Exception:
            resolved.append(str(uid))
    await interaction.response.send_message(embed=discord.Embed(title="📜 Whitelist", description="\n".join(resolved), color=EMBED_COLOR), ephemeral=True)

@bot.tree.command(name="addblacklist", description="Fügt einen User zur Blacklist hinzu (Owner/Admin Only)")
async def add_blacklist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(embed=discord.Embed(title="❌ Keine Berechtigung.", description="Du bist kein Bot-Admin.", color=EMBED_COLOR), ephemeral=True)
    blacklists[interaction.guild.id].add(user.id)
    await interaction.response.send_message(embed=discord.Embed(title="✅ Blacklist", description=f"User {user} wurde in *{interaction.guild.name}* zur Blacklist hinzugefügt.", color=EMBED_COLOR), ephemeral=True)
    await log_to_channel(interaction.guild, "moderation", "Blacklist Update", f"{user} wurde zur Blacklist hinzugefügt von {interaction.user}.")

@bot.tree.command(name="removeblacklist", description="Entfernt einen User von der Blacklist (Owner/Admin Only)")
async def remove_blacklist(interaction: discord.Interaction, user: discord.User):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(embed=discord.Embed(title="❌ Keine Berechtigung.", description="Du bist kein Bot-Admin.", color=EMBED_COLOR), ephemeral=True)
    blacklists[interaction.guild.id].discard(user.id)
    await interaction.response.send_message(embed=discord.Embed(title="✅ Blacklist", description=f"User {user} wurde in *{interaction.guild.name}* von der Blacklist entfernt.", color=EMBED_COLOR), ephemeral=True)
    await log_to_channel(interaction.guild, "moderation", "Blacklist Update", f"{user} wurde von der Blacklist entfernt von {interaction.user}.")

@bot.tree.command(name="showblacklist", description="Zeigt alle User in der Blacklist")
async def show_blacklist(interaction: discord.Interaction):
    users = blacklists[interaction.guild.id]
    if not users:
        return await interaction.response.send_message(embed=discord.Embed(title="ℹ Blacklist ist leer.", color=EMBED_COLOR), ephemeral=True)
    resolved = []
    for uid in users:
        try:
            user = interaction.guild.get_member(uid) or await bot.fetch_user(uid)
            resolved.append(user.name if user else str(uid))
        except Exception:
            resolved.append(str(uid))
    await interaction.response.send_message(embed=discord.Embed(title="🚫 Blacklist", description="\n".join(resolved), color=EMBED_COLOR), ephemeral=True)

# ---------- Neuer Slash Command: Create Webhook ----------
@bot.tree.command(name="create-webhook", description="Erstellt einen Webhook (Whitelist Only)")
async def create_webhook(interaction: discord.Interaction, channel: discord.TextChannel, name: str):
    if not is_whitelisted(interaction.user):
        return await interaction.response.send_message(embed=discord.Embed(title="❌ Nicht whitelisted", description="Du bist nicht whitelisted!", color=EMBED_COLOR), ephemeral=True)

    try:
        hook = await channel.create_webhook(name=name, reason=f"Erstellt von whitelisted User {interaction.user}")
        existing_webhooks[interaction.guild.id].add(hook.id)

        async def delete_later():
            await asyncio.sleep(7 * 24 * 60 * 60)
            try:
                await hook.delete(reason="Webhook Ablauf nach 1 Woche")
                existing_webhooks[interaction.guild.id].discard(hook.id)
            except:
                pass

        asyncio.create_task(delete_later())

        await interaction.response.send_message(embed=discord.Embed(title="✅ Webhook erstellt", description=hook.url, color=EMBED_COLOR), ephemeral=True)
        await log_to_channel(interaction.guild, "moderation", "Webhook erstellt", f"Webhook {hook.name} erstellt von {interaction.user} in #{channel.name}")
    except Exception as e:
        await interaction.response.send_message(embed=discord.Embed(title="❌ Fehler beim Erstellen des Webhooks", description=str(e), color=EMBED_COLOR), ephemeral=True)
        await log_to_channel(interaction.guild, "errors", "Webhook Error", str(e))

# ---------- Neuer Slash Command: Setup Logs ----------
@bot.tree.command(name="setup-logs", description="Erstellt alle Log-Channels (Owner/Admin Only)")
async def setup_logs_command(interaction: discord.Interaction):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(
            embed=discord.Embed(
                title="❌ Keine Berechtigung.",
                description="Du bist kein Bot-Admin.",
                color=EMBED_COLOR
            ),
            ephemeral=True
        )
    
    try:
        await setup_log_channels(interaction.guild)
        await interaction.response.send_message(
            embed=discord.Embed(
                title="✅ Log-Channels erstellt",
                description="Alle in LOG_CHANNELS konfigurierten Channels wurden überprüft und ggf. erstellt.",
                color=EMBED_COLOR
            ),
            ephemeral=True
        )
        await log_to_channel(interaction.guild, "moderation", "Setup Logs", f"{interaction.user} hat alle Log-Channels eingerichtet.")
    except Exception as e:
        await interaction.response.send_message(
            embed=discord.Embed(
                title="❌ Fehler beim Erstellen der Log-Channels",
                description=str(e),
                color=EMBED_COLOR
            ),
            ephemeral=True
        )
        await log_to_channel(interaction.guild, "errors", "Setup Logs Error", f"{interaction.user} versuchte Log-Channels einzurichten.\nFehler: {e}")

# ---------- /help Command ----------
@bot.tree.command(name="help", description="Zeigt alle Bot Funktionen")
async def help_cmd(interaction: discord.Interaction):
    text = (
        "🛡️ **TrustGate Security System**\n\n"
        "**Whitelist**\n"
        "`/addwhitelist USER`\n"
        "`/removewhitelist USER`\n"
        "`/showwhitelist`\n\n"
        "**Blacklist**\n"
        "`/addblacklist USER`\n"
        "`/removeblacklist USER`\n"
        "`/showblacklist`\n\n"
        "**Webhook**\n"
        "`/create-webhook CHANNEL NAME` (nur für Whitelisted Users)\n\n"
        "**Schutzsysteme:**\n"
        "• Anti Invite Spam\n"
        "• Anti Ban/Kick Spam\n"
        "• Anti Channel Create/Delete\n"
        "• Anti Role Delete\n"
        "• Anti Webhook\n"
        "• Anti Bot Invite\n"
        "• Anti Mention Spam\n\n"
        "**Logs:**\n"
        f"Alle Logs werden automatisch in: {', '.join(LOG_CHANNELS.values())} gespeichert."
    )
    embed = discord.Embed(title="📖 TrustGate Hilfe", description=text, color=EMBED_COLOR)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---------- DMs + Events für Owner Alerts ----------
@bot.event
async def on_guild_join(guild):
    try:
        await setup_log_channels(guild)
    except Exception as e:
        log(f"Fehler beim Setup der Log-Channels in {guild.name}: {e}")

    inviter = None
    try:
        async for entry in guild.audit_logs(limit=5, action=AuditLogAction.bot_add):
            if entry.target.id == bot.user.id:
                inviter = entry.user
                break
    except Exception:
        pass

    owner = guild.owner or await bot.fetch_user(guild.owner_id)
    inviter_text = f"{inviter} (ID: {inviter.id})" if inviter else "Unbekannt"

    join_message = (
        f"Server: {guild.name}\n"
        f"Server-ID: {guild.id}\n"
        f"Owner: {owner} (ID: {guild.owner_id})\n"
        f"Einladender: {inviter_text}\n"
        f"Mitglieder: {guild.member_count}\n"
        f"Locale: {guild.preferred_locale}\n"
        f"Zeit: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M:%S UTC')}"
    )

    await dm_owner("➕ Bot hinzugefügt", join_message)
    await log_to_channel(guild, "joins", "➕ Bot hinzugefügt", join_message)

@bot.event
async def on_error(event, *args, **kwargs):
    try:
        await dm_owner("⚠️ BOT FEHLER", f"Event: {event}\nArgs: {args}\nKwargs: {kwargs}")
    except Exception as e:
        log(f"Fehler beim Senden von Fehler-DM an Owner: {e}")

@bot.event
async def on_application_command_error(interaction: discord.Interaction, error: Exception):
    log(f"Command Error: {error}")
    guild = interaction.guild
    if guild:
        await log_to_channel(guild, "errors", "Slash Command Error", f"User: {interaction.user}\nCommand: {interaction.command.name if interaction.command else 'unknown'}\nError: {error}")
    await dm_owner("🛑 Command Error", f"Guild: {guild.name if guild else 'DM'}\nUser: {interaction.user}\nCommand: {interaction.command.name if interaction.command else 'unknown'}\nError: {error}")
    try:
        await interaction.response.send_message(embed=discord.Embed(title="❌ Fehler", description="Ein Fehler ist aufgetreten. Der Bot-Owner wurde informiert.", color=EMBED_COLOR), ephemeral=True)
    except Exception:
        pass

# ---------- Neuer Slash Command: Setup Log Bereich ----------

@bot.tree.command(name="setup_log", description="Erstellt alle Log-Channels unter einer TRUST GATE Kategorie (Owner/Admin Only)")
async def setup_log(interaction: discord.Interaction):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message(
            embed=discord.Embed(
                title="❌ Keine Berechtigung.",
                description="Du bist kein Bot-Admin.",
                color=EMBED_COLOR
            ),
            ephemeral=True
        )

    guild = interaction.guild

    # Kategorie suchen oder erstellen
    category = discord.utils.get(guild.categories, name="TRUST GATE")
    if category is None:
        category = await guild.create_category(
            "TRUST GATE",
            reason=f"Erstellt von {interaction.user}"
        )

        # Kategorie ganz nach unten verschieben
        await category.edit(position=len(guild.categories))

    created_channels = []

    # Log-Channels innerhalb der Kategorie erstellen
    for key, name in LOG_CHANNELS.items():
        chan = discord.utils.get(guild.text_channels, name=name)

        if chan is None:
            chan = await guild.create_text_channel(
                name=name,
                category=category,
                reason=f"Log-Channel erstellt von {interaction.user}"
            )
            created_channels.append(chan.name)
        else:
            # Falls Channel existiert: in die TRUST GATE Kategorie verschieben
            try:
                await chan.edit(category=category)
            except:
                pass

    # Antwort an den User
    if created_channels:
        msg = "Folgende Channels wurden erstellt:\n" + "\n".join(f"• {c}" for c in created_channels)
    else:
        msg = "Alle Log-Channels existieren bereits und wurden in die TRUST GATE Kategorie verschoben."

    await interaction.response.send_message(
        embed=discord.Embed(
            title="📂 TRUST GATE Logs eingerichtet",
            description=msg,
            color=EMBED_COLOR
        ),
        ephemeral=True
    )

    # Logging
    await log_to_channel(
        guild,
        "moderation",
        "Setup Log Bereich",
        f"{interaction.user} hat die TRUST GATE Log-Struktur eingerichtet."
    )
    
# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)
