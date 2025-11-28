# trustgate_bot.py
# Python 3.11+ (typing usage), discord.py 2.x
# Kompatibel mit Railway (set DISCORD_TOKEN env var)

import os
import re
import asyncio
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import discord
from discord import AuditLogAction, Forbidden, HTTPException, NotFound
from discord.ext import commands

# ---------------- Configuration ----------------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
if not TOKEN:
    print("WARNUNG: DISCORD_TOKEN nicht gesetzt. Setze die Umgebungsvariable in Railway.")
BOT_OWNER_ID = 662596869221908480  # Deine User-ID (für DMs)

# Admin (optional) - du kannst eine zweite Admin-ID hinzufügen falls gewünscht
BOT_ADMIN_ID = BOT_OWNER_ID

# Anti settings
INVITE_SPAM_WINDOW_SECONDS = 45
INVITE_SPAM_THRESHOLD = 5

WEBHOOK_STRIKES_BEFORE_KICK = 3

ANTI_BAN_KICK_WINDOW_SECONDS = 60
ANTI_BAN_KICK_THRESHOLD = 3

MENTION_SPAM_WINDOW_SECONDS = 30
MENTION_SPAM_THRESHOLD = 3

VERBOSE = True

# Embed color (Neon Dunkel Blau)
EMBED_COLOR = discord.Color.from_rgb(0, 110, 255)

# Log channels to create inside TRUST GATE category
LOG_CHANNELS = {
    "moderation": "trustgate-logs-mod",
    "security": "trustgate-logs-security",
    "errors": "trustgate-logs-errors",
    "joins": "trustgate-logs-joins",
    "audit": "trustgate-logs-audit",
}

# ---------------- Intents & Bot ----------------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True
intents.bans = True
intents.webhooks = True
intents.guild_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

# For use in anti-spam tracking
INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[A-Za-z0-9\-]+",
    re.IGNORECASE,
)

# in-memory lists (Railway ephemeral — persist if needed via DB/files)
whitelists: dict[int, set[int]] = defaultdict(set)
blacklists: dict[int, set[int]] = defaultdict(set)

invite_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=50))
webhook_strikes: defaultdict[int, int] = defaultdict(int)
existing_webhooks: dict[int, set[int]] = defaultdict(set)

ban_kick_actions: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
mention_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
mention_messages: dict[int, deque[discord.Message]] = defaultdict(lambda: deque(maxlen=10))

# ---------------- Helpers ----------------
def log(*args):
    if VERBOSE:
        print("[LOG]", *args)

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

async def send_embed(destination, title: str, description: str, *, ephemeral: bool=False):
    embed = discord.Embed(title=title, description=description, color=EMBED_COLOR, timestamp=datetime.now(timezone.utc))
    try:
        await destination.send(embed=embed)
    except Exception as e:
        log(f"Fehler beim Senden Embed an {destination}: {e}")

async def dm_owner(title: str, description: str):
    try:
        owner = await bot.fetch_user(BOT_OWNER_ID)
        if owner:
            await send_embed(owner, title, description)
    except Exception as e:
        log(f"Fehler beim Senden DM an Owner: {e}")

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
        try:
            await send_embed(chan, title, message)
        except Exception as e:
            log(f"Fehler beim Loggen in {name}: {e}")

async def safe_delete_message(msg: discord.Message):
    try:
        await msg.delete()
    except (NotFound, Forbidden, HTTPException):
        pass

# Moderation actions
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
        # Note: depending on discord.py version, field may be 'timed_out_until' or 'timeout' - this works on common versions
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

# ---------------- Startup / Ready ----------------
@bot.event
async def on_ready():
    log(f"Bot online als {bot.user} (ID: {bot.user.id})")
    # Status setzen
    try:
        await bot.change_presence(status=discord.Status.online, activity=discord.Game("discord.gg/trustgate"))
    except Exception:
        pass

    # Ensure log channels exist in all guilds
    for guild in bot.guilds:
        try:
            await setup_log_channels(guild)
        except Exception as e:
            log(f"Fehler beim Setup Log-Channels in {guild.name}: {e}")

    # Sync commands
    try:
        await bot.tree.sync()
        log("Slash Commands synchronisiert")
    except Exception as e:
        log(f"Fehler beim Sync der Slash Commands: {e}")

# ---------------- Anti Ban/Kick Spam ----------------
async def track_ban_kick(actor: discord.Member, action_type: str):
    now = asyncio.get_event_loop().time()
    dq = ban_kick_actions[actor.id]
    dq.append(now)
    while dq and (now - dq[0]) > ANTI_BAN_KICK_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= ANTI_BAN_KICK_THRESHOLD:
        guild = actor.guild
        await kick_member(guild, actor, f"Anti Ban/Kick Spam: {len(dq)} Aktionen")
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

# ---------------- Anti Invite / Mention / Webhook / Bot Join ----------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # Anti Invite Link
    if INVITE_REGEX.search(message.content):
        if not is_whitelisted(message.author):
            await safe_delete_message(message)
            now_ts = asyncio.get_event_loop().time()
            dq = invite_timestamps[message.author.id]
            dq.append(now_ts)
            while dq and (now_ts - dq[0]) > INVITE_SPAM_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= INVITE_SPAM_THRESHOLD:
                await kick_member(message.guild, message.author, "Invite-Link Spam")
                invite_timestamps[message.author.id].clear()
                await log_to_channel(message.guild, "security", "🚫 Invite Spam erkannt", f"{message.author} wurde gekickt wegen Invite Spam.")

    # Anti Mention Spam (@everyone/@here or role pings)
    if not is_whitelisted(message.author):
        if message.mention_everyone or message.role_mentions:
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
                await kick_member(message.guild, message.author, f"Massenmention Spam: {len(dq)} Erwähnungen")
                for msg in list(msg_list):
                    await safe_delete_message(msg)
                mention_timestamps[message.author.id].clear()
                mention_messages[message.author.id].clear()
                await log_to_channel(message.guild, "security", "📢 Mention Spam erkannt", f"{message.author} wurde gekickt wegen Massen-Pings.")

    await bot.process_commands(message)

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
            await kick_member(guild, actor, "Zu viele Webhook-Erstellungen")
            webhook_strikes[actor.id] = 0

@bot.event
async def on_member_join(member: discord.Member):
    # Anti Bot Join
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
    else:
        # normaler User Join logging
        await log_to_channel(member.guild, "joins", "👤 Member Join", f"{member} ist dem Server beigetreten.")

# ---------------- Channel / Role Protection ----------------
@bot.event
async def on_guild_channel_delete(channel):
    actor = await actor_from_audit_log(channel.guild, AuditLogAction.channel_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(channel.guild, actor, "Kanal gelöscht ohne Berechtigung")
        await log_to_channel(channel.guild, "security", "🗑️ Kanal gelöscht", f"{actor} hat einen Kanal gelöscht.")

@bot.event
async def on_guild_role_delete(role):
    actor = await actor_from_audit_log(role.guild, AuditLogAction.role_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(role.guild, actor, "Rolle gelöscht ohne Berechtigung")
        await log_to_channel(role.guild, "security", "🔐 Rolle gelöscht", f"{actor} hat eine Rolle gelöscht.")

@bot.event
async def on_guild_channel_create(channel):
    actor = await actor_from_audit_log(channel.guild, AuditLogAction.channel_create, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(channel.guild, actor, "Kanal erstellt ohne Whitelist-Berechtigung")
        await log_to_channel(channel.guild, "security", "📂 Kanal erstellt", f"{actor} hat einen Kanal erstellt.")

# ---------------- Owner Notification on Guild Join ----------------
@bot.event
async def on_guild_join(guild: discord.Guild):
    # Ensure log channels & TRUST GATE category
    try:
        # create category if not exists and ensure channels below created
        category = discord.utils.get(guild.categories, name="TRUST GATE")
        if category is None:
            category = await guild.create_category("TRUST GATE", reason="Automatisch erstellt von TrustGate")
            try:
                await category.edit(position=len(guild.categories))
            except Exception:
                pass

        for key, name in LOG_CHANNELS.items():
            ch = discord.utils.get(guild.text_channels, name=name)
            if ch is None:
                try:
                    ch = await guild.create_text_channel(name, category=category, reason="Log Channel erstellt von TrustGate")
                except Exception:
                    pass
            else:
                try:
                    await ch.edit(category=category)
                except Exception:
                    pass
    except Exception as e:
        log(f"Fehler beim Erstellen der TRUST GATE Struktur in {guild.name}: {e}")

    # find inviter of bot (bot_add audit log)
    inviter = None
    try:
        async for entry in guild.audit_logs(limit=10, action=AuditLogAction.bot_add):
            if entry.target.id == bot.user.id:
                inviter = entry.user
                break
    except Exception:
        pass

    owner = guild.owner or await bot.fetch_user(guild.owner_id)
    inviter_text = f\"{inviter} (ID: {inviter.id})\" if inviter else \"Unbekannt\"

    join_message = (
        f\"Server: {guild.name}\\n\"
        f\"Server-ID: {guild.id}\\n\"
        f\"Owner: {owner} (ID: {guild.owner_id})\\n\"
        f\"Einladender: {inviter_text}\\n\"
        f\"Mitglieder: {guild.member_count}\\n\"
        f\"Locale: {guild.preferred_locale}\\n\"
        f\"Zeit: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M:%S UTC')}\"
    )

    # DM to owner (your provided user id)
    await dm_owner(\"➕ Bot hinzugefügt\", join_message)
    # log to guild log channel if exists
    await log_to_channel(guild, "joins", "➕ Bot hinzugefügt", join_message)

# ---------------- Error & Command Handlers ----------------
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

# ---------------- Slash Commands ----------------
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

# Create webhook (only whitelisted)
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

# Setup logs command: create TRUST GATE category and place channels at bottom
@bot.tree.command(name="setup_log", description="Erstellt die TRUST GATE Kategorie und alle Log-Channels ganz unten.")
async def setup_log(interaction: discord.Interaction):
    if not is_bot_admin(interaction):
        return await interaction.response.send_message("❌ Keine Berechtigung.", ephemeral=True)

    guild = interaction.guild
    if guild is None:
        return await interaction.response.send_message("❌ Dieser Command kann nur in einem Server genutzt werden.", ephemeral=True)

    await interaction.response.send_message("⏳ Richte Log-System ein...", ephemeral=True)

    category_name = "TRUST GATE"
    category = discord.utils.get(guild.categories, name=category_name)

    if category is None:
        category = await guild.create_category(category_name)

    # Kategorie ganz nach unten schieben
    try:
        await category.edit(position=len(guild.categories))
    except:
        pass

    # Log-Channels erstellen oder verschieben
    created_or_moved = []

    for key, ch_name in LOG_CHANNELS.items():
        channel = discord.utils.get(guild.text_channels, name=ch_name)

        if channel is None:
            channel = await guild.create_text_channel(ch_name, category=category)
            created_or_moved.append(f"🆕 `{ch_name}` erstellt")
        else:
            await channel.edit(category=category)
            created_or_moved.append(f"➡️ `{ch_name}` verschoben")

        try:
            await channel.edit(position=len(category.channels))
        except:
            pass

    msg = "
".join(created_or_moved) if created_or_moved else "Alles war bereits korrekt eingerichtet."

    await interaction.followup.send(f"✅ **TRUST GATE Log-System aktualisiert:**
{msg}", ephemeral=True)


# ---------- /help Command ----------
@bot.tree.command(name="help", description="Zeigt alle verfügbaren Slash-Commands an.")
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(title="📘 TRUST GATE — Hilfe", color=EMBED_COLOR)
    embed.add_field(name="/setup_log", value="Richtet alle TRUST GATE Log-Channels automatisch ein.", inline=False)
    embed.add_field(name="(weitere Commands folgen)", value="Weitere Module können später ergänzt werden.", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---------- Bot Events & Start ----------
@bot.event
async def on_ready():
    print(f"Bot ist online als {bot.user}")
    for guild in bot.guilds:
        await setup_log_channels(guild)
    try:
        synced = await bot.tree.sync()
        print(f"Slash-Commands synchronisiert: {len(synced)}")
    except Exception as e:
        print(f"Fehler beim Sync: {e}")

# Beispiel-Event: Join-Logging
@bot.event
async def on_member_join(member: discord.Member):
    await log_to_channel(member.guild, "joins", "👤 Neuer User", f"{member} ist dem Server beigetreten.")

# Beispiel-Event: Fehler-Logging
@bot.event
async def on_error(event_method, *args, **kwargs):
    for guild in bot.guilds:
        await log_to_channel(guild, "errors", "⚠️ Fehler", f"Fehler in {event_method}")

# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)
