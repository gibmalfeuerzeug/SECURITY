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

# Invite-Settings
INVITE_SPAM_WINDOW_SECONDS = 30
INVITE_SPAM_THRESHOLD = 5
INVITE_TIMEOUT_HOURS = 1

# Anti-Webhook Settings
WEBHOOK_STRIKES_BEFORE_KICK = 3

# Anti Ban/Kick Spamm Settings
ANTI_BAN_KICK_WINDOW_SECONDS = 30
ANTI_BAN_KICK_THRESHOLD = 3

# Anti Mention Spam Settings
MENTION_SPAM_WINDOW_SECONDS = 15
MENTION_SPAM_THRESHOLD = 3

VERBOSE = True

# ---------- Bot & Intents ----------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True
intents.bans = True
intents.webhooks = True
intents.guild_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- Hilfsfunktionen ----------
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

def log(*args):
    if VERBOSE:
        print("[LOG]", *args)

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
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Timeout failed for {member}: {e}")

async def actor_from_audit_log(guild: discord.Guild, action: AuditLogAction, target_id: int | None = None, within_seconds: int = 15):
    await asyncio.sleep(0.45)
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

# ---------- Events ----------
@bot.event
async def on_ready():
    log(f"Bot online als {bot.user} (ID: {bot.user.id})")
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Game("Bereit zum Beschützen!")
    )

    # Globale Synchronisierung aller Slash Commands
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
