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
BOT_OWNER_ID = 662596869221908480 # Deine Nutzer-ID (für DM-Alerts)


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
EMBED_COLOR = discord.Color.from_rgb(0, 110, 255) # Dunkel Neon Blau
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
"""Sends a standardized embed to a destination.
destination can be a TextChannel, Member, User or InteractionResponse.
For interaction responses, call interaction.response.send_message(embed=...) directly.
"""
embed = discord.Embed(title=title, description=description, color=EMBED_COLOR, timestamp=datetime.now(timezone.utc))
# If destination is an InteractionResponse (we expect a discord.Interaction), use its response
try:
# typical destinations: discord.abc.Messageable (TextChannel, Member, User)
await destination.send(embed=embed)
except Exception as e:
# Fallback logging — we don't want the bot to crash if a DM or channel send fails
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
bot.run(TOKEN)
