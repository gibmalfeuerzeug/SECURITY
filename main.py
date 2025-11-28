import discord
from discord.ext import commands
from discord import app_commands
import os

OWNER_ID = 662596869221908480

intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

# ======================
# Embed Farbe (Blau)
# ======================
COLOR = discord.Color.blue()

# ======================
# Datenbanken (RAM-basiert)
# ======================
blacklist = set()
whitelist = set()

# ======================
# On Ready
# ======================
@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        print(f"Slash Commands synchronisiert: {len(synced)}")
    except Exception as e:
        print(e)

    await bot.change_presence(
        activity=discord.Game("discord.gg/trustgate")
    )
    print(f"Bot eingeloggt als {bot.user}")


# ============================
# Kategorie / Audit-Log Setup
# ============================
async def ensure_audit_channels(guild: discord.Guild):
    category = discord.utils.get(guild.categories, name="TRUST GATE")
    if category is None:
        category = await guild.create_category("TRUST GATE")

    log = discord.utils.get(guild.text_channels, name="tg-audit-log")
    if log is None:
        log = await guild.create_text_channel("tg-audit-log", category=category)

    return log


# =======================
# Benachrichtigung per DM
# =======================
@bot.event
async def on_guild_join(guild):
    user = bot.get_user(OWNER_ID)
    if user:
        embed = discord.Embed(
            title="Bot zu einem neuen Server hinzugefügt!",
            color=COLOR
        )
        embed.add_field(name="Servername", value=guild.name, inline=False)
        embed.add_field(name="Server ID", value=guild.id, inline=False)
        embed.add_field(name="Mitglieder", value=guild.member_count, inline=False)
        await user.send(embed=embed)

    await ensure_audit_channels(guild)


# =======================
# Anti‑Webhook & Anti‑Spam
# =======================
@bot.event
async def on_webhooks_update(channel):
    guild = channel.guild
    log = await ensure_audit_channels(guild)

    audit = await guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create).flatten()
    if audit:
        entry = audit[0]
        if entry.user.id not in whitelist:
            await entry.user.ban(reason="Webhook Erstellung ohne Whitelist")
            await log.send(embed=discord.Embed(
                title="❗ Webhook erstellt",
                description=f"**{entry.user}** wurde gebannt.",
                color=COLOR
            ))


# =======================
# Anti Role / Channel Delete
# =======================
@bot.event
async def on_guild_channel_delete(channel):
    guild = channel.guild
    log = await ensure_audit_channels(guild)

    audit = await guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete).flatten()
    if audit:
        entry = audit[0]
        if entry.user.id not in whitelist:
            await entry.user.ban(reason="Channel Delete ohne Whitelist")
            await log.send(embed=discord.Embed(
                title="❗ Channel gelöscht",
                description=f"**{entry.user}** wurde gebannt.",
                color=COLOR
            ))


@bot.event
async def on_guild_role_delete(role):
    guild = role.guild
    log = await ensure_audit_channels(guild)

    audit = await guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete).flatten()
    if audit:
        entry = audit[0]
        if entry.user.id not in whitelist:
            await entry.user.ban(reason="Rolle gelöscht ohne Whitelist")
            await log.send(embed=discord.Embed(
                title="❗ Rolle gelöscht",
                description=f"**{entry.user}** wurde gebannt.",
                color=COLOR
            ))


# =======================
# Anti Invite / Anti Everyone Spam
# =======================
@bot.event
async def on_message(msg):
    if msg.author.bot:
        return

    guild = msg.guild
    log = await ensure_audit_channels(guild)

    # Anti-Invite
    if "discord.gg/" in msg.content.lower():
        if msg.author.id not in whitelist:
            await msg.delete()
            await log.send(embed=discord.Embed(
                title="❗ Invite Link entfernt",
                description=f"{msg.author.mention} hat einen Invite gepostet.",
                color=COLOR
            ))
            return

    # @everyone / @here Spam
    if "@everyone" in msg.content or "@here" in msg.content:
        if msg.author.id not in whitelist:
            await msg.delete()
            await log.send(embed=discord.Embed(
                title="❗ Ping Spam blockiert",
                description=f"{msg.author.mention} wollte everyone/here erwähnen.",
                color=COLOR
            ))

    await bot.process_commands(msg)


# =======================
# Anti Bot Join
# =======================
@bot.event
async def on_member_join(member):
    if member.bot and member.id not in whitelist:
        await member.kick(reason="Bot Join Blockiert")


# =======================
# Anti Kick / Ban Spam
# =======================
@bot.event
async def on_member_remove(member):
    guild = member.guild
    log = await ensure_audit_channels(guild)
    audit = await guild.audit_logs(limit=1).flatten()

    if not audit:
        return

    entry = audit[0]
    if entry.action in [
        discord.AuditLogAction.kick,
        discord.AuditLogAction.ban
    ]:
        if entry.user.id not in whitelist:
            await entry.user.ban(reason="Kick/Ban Spam")
            await log.send(embed=discord.Embed(
                title="❗ Kick/Ban Spam erkannt",
                description=f"**{entry.user}** wurde gebannt.",
                color=COLOR
            ))


# =======================
# Slash Commands
# =======================

# /help
@bot.tree.command(name="help", description="Zeigt alle Befehle")
async def help_cmd(interaction: discord.Interaction):
    embed = discord.Embed(
        title="TrustGate – Hilfe",
        color=COLOR
    )
    embed.add_field(name="/blacklist add <ID>", value="Nutzer zur Blacklist hinzufügen", inline=False)
    embed.add_field(name="/blacklist remove <ID>", value="Nutzer von Blacklist entfernen", inline=False)
    embed.add_field(name="/whitelist add <ID>", value="Nutzer whitelisten", inline=False)
    embed.add_field(name="/whitelist remove <ID>", value="Nutzer von Whitelist entfernen", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


# Blacklist hinzufügen
@bot.tree.command(name="blacklist")
@app_commands.describe(action="add/remove", user_id="User ID")
async def blacklist_cmd(interaction: discord.Interaction, action: str, user_id: str):
    if interaction.user.id != OWNER_ID:
        return await interaction.response.send_message("Nur Owner!", ephemeral=True)

    uid = int(user_id)

    if action == "add":
        blacklist.add(uid)
        await interaction.response.send_message(f"User `{uid}` zur Blacklist hinzugefügt!", ephemeral=True)

    elif action == "remove":
        blacklist.discard(uid)
        await interaction.response.send_message(f"User `{uid}` von Blacklist entfernt!", ephemeral=True)


# Whitelist hinzufügen
@bot.tree.command(name="whitelist")
@app_commands.describe(action="add/remove", user_id="User ID")
async def whitelist_cmd(interaction: discord.Interaction, action: str, user_id: str):
    if interaction.user.id != OWNER_ID:
        return await interaction.response.send_message("Nur Owner!", ephemeral=True)

    uid = int(user_id)

    if action == "add":
        whitelist.add(uid)
        await interaction.response.send_message(f"User `{uid}` zur Whitelist hinzugefügt!", ephemeral=True)

    elif action == "remove":
        whitelist.discard(uid)
        await interaction.response.send_message(f"User `{uid}` von Whitelist entfernt!", ephemeral=True)


# =======================
# Start
# =======================
bot.run(os.getenv("TOKEN"))
