#!/usr/bin/env python3
"""
Telegram Bot — Bug Bounty Source Code Monitor (resident mode)
Best-effort long-polling: restarts ~every 5.5h via GitHub Actions, gaps happen.
Replies are fast when alive, NOT guaranteed 24/7 single-process instant.
Data: state.json + changes_log.json written by monitor.py.
/refresh runs monitor.py inline — no PAT needed.
Blunt rules: timestamps = detection time; H1 amounts unknown; Chaos = no scope.
"""

import html, json, os, signal, subprocess, sys, threading, time, traceback
from datetime import datetime, timezone
from typing import List, Optional
import requests

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
ANNOUNCE         = os.environ.get("ANNOUNCE", "") == "1"
BOT_MAX_MINUTES  = int(os.environ.get("BOT_MAX_MINUTES", "330"))  # graceful exit before job timeout

OFFSET_FILE  = "bot_offset.json"
STATE_FILE   = "state.json"
CHANGES_FILE = "changes_log.json"
API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

BOT_STARTED_AT = time.time()
MONITOR_INTERVAL = 30 * 60          # best-effort ~30 min; cron delays + restarts happen
LAST_MONITOR_AT  = time.time() - (MONITOR_INTERVAL - 120)  # first cycle ~2 min after boot

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡",
                   "federacy":"🟣","chaos":"🌍",
                   "hackenproof":"🟠","immunefi":"💠","cantina":"🍷","sherlock":"🔍"}
PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy",
             "hackenproof", "immunefi", "cantina", "sherlock", "other"]
BLOCKCHAIN_PLATFORMS = {"hackenproof", "immunefi", "cantina", "sherlock"}
EVENT_EMOJI = {
    "new_program":"🆕", "scope_added":"📦",
    "scope_updated":"🔄", "bounty_enabled":"💰", "new_external":"🌍",
    "new_repo":"🐙",
}

PREFS_FILE   = "prefs.json"
BLOCKED_FILE = "blocked.json"

# ── Abuse controls (in-memory sliding windows; blocklist persisted) ──────────
CMD_HITS: dict = {}        # chat_id -> [timestamps] general commands
REFRESH_HITS: dict = {}    # chat_id -> [timestamps] /refresh uses
LAST_REFRESH_AT = 0.0      # global /refresh cooldown timestamp
CMD_LIMIT = 20             # cmds per CMD_WINDOW per chat
CMD_WINDOW = 60.0
REFRESH_GLOBAL_COOLDOWN = 15 * 60   # 1 refresh per 15 min globally
REFRESH_USER_COOLDOWN = 60 * 60     # 1 refresh per hour per public user
USAGE: dict = {}           # cmd -> count (this process lifetime)

# ── Utils ──────────────────────────────────────────────────────────────────────

def esc(s) -> str:
    return html.escape(str(s or ""), quote=False)

def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default

def save_json(path, data):
    """Atomic write (tmp + fsync + replace): a SIGTERM/timeout kill can never
    leave a half-written JSON file behind (that used to corrupt offset/prefs
    and wedge the next run)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

# ── Crash-loop circuit breaker + graceful shutdown ──────────────────────────
_SHUTDOWN = False          # set by SIGTERM/SIGINT handler → exit at next checkpoint
_CONFLICT_STREAK = 0       # consecutive Telegram 409s (another poller alive)
_HEALED_CONFLICT = False   # deleteWebhook attempted once per process

def _on_term(signum, frame):
    global _SHUTDOWN
    print(f"\n  ⚠ signal {signum} — finishing current batch, then exiting gracefully")
    _SHUTDOWN = True

def get_programs(state: dict) -> dict:
    return {k: v for k, v in state.items() if k != "_meta"}

def qualifying(programs: dict) -> dict:
    return {k: v for k, v in programs.items()
            if k.split(":",1)[0] != "chaos" and v.get("bounty") and v.get("source")}

def externals(programs: dict) -> dict:
    return {k: v for k, v in programs.items() if k.split(":",1)[0] == "chaos"}

def blockchains(programs: dict) -> dict:
    return {k: v for k, v in programs.items()
            if v.get("platform") in BLOCKCHAIN_PLATFORMS}

def fmt_ts(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %H:%M UTC")
    except Exception:
        return iso or "?"

def fmt_when(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        now = datetime.now(timezone.utc) if dt.tzinfo else datetime.utcnow()
        secs = (now - dt).total_seconds()
        if secs < 0: secs = 0
        if secs < 60:    return "just now"
        if secs < 3600:  return f"{int(secs//60)}m ago"
        if secs < 86400: return f"{int(secs//3600)}h ago"
        return f"{int(secs//86400)}d ago"
    except Exception:
        return "?"

def uptime() -> str:
    s = int(time.time() - BOT_STARTED_AT)
    h, m = s // 3600, (s % 3600) // 60
    return f"{h}h {m}m" if h else f"{m}m"

def is_owner(chat_id) -> bool:
    return not TELEGRAM_CHAT_ID or str(chat_id) == str(TELEGRAM_CHAT_ID)

def is_blocked(chat_id) -> bool:
    try:
        blocked = load_json(BLOCKED_FILE, {"blocked": []}).get("blocked", [])
        return str(chat_id) in {str(x) for x in blocked}
    except Exception:
        return False

def _prune(hits: list, window: float) -> list:
    now = time.time()
    return [t for t in hits if now - t < window]

def check_rate(chat_id) -> Optional[str]:
    """General per-chat rate limit. Returns warning text or None if allowed."""
    if is_owner(chat_id):
        return None
    now = time.time()
    hits = _prune(CMD_HITS.get(str(chat_id), []), CMD_WINDOW)
    if len(hits) >= CMD_LIMIT:
        return f"⏳ Too fast — max {CMD_LIMIT} commands per minute. Try again shortly."
    hits.append(now)
    CMD_HITS[str(chat_id)] = hits
    return None

def check_refresh_rate(chat_id) -> Optional[str]:
    """Strict cooldown for /refresh. Returns wait text or None if allowed."""
    global LAST_REFRESH_AT
    now = time.time()
    if not is_owner(chat_id):
        if now - LAST_REFRESH_AT < REFRESH_GLOBAL_COOLDOWN:
            wait = int((REFRESH_GLOBAL_COOLDOWN - (now - LAST_REFRESH_AT)) // 60) + 1
            return (f"⏳ Refresh cooldown — auto-refresh is best-effort ~30 min (often delayed). "
                    f"Try again in ~{wait}m. Owner can force it anytime.")
        uhits = _prune(REFRESH_HITS.get(str(chat_id), []), REFRESH_USER_COOLDOWN)
        if uhits:
            wait = int((REFRESH_USER_COOLDOWN - (now - uhits[0])) // 60) + 1
            return f"⏳ You already forced a refresh recently. Try again in ~{wait}m."
        uhits.append(now)
        REFRESH_HITS[str(chat_id)] = uhits
    LAST_REFRESH_AT = now
    return None

def get_prefs() -> dict:
    return load_json(PREFS_FILE, {})

def save_prefs(prefs: dict):
    save_json(PREFS_FILE, prefs)

def get_digest(chat_id) -> str:
    return get_prefs().get(str(chat_id), {}).get("digest", "off")

def fmt_bounty(v) -> str:
    """None/0-safe money format: 15000 → '15,000'."""
    try:
        v = int(v or 0)
        return f"{v:,}" if v else ""
    except Exception:
        return ""

def bounty_line(v: dict) -> str:
    """Blunt: HackerOne feed has NO amounts — never imply a range we don't have."""
    if not v.get("bounty"):
        return "💰 Bounty: ❌ no monetary rewards (per feed)"
    ccy = (v.get("bounty_ccy") or "").replace("USD", "$").replace("EUR", "€").replace("GBP", "£")
    if not ccy:
        ccy = "$" if not v.get("bounty_ccy") else v.get("bounty_ccy") + " "
    lo, hi = fmt_bounty(v.get("bounty_min")), fmt_bounty(v.get("bounty_max"))
    if lo and hi:
        return f"💰 Bounty: ✅ {ccy}{lo} – {ccy}{hi}"
    if hi:
        return f"💰 Bounty: ✅ up to {ccy}{hi}"
    if lo:
        return f"💰 Bounty: ✅ from {ccy}{lo}"
    if (v.get("platform") == "hackerone"):
        return "💰 Bounty: ✅ yes (HackerOne feed publishes NO amounts — check program page)"
    return "💰 Bounty: ✅ yes (amount not in feed — check program page)"

# ── Command handlers (pure: return reply text) ────────────────────────────────

def cmd_start(args, state, changes) -> str:
    return (
        "👋 <b>Bug Bounty Monitor Bot</b>\n\n"
        "Blunt scope — I watch <b>9 feeds + 1 index, nothing else</b>:\n"
        "  🟢 HackerOne · 🔴 Bugcrowd · 🔵 Intigriti\n"
        "  🟡 YesWeHack · 🟣 Federacy (scope text analysis)\n"
        "  ⛓️ Blockchain: 🟠 HackenProof · 💠 Immunefi · 🍷 Cantina · 🔍 Sherlock\n"
        "  🌍 Chaos index — program names/URLs only, NO scope detail\n\n"
        "What counts as “source code”: explicit SC asset type OR a\n"
        "github/gitlab/bitbucket URL in the target. On blockchain feeds,\n"
        "smart-contract scope counts too. Description mentions\n"
        "alone do NOT count.\n\n"
        "🔔 Instant alerts go to the <b>owner channel only</b>. You get:\n"
        "  • /latest /changes — what I detected + when I detected it\n"
        "  • /blockchain — ⛓️ blockchain bounties only (ranked by max payout)\n"
        "  • /digest daily|weekly — rolling 24h / 7d summaries (not fixed clock)\n"
        "  • /diff /scope /export — scope detail for tracked programs\n\n"
        "⚠️ Timestamps are <b>detection time, not launch time</b>. "
        "Best-effort ~30 min; GitHub cron + restarts delay it. "
        "HackerOne amounts are NOT in the feed (yes/no only). "
        "Full source removal is NOT alerted — program just drops out.\n\n"
        "📰 /digest daily for summaries · 📖 /help for everything"
    )

def cmd_help(args, state, changes) -> str:
    return (
        "🤖 <b>Commands</b>\n\n"
        "📊 <b>Info</b>\n"
        "  /status — Monitor health &amp; last run\n"
        "  /stats — Program statistics\n"
        "  /sources — Data sources I watch\n\n"
        "🔔 <b>Activity</b>\n"
        "  /latest — Last 5 changes\n"
        "  /new — Recently added programs\n"
        "  /changes — Last 15 changes\n\n"
        "🔎 <b>Search</b>\n"
        "  /search &lt;query&gt; — Search programs &amp; repos\n"
        "     e.g. /search wordpress · /search svg\n"
        "  /scope &lt;program&gt; — Show a program's source-code scope\n"
        "     e.g. /scope automattic\n\n"
        "🗂 <b>Browse</b>\n"
        "  /platform — Counts per platform\n"
        "  /platform &lt;name&gt; — hackerone | bugcrowd | intigriti | yeswehack | federacy\n"
        "     hackenproof | immunefi | cantina | sherlock | other\n"
        "  /blockchain — ⛓️ Blockchain bounties only (/blockchain uniswap)\n"
        "  /source — Programs with SOURCE_CODE scope assets\n"
        "  /github — Programs with GitHub repos in scope\n"
        "  /top — 🏆 Rough ranking (H1-biased, read caveats)\n"
        "  /fresh — 🆕 Detected last 7d (/fresh 30)\n"
        "  /repos — 🐙 GitHub repos in scope\n\n"
        "🔄 <b>Intel</b>\n"
        "  /diff &lt;program&gt; — Added/removed scope targets\n"
        "  /export &lt;program&gt; — Recon .txt file (classic + blockchain)\n\n"
        "⚙️ <b>Control</b>\n"
        "  /refresh — Force a data refresh now\n"
        "  /digest daily|weekly|off — Summary mode (rolling 24h/7d)\n"
        "  /settings — Your settings\n\n"
        "⚠️ Best-effort ~30 min refresh; GitHub cron + restarts delay it.\n"
        "⚠️ Times are DETECTION time, not launch time. Instant alerts → owner channel only."
    )

def cmd_status(args, state, changes) -> str:
    meta = state.get("_meta", {})
    programs = get_programs(state)
    if not programs and not meta:
        return "⚠️ No data yet — the monitor hasn't run. Send /refresh to force it now."
    stale = meta.get("stale", []) or []
    fetch_ok = meta.get("fetch_ok", {}) or {}
    health = "🟢 fresh" if not stale else f"🟡 STALE: {', '.join(stale)} (carried over, no events that cycle)"
    lines = [
        "🟢 <b>Monitor Status</b>", "",
        f"🕒 Last write        : {fmt_when(meta.get('updated_at',''))} ({fmt_ts(meta.get('updated_at',''))})",
        f"📦 Total programs    : {meta.get('total', len(programs))}",
        f"💰 Bounty + source   : {meta.get('qualifying', len(qualifying(programs)))}",
        f"⛓️ Blockchain bounty : {meta.get('blockchain', sum(1 for v in blockchains(programs).values() if v.get('bounty') and v.get('source')))}",
        f"🌍 Worldwide watch   : {meta.get('external', len(externals(programs)))}",
        f"📜 Changes logged    : {len(changes)}",
        f"🤖 Bot uptime        : {uptime()} (resets every ~5.5h restart — not 24/7 single process)",
        f"📡 Feed health       : {health}",
        "", "⚠️ 'Last write' = file write, not proof all feeds succeeded. See feed health.",
        "⚠️ Refreshes best-effort ~30 min (cron delays + restarts happen).",
    ]
    if fetch_ok:
        detail = ", ".join(f"{p}:{'ok' if ok else 'STALE'}" for p, ok in sorted(fetch_ok.items()))
        lines.append(f"   {detail}")
    return "\n".join(lines)

def cmd_stats(args, state, changes) -> str:
    programs = get_programs(state)
    if not programs:
        return "⚠️ No data yet — send /refresh to force the first run."
    qual = qualifying(programs)
    ext = externals(programs)
    lines = ["📊 <b>Statistics</b>", "",
             f"📦 Total programs   : {len(programs)}",
             f"💰 Bounty + source  : {len(qual)}",
             f"🌍 Worldwide        : {len(ext)}", "",
             "<b>Per platform</b>  <i>(bounty+SC / total)</i>"]
    for p in PLATFORMS[:-1]:
        tot = sum(1 for k, v in programs.items() if v.get("platform") == p)
        q   = sum(1 for k, v in qual.items()      if v.get("platform") == p)
        lines.append(f"{PLATFORM_EMOJI.get(p,'⚪')} {p:12s} {q:3d} / {tot}")
    bc = sum(1 for v in qual.values() if v.get("platform") in BLOCKCHAIN_PLATFORMS)
    lines.append(f"⛓️ {'blockchain':12s} {bc:3d}     (🟠💠🍷🔍 subtotal — see /blockchain)")
    lines.append(f"🌍 {'other':12s} {len(ext):3d}   / {len(ext)}")
    hosts = {"github.com": 0, "gitlab.com": 0, "bitbucket.org": 0}
    for v in qual.values():
        for t in v.get("sc_targets", []):
            ident = (t.get("identifier") or "").lower()
            for h in hosts:
                if h in ident:
                    hosts[h] += 1
                    break
    lines += ["", "<b>Repo hosts in scope</b>",
              f"  GitHub    : {hosts['github.com']}",
              f"  GitLab    : {hosts['gitlab.com']}",
              f"  Bitbucket : {hosts['bitbucket.org']}"]
    return "\n".join(lines)

def cmd_sources(args, state, changes) -> str:
    return (
        "📡 <b>Data Sources — blunt version</b>\n\n"
        "<b>Classic scope feeds</b> (best-effort ~30 min)\n"
        "  arkadiyt/bounty-targets-data:\n"
        "  🟢 HackerOne · 🔴 Bugcrowd · 🔵 Intigriti\n"
        "  🟡 YesWeHack · 🟣 Federacy\n"
        "  → per-target scope: bounty flag + strict SC check\n"
        "  (SC asset type OR github/gitlab/bitbucket URL — nothing else)\n\n"
        "<b>⛓️ Blockchain feeds</b> (best-effort, slower — detail pages)\n"
        "  🟠 HackenProof — sitemap + program pages\n"
        "    (smart-contract scope, USD max, LIVE/PAUSED/ENDED)\n"
        "  💠 Immunefi — public-api/bounties.json\n"
        "    (per-asset scope incl. chain, max bounty + token)\n"
        "  🍷 Cantina — sitemap + bounty pages\n"
        "    (GitHub scope refs, USDC reward pot, live/ended)\n"
        "  🔍 Sherlock — sitemap + bug-bounty pages\n"
        "    (Max Rewards USDC, in-scope contract names)\n"
        "  → smart-contract scope counts as source here\n"
        "  → /blockchain for the blockchain-only view\n\n"
        "<b>Worldwide index</b> (program-level ONLY)\n"
        "  🌍 ProjectDiscovery Chaos index:\n"
        "  → names + URLs + bounty flag. NO scope detail.\n"
        "  → origin field (hackenproof/direct/…) is whatever Chaos says\n\n"
        "⚠️ NOT covered: private programs, Synack/Cobalt, anything\n"
        "outside these 10 feeds. HackerOne amounts are NOT in the feed.\n"
        "⚠️ Times are detection time, not launch time."
    )

def _changes_list(changes: list, n: int, event_filter: Optional[str] = None) -> str:
    items = [c for c in changes if event_filter is None or c.get("event") == event_filter]
    if not items:
        return "🌿 No changes logged yet — baseline only. New activity will appear here."
    lines = [f"📜 <b>Last {min(n, len(items))} detected change(s)</b> — {len(items)} total",
             "<i>Times = when I detected it, NOT when it launched</i>", ""]
    for c in reversed(items[-n:]):
        e = EVENT_EMOJI.get(c.get("event"), "🔔")
        plat = c.get("platform", "?")
        lines.append(f"{e} <b>{esc(c.get('name'))}</b>")
        lines.append(f"   {PLATFORM_EMOJI.get(plat,'⚪')} {plat} · detected {fmt_when(c.get('timestamp',''))} ({fmt_ts(c.get('timestamp',''))})")
        added = c.get("added", []) or []
        removed = c.get("removed", []) or []
        if added:
            lines.append(f"   ➕ {esc(added[0])}" + (f" <i>+{len(added) - 1} more</i>" if len(added) > 1 else ""))
        if removed:
            lines.append(f"   ➖ {esc(removed[0])}" + (f" <i>+{len(removed) - 1} more</i>" if len(removed) > 1 else ""))
        lines.append(f"   {esc(c.get('url',''))}")
        lines.append("")
    return "\n".join(lines).rstrip()

def cmd_latest(args, state, changes) -> str:
    return _changes_list(changes, 5)

def cmd_changes(args, state, changes) -> str:
    return _changes_list(changes, 15)

def cmd_new(args, state, changes) -> str:
    items = [c for c in changes if c.get("event") in ("new_program", "new_external")]
    if not items:
        return "🌿 No new programs detected yet. Detection runs best-effort ~30 min."
    out = _changes_list(items, 10)
    return out.replace("change(s)", "new program(s)")

def cmd_search(args, state, changes) -> str:
    if not args:
        return "🔎 Usage: <code>/search &lt;query&gt;</code>\ne.g. <code>/search wordpress</code>"
    q = args.lower()
    programs = get_programs(state)
    name_hits, repo_hits, ext_hits = [], [], []
    for k, v in programs.items():
        is_ext = k.split(":", 1)[0] == "chaos"
        if q in (v.get("name","").lower()) or q in (k.split(":",1)[-1].lower()):
            (ext_hits if is_ext else name_hits).append(v)
            continue
        if is_ext: continue
        if not (v.get("bounty") and v.get("source")): continue
        for t in v.get("sc_targets", []):
            if q in (t.get("identifier","").lower()) or q in (t.get("description","").lower()):
                repo_hits.append((v, t)); break
    total = len(name_hits) + len(repo_hits) + len(ext_hits)
    if total == 0:
        return f"🔍 No matches for <b>{esc(args)}</b>.\nTry /platform to browse, or /source &amp; /github."
    lines = [f"🔎 <b>Results for \"{esc(args)}\"</b> — {total} match(es)",
             "<i>Bounty+source filter applies to repo hits; name hits show all</i>", ""]
    shown = 0
    for v in name_hits[:10]:
        plat = v.get("platform","?")
        hi = fmt_bounty(v.get("bounty_max"))
        c = (v.get("bounty_ccy") or "").replace("USD","$").replace("EUR","€").replace("GBP","£") or "$"
        if hi:
            extra = f"  💸 up to {c}{hi}"
        elif v.get("bounty"):
            extra = "  💸 bounty yes (amount not in feed)"
        else:
            extra = "  💸 no bounty"
        lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>{extra}")
        lines.append(f"   {esc(v.get('url',''))}")
        shown += 1
    for v, t in repo_hits[:max(0, 10 - shown)]:
        plat = v.get("platform","?")
        lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>")
        lines.append(f"   📁 <code>{esc(t.get('identifier'))}</code>")
        shown += 1
    for v in ext_hits[:max(0, 10 - shown)]:
        lines.append(f"🌍 <b>{esc(v.get('name'))}</b> <i>({esc(v.get('origin','direct'))} — no scope data)</i>")
        lines.append(f"   {esc(v.get('url',''))}")
    if total > 10:
        lines.append(f"\n… and {total - 10} more — refine your query")
    hint = (name_hits or ([repo_hits[0][0]] if repo_hits else ([ext_hits[0]] if ext_hits else [])))
    if hint:
        first_word = (hint[0].get("name","") or "?").split()[0]
        lines.append(f"\n💡 Full scope: /scope {esc(first_word)}")
    return "\n".join(lines)

def cmd_platform(args, state, changes) -> str:
    programs = get_programs(state)
    qual = qualifying(programs)
    if not args:
        lines = ["🗂 <b>Programs per platform</b>  <i>(bounty+SC / total)</i>", ""]
        for p in PLATFORMS[:-1]:
            tot = sum(1 for v in programs.values() if v.get("platform") == p)
            q   = sum(1 for k, v in qual.items() if v.get("platform") == p)
            lines.append(f"{PLATFORM_EMOJI.get(p,'⚪')} <b>{p}</b> — {q} / {tot}")
        lines.append(f"🌍 <b>other (worldwide)</b> — {len(externals(programs))}")
        lines.append("\nUsage: <code>/platform hackerone</code>")
        return "\n".join(lines)
    p = args.lower().strip()
    if p in ("other", "worldwide", "direct", "external"):
        ext = sorted(externals(programs).values(), key=lambda v: (v.get("origin",""), v.get("name","").lower()))
        if not ext:
            return "🌍 No worldwide programs tracked yet."
        lines = [f"🌍 <b>Worldwide programs (Chaos index, program-level only)</b> — {len(ext)}", "<i>No scope detail — check program page. Origin = whatever Chaos says.</i>", ""]
        for v in ext[:20]:
            lines.append(f"• <b>{esc(v.get('name'))}</b> — {esc(v.get('origin','direct'))}\n  {esc(v.get('url',''))}")
        if len(ext) > 20:
            lines.append(f"\n… and {len(ext)-20} more — use /search to narrow down")
        return "\n".join(lines)
    if p not in PLATFORM_EMOJI:
        return (f"⚠️ Unknown platform \"{esc(args)}\"\n"
                f"Choose: {' · '.join(PLATFORMS)}")
    entries = sorted((v for k, v in programs.items()
                      if v.get("platform") == p and k.split(":",1)[0] != "chaos"
                      and v.get("bounty") and v.get("source")),
                     key=lambda v: v.get("name","").lower())
    if not entries:
        return f"{PLATFORM_EMOJI[p]} No bounty+source programs on {p} right now."
    lines = [f"{PLATFORM_EMOJI[p]} <b>{p.capitalize()}</b> — {len(entries)} bounty+source program(s)", ""]
    for v in entries[:20]:
        lines.append(f"• <b>{esc(v.get('name'))}</b>\n  {esc(v.get('url',''))}")
    if len(entries) > 20:
        lines.append(f"\n… and {len(entries)-20} more — use /search to narrow down")
    return "\n".join(lines)

def cmd_source(args, state, changes) -> str:
    programs = get_programs(state)
    hits = []
    for k, v in qualifying(programs).items():
        assets = [t for t in v.get("sc_targets", [])
                  if (t.get("asset_type") or "").upper() in SOURCE_CODE_ASSET_TYPES]
        if assets:
            hits.append((v, assets))
    if not hits:
        return "📁 No programs with explicit SOURCE_CODE asset types right now.\nTry /github for repo-URL matches."
    lines = [f"📁 <b>Programs with SOURCE_CODE scope assets</b> — {len(hits)}", ""]
    for v, assets in sorted(hits, key=lambda x: x[0].get("name","").lower())[:15]:
        plat = v.get("platform","?")
        ident = assets[0].get("identifier") or "(unnamed)"
        more = f" <i>+{len(assets)-1} more</i>" if len(assets) > 1 else ""
        lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>{more}")
        lines.append(f"   <code>{esc(ident)}</code>")
    if len(hits) > 15:
        lines.append(f"\n… and {len(hits)-15} more")
    return "\n".join(lines)

def cmd_github(args, state, changes) -> str:
    programs = get_programs(state)
    hits = []
    for v in qualifying(programs).values():
        repos = [t for t in v.get("sc_targets", [])
                 if "github.com/" in (t.get("identifier") or "").lower()]
        if repos:
            hits.append((v, repos))
    if not hits:
        return "🐙 No programs with GitHub repos in scope right now."
    lines = [f"🐙 <b>Programs with GitHub repos in scope</b> — {len(hits)}", ""]
    for v, repos in sorted(hits, key=lambda x: x[0].get("name","").lower())[:15]:
        plat = v.get("platform","?")
        repo = repos[0].get("identifier") or "?"
        more = f" <i>+{len(repos)-1} more</i>" if len(repos) > 1 else ""
        lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>{more}")
        lines.append(f"   <code>{esc(repo)}</code>")
    if len(hits) > 15:
        lines.append(f"\n… and {len(hits)-15} more")
    return "\n".join(lines)

def cmd_scope(args, state, changes) -> str:
    if not args:
        return "🔎 Usage: <code>/scope &lt;program&gt;</code>\ne.g. <code>/scope automattic</code>"
    q = args.lower()
    programs = get_programs(state)
    matches = [v for k, v in programs.items()
               if q in (v.get("name","").lower()) or q in (k.split(":",1)[-1].lower())]
    if not matches:
        return f"🔍 No program found matching \"{esc(args)}\".\nTry /search {esc(args)}"
    v = matches[0]
    if v.get("platform") == "chaos":
        return (f"🌍 <b>{esc(v.get('name'))}</b> — worldwide ({esc(v.get('origin','direct'))})\n\n"
                f"🔗 {esc(v.get('url',''))}\n\n"
                f"ℹ️ No scope detail in the worldwide index — check the program page.")
    if len(matches) > 1 and not all(m.get("name") == v.get("name") for m in matches[:5]):
        names = sorted({m.get("name","") for m in matches})[:10]
        more = f"\n… and {len(matches)-10} more" if len(matches) > 10 else ""
        return ("🔍 Multiple matches — be more specific:\n\n"
                + "\n".join(f"• {esc(n)}" for n in names) + more)
    plat = v.get("platform","?")
    sc = v.get("sc_targets", [])
    sc_total = v.get("sc_total", len(sc))
    lines = [
        f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b> — {plat}", "",
        f"🔗 {esc(v.get('url',''))}",
        bounty_line(v),
    ]
    if plat in BLOCKCHAIN_PLATFORMS and v.get("live_status"):
        lines.append(f"⛓️ Status: {esc(v.get('live_status'))} (blockchain feed — pause/end flips alert like bounty)")
    lines += ["", f"📁 <b>Source-code targets ({sc_total} total, showing {len(sc)}):</b>"]
    for t in sc:
        lines.append(f"  • <code>{esc(t.get('identifier'))}</code>  [{esc(t.get('asset_type'))}]")
    if not sc:
        lines.append("  (none detected — strict check: SC asset type or repo-host URL only)")
    if sc_total > len(sc):
        lines.append(f"  <i>… truncated: showing {len(sc)} of {sc_total}. /export for full sc_ids list.</i>")
        for sid in (v.get("sc_ids", []) or [])[len(sc):][:10]:
            lines.append(f"  • <code>{esc(sid)}</code>  [id-only]")
    return "\n".join(lines)

def cmd_refresh(args, state, changes, chat_id=None) -> str:
    """Runs monitor.py inline — no PAT needed. Strict cooldown for public users."""
    wait = check_refresh_rate(chat_id)
    if wait:
        return wait
    is_own = is_owner(chat_id)
    if not is_own:
        print(f"  [/refresh] public user {chat_id} — allowed (cooldown passed)")
    print("  [/refresh] running monitor.py …")
    try:
        env = dict(os.environ, MONITOR_BUDGET_SEC="240")  # must finish < timeout
        r = subprocess.run([sys.executable, "monitor.py"],
                           capture_output=True, text=True, timeout=300, env=env)
    except Exception as e:
        return f"⚠️ Refresh failed to start: {esc(e)}"
    if r.returncode != 0:
        tail = (r.stdout or "") + (r.stderr or "")
        return f"⚠️ Monitor exited with error:\n<code>{esc(tail[-400:])}</code>"
    # monitor already sent any change notifications itself
    meta = load_json(STATE_FILE, {}).get("_meta", {})
    ext_q = meta.get("external", "?")
    stale = meta.get("stale", []) or []
    stale_note = "" if not stale else f"\n⚠️ STALE this cycle: {', '.join(stale)} (carried over)"
    return ("🔄 <b>Refresh attempted (best-effort)</b>\n\n"
            f"💰 Bounty + source : {meta.get('qualifying','?')}\n"
            f"⛓️ Blockchain      : {meta.get('blockchain','?')}\n"
            f"🌍 Worldwide       : {ext_q}\n"
            f"📦 Total programs  : {meta.get('total','?')}{stale_note}\n\n"
            f"🕒 Wrote {fmt_ts(meta.get('updated_at',''))} — /latest shows DETECTED changes")

def cmd_top(args, state, changes) -> str:
    """Blunt ranking: signals are HackerOne-heavy. No researcher counts exist."""
    programs = get_programs(state)
    qual = list(qualifying(programs).values())
    if not qual:
        return ("🏆 Nothing qualifying right now.\n"
                "Try /refresh then /top again.")
    def score(v):
        d  = v.get("domains") or 0
        ef = v.get("resp_eff") or 0
        bd = v.get("bounty_days")
        speed = max(0.0, 100.0 - min(bd, 100)) if isinstance(bd, (int, float)) else 0.0
        return d * 2 + ef + speed   # surface dominates, triage breaks ties
    ranked = sorted(qual, key=score, reverse=True)
    h1_count = sum(1 for v in ranked[:10] if v.get("platform") == "hackerone")
    lines = [
        "🏆 <b>Top opportunities (rough proxy, NOT crowding data)</b>", "",
        "<i>Blunt: no platform publishes researcher counts. Ranked by: "
        "Chaos domain count + HackerOne triage% + payout speed. "
        "Only HackerOne has triage/speed — other platforms almost always "
        "score lower through no fault of their own.</i>", "",
    ]
    if h1_count >= 8:
        lines.append(f"<i>Heads-up: {h1_count}/10 below are HackerOne for that reason.</i>")
        lines.append("")
    for i, v in enumerate(ranked[:10], 1):
        plat = v.get("platform","?")
        parts = []
        if v.get("domains"):
            parts.append(f"🌐 {v['domains']:,} domains (Chaos name-match, may be 0/mismatched)")
        else:
            parts.append("🌐 domains unknown")
        if v.get("resp_eff"):
            parts.append(f"⚡ {int(v['resp_eff'])}% triage (H1 only)")
        else:
            parts.append("⚡ triage n/a (non-H1)")
        if isinstance(v.get("bounty_days"), (int, float)):
            parts.append(f"💸 bounty ~{int(v['bounty_days'])}d (H1 only)")
        hi = fmt_bounty(v.get("bounty_max"))
        if hi:
            c = (v.get("bounty_ccy") or "").replace("USD","$").replace("EUR","€") or "$"
            parts.append(f"{c}{hi} max")
        else:
            parts.append("bounty amount not in feed" if v.get("bounty") else "no bounty")
        lines.append(f"{i}. {PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>")
        lines.append(f"   {' · '.join(parts)}")
        lines.append(f"   {esc(v.get('url',''))}")
        lines.append("")
    lines.append("💡 /scope &lt;name&gt; for scope detail (truncated, see note there)")
    lines.append("💡 Blockchain bounties rank by max payout under /blockchain, not here")
    return "\n".join(lines).rstrip()

def send_document(chat_id: int, filename: str, content: str, caption: str = "") -> bool:
    """Send a text file as a Telegram document (for /export)."""
    try:
        r = requests.post(
            f"{API}/sendDocument",
            data={"chat_id": chat_id,
                  "caption": caption[:900],
                  "disable_notification": False},
            files={"document": (filename, content.encode("utf-8"), "text/plain")},
            timeout=30)
        if r.status_code == 429:
            time.sleep(r.json().get("parameters", {}).get("retry_after", 15))
            return send_document(chat_id, filename, content, caption)
        return bool(r.ok)
    except Exception as e:
        print(f"  ✗ sendDocument: {e}")
        return False

def reply_result(chat_id: int, result) -> bool:
    """Send a handler result: tuple (filename, content, caption) → document."""
    if isinstance(result, tuple) and len(result) == 3:
        filename, content, caption = result
        ok = send_document(chat_id, filename, content, caption)
        if not ok:
            send_reply(chat_id, "⚠️ File send failed — here's a preview:\n\n"
                       + esc(content[:3000]))
        return ok
    return send_reply(chat_id, result)

def _find_program(args: str, programs: dict):
    q = (args or "").lower().strip()
    if not q:
        return None, []
    matches = [v for k, v in programs.items()
               if q in (v.get("name", "").lower()) or q in (k.split(":", 1)[-1].lower())]
    if not matches:
        return None, []
    return matches[0], matches

def cmd_diff(args, state, changes) -> str:
    """Show what actually changed in a program's scope (added/removed targets)."""
    programs = get_programs(state)
    v, matches = _find_program(args, programs)
    if not v:
        return ("🔎 Usage: <code>/diff &lt;program&gt;</code>\n"
                "e.g. <code>/diff netflix</code> — shows added/removed scope targets")
    if v.get("platform") == "chaos":
        return (f"🌍 <b>{esc(v.get('name'))}</b> — worldwide index has no scope detail.\n"
                "Diffs work for classic + blockchain programs (not Chaos).")
    name = v.get("name", "")
    related = [c for c in changes
               if (c.get("name", "").lower() == name.lower())
               and c.get("event") in ("scope_added", "scope_updated", "new_program", "new_repo")]
    if not related:
        return (f"🌿 No recorded scope changes for <b>{esc(name)}</b> yet.\n"
                "I log SC diffs from now on (strict check; non-SC reshuffles are ignored). "
                f"Current scope: /scope {esc(name.split()[0])}")
    lines = [f"🔄 <b>Scope diffs — {esc(name)}</b> (detection times)", ""]
    for c in reversed(related[-3:]):
        e = EVENT_EMOJI.get(c.get("event"), "🔔")
        lines.append(f"{e} detected {fmt_when(c.get('timestamp', ''))} ({fmt_ts(c.get('timestamp', ''))})")
        added = c.get("added", []) or []
        removed = c.get("removed", []) or []
        gh = c.get("github_repos", []) or []
        if added:
            lines.append(f"  ➕ <b>Added ({len(added)}):</b>")
            for a in added[:8]:
                lines.append(f"    • <code>{esc(a)}</code>")
            if len(added) > 8:
                lines.append(f"    … and {len(added) - 8} more")
        if removed:
            lines.append(f"  ➖ <b>Removed ({len(removed)}):</b>")
            for r in removed[:5]:
                lines.append(f"    • <code>{esc(r)}</code>")
            if len(removed) > 5:
                lines.append(f"    … and {len(removed) - 5} more")
        if gh:
            lines.append(f"  🐙 <b>New repos ({len(gh)}):</b>")
            for r in gh[:5]:
                lines.append(f"    • <code>github.com/{esc(r)}</code>")
        if not added and not removed and not gh:
            sc = c.get("sc_targets", []) or []
            lines.append(f"  📁 {len(sc)} source-code target(s) at the time")
        lines.append("")
    lines.append(f"💡 Full scope: /scope {esc(name.split()[0])} · Export: /export {esc(name.split()[0])}")
    return "\n".join(lines).rstrip()

def cmd_fresh(args, state, changes) -> str:
    """Bounty+source programs first seen in the last N days (default 7)."""
    try:
        days = int((args or "7").strip().split()[0])
    except Exception:
        days = 7
    days = max(1, min(days, 90))
    programs = get_programs(state)
    cutoff = time.time() - days * 86400
    fresh_keys = set()
    for c in changes:
        if c.get("event") not in ("new_program", "new_external"):
            continue
        try:
            ts = datetime.fromisoformat(c.get("timestamp", "")).timestamp()
        except Exception:
            continue
        if ts >= cutoff:
            fresh_keys.add((c.get("platform", ""), c.get("handle", "")))
    hits = []
    for k, v in programs.items():
        plat, handle = k.split(":", 1)[0], k.split(":", 1)[-1]
        if (plat, handle) not in fresh_keys:
            continue
        if not (v.get("bounty") and v.get("source")) and plat != "chaos":
            continue
        hits.append(v)
    if not hits:
        return (f"🌿 Nothing detected as brand-new in the last {days}d.\n"
                "“Fresh” = first DETECTED in that window, not launched. "
                "Try <code>/fresh 30</code> for a wider window.")
    def _fresh_score(v):
        hi = v.get("bounty_max") or 0
        return (hi, v.get("domains") or 0)
    hits.sort(key=_fresh_score, reverse=True)
    lines = [f"🆕 <b>Freshly detected — last {days}d</b> — {len(hits)}",
             "<i>Detection time, not launch time. Amounts missing = not in feed.</i>", ""]
    for v in hits[:10]:
        plat = v.get("platform", "?")
        hi = fmt_bounty(v.get("bounty_max"))
        c = (v.get("bounty_ccy") or "").replace("USD", "$").replace("EUR", "€") or "$"
        if hi:
            extra = f"  💸 up to {c}{hi}"
        elif plat == "chaos":
            extra = "  💸 bounty yes (no amounts in Chaos index)"
        elif v.get("bounty"):
            extra = "  💸 bounty yes (amount not in feed)"
        else:
            extra = ""
        lines.append(f"{PLATFORM_EMOJI.get(plat, '⚪')} <b>{esc(v.get('name'))}</b>{extra}")
        lines.append(f"   {esc(v.get('url', ''))}")
    if len(hits) > 10:
        lines.append(f"\n… and {len(hits) - 10} more")
    lines.append("\n💡 Fresh ≠ least competition proof. /scope &lt;name&gt; for detail")
    return "\n".join(lines)

def cmd_repos(args, state, changes) -> str:
    """GitHub repos in scope: per program, or leaderboard when no arg."""
    programs = get_programs(state)
    qual = qualifying(programs)
    if not args:
        ranked = sorted(
            ((v, v.get("github_repos") or []) for v in qual.values()),
            key=lambda x: len(x[1]), reverse=True)
        ranked = [(v, r) for v, r in ranked if r]
        if not ranked:
            return "🐙 No GitHub repos tracked in scope right now."
        lines = ["🐙 <b>Top programs by tracked GitHub repos</b>", ""]
        for v, repos in ranked[:10]:
            plat = v.get("platform", "?")
            lines.append(f"{PLATFORM_EMOJI.get(plat, '⚪')} <b>{esc(v.get('name'))}</b> — {len(repos)} repo(s)")
            lines.append(f"   <code>github.com/{esc(repos[0])}</code>"
                         + (f" <i>+{len(repos) - 1} more</i>" if len(repos) > 1 else ""))
        lines.append("\n💡 Usage: <code>/repos &lt;program&gt;</code> for the full list")
        return "\n".join(lines)
    v, matches = _find_program(args, programs)
    if not v:
        return f"🔍 No program found matching \"{esc(args)}\".\nTry /search {esc(args)}"
    repos = v.get("github_repos") or []
    if not repos:
        return (f"🐙 <b>{esc(v.get('name'))}</b> — no GitHub repos in scope.\n"
                "Repo tracking covers github.com targets; other hosts (GitLab/Bitbucket) "
                "show in /scope.")
    lines = [f"🐙 <b>{esc(v.get('name'))}</b> — {len(repos)} GitHub repo(s) in scope", ""]
    for r in repos[:20]:
        lines.append(f"  • <code>github.com/{esc(r)}</code>")
    if len(repos) > 20:
        lines.append(f"\n… and {len(repos) - 20} more — /export {esc(v.get('name', '').split()[0])} for the full list")
    return "\n".join(lines)

def cmd_blockchain(args, state, changes) -> str:
    """Blockchain-only view: HackenProof / Immunefi / Cantina / Sherlock.
    No args → per-feed counts + top 10 by max payout.
    With args → search name/scope within blockchain programs only."""
    programs = get_programs(state)
    bcs = blockchains(programs)
    if not bcs:
        return ("⛓️ No blockchain programs tracked yet.\n"
                "The monitor hasn't built its baseline — send /refresh, then try again.")
    live = {k: v for k, v in bcs.items() if v.get("bounty") and v.get("source")}

    def _money(v) -> str:
        hi = fmt_bounty(v.get("bounty_max"))
        if not hi:
            return "amount not in feed" if v.get("bounty") else "no bounty"
        ccy = (v.get("bounty_ccy") or "USD")
        return f"up to {ccy} {hi}"

    q = (args or "").strip().lower()
    if q:
        hits = []
        for v in bcs.values():
            if q in (v.get("name", "").lower()):
                hits.append(v)
                continue
            if not (v.get("bounty") and v.get("source")):
                continue
            for t in v.get("sc_targets", []):
                if q in (t.get("identifier", "").lower()) or q in (t.get("description", "").lower()):
                    hits.append(v)
                    break
        if not hits:
            return (f"⛓️ No blockchain matches for <b>{esc(args)}</b>.\n"
                    "Try /blockchain for the top list, or /search for everything.")
        hits.sort(key=lambda v: (v.get("bounty_max") or 0), reverse=True)
        lines = [f"⛓️ <b>Blockchain results for \"{esc(args)}\"</b> — {len(hits)} match(es)", ""]
        for v in hits[:10]:
            plat = v.get("platform", "?")
            st = v.get("live_status") or "?"
            lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>")
            lines.append(f"   💰 {_money(v)} · ⛓️ {esc(st)}")
            lines.append(f"   {esc(v.get('url',''))}")
            lines.append("")
        if len(hits) > 10:
            lines.append(f"… and {len(hits) - 10} more — refine your query")
        return "\n".join(lines).rstrip()

    if not live:
        return ("⛓️ Blockchain feeds tracked, but nothing bounty+source right now.\n"
                "Paused/ended/web-only programs are tracked silently. Try /refresh later.")
    lines = [f"⛓️ <b>Blockchain bounties</b> — {len(live)} bounty+source across 4 feeds",
             "<i>Smart-contract scope. Ranked by max payout (not competition).</i>", ""]
    for p in ["hackenproof", "immunefi", "cantina", "sherlock"]:
        tot = sum(1 for v in bcs.values() if v.get("platform") == p)
        qn = sum(1 for v in live.values() if v.get("platform") == p)
        lines.append(f"{PLATFORM_EMOJI.get(p,'⚪')} <b>{p}</b> — {qn} live / {tot} tracked")
    lines.append("")
    ranked = sorted(live.values(), key=lambda v: (v.get("bounty_max") or 0), reverse=True)
    lines.append("<b>Top by max payout</b>")
    for i, v in enumerate(ranked[:10], 1):
        plat = v.get("platform", "?")
        st = v.get("live_status") or "?"
        lines.append(f"{i}. {PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b> — 💰 {_money(v)} · ⛓️ {esc(st)}")
        lines.append(f"   {esc(v.get('url',''))}")
    if len(ranked) > 10:
        lines.append(f"\n… and {len(ranked) - 10} more — /blockchain &lt;query&gt; to search")
    lines.append("\n💡 /scope &lt;name&gt; for scope · /diff &lt;name&gt; for scope changes")
    return "\n".join(lines)

def cmd_export(args, state, changes, chat_id=None):
    """Build a recon file for a program. Returns (filename, content, caption)."""
    programs = get_programs(state)
    v, matches = _find_program(args, programs)
    if not v:
        return ("📤 Usage: <code>/export &lt;program&gt;</code>\n"
                "e.g. <code>/export netflix</code> — source-code scope as .txt (classic + blockchain)")
    if v.get("platform") == "chaos":
        return (f"🌍 <b>{esc(v.get('name'))}</b> — worldwide index has no scope detail to export.\n"
                "Exports work for classic + blockchain programs.")
    sc = v.get("sc_targets", []) or []
    sc_ids = v.get("sc_ids", []) or []
    sc_total = v.get("sc_total", len(sc))
    if not sc and not sc_ids:
        return (f"📤 <b>{esc(v.get('name'))}</b> has no source-code targets to export.\n"
                "Strict check only: SC asset type or repo-host URL. "
                "Web/API scope is NOT in this file — see program page.")
    name = v.get("name", "program")
    handle = "".join(c if (c.isalnum() or c in "-_") else "-" for c in name.lower().replace(" ", "-"))[:40]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [f"# {name} — source-code scope export (STRICT: SC type or repo-host URL only)",
              f"# platform: {v.get('platform')}  |  exported: {ts}",
              f"# url: {v.get('url')}",
              f"# blunt: detail rows truncated in state to {len(sc)} of {sc_total}; sc_ids below are the FULL normalized set",
              ""]
    idents, repos = [], []
    for t in sc:
        ident = (t.get("identifier") or "").strip()
        if not ident:
            continue
        idents.append(ident)
        if "github.com/" in ident.lower():
            repos.append(ident)
    # FULL normalized IDs (not truncated) — best recon source in this file
    full_ids = sorted(set(sc_ids)) if sc_ids else sorted(set(i.lower() for i in idents))
    body = ["## full normalized sc ids (COMPLETE, use these):"] + full_ids
    body += ["", "## detail rows (TRUNCATED in state, first "
             f"{len(idents)} of {sc_total}):"] + idents
    if repos:
        body += ["", "## github repos (from detail rows):"] + sorted(set(repos))
    filename = f"{handle}-scope.txt"
    caption = (f"📤 <b>{esc(name)}</b> — {len(full_ids)} SC id(s) total "
               f"(detail rows {len(idents)}/{sc_total})")
    return (filename, "\n".join(header + body) + "\n", caption)

def cmd_digest(args, state, changes, chat_id=None) -> str:
    """Per-user digest subscription: /digest daily|weekly|off."""
    if chat_id is None:
        return "⚙️ Digest needs a chat context — send /digest from your chat."
    mode = (args or "").lower().strip().split()[0] if args else ""
    prefs = get_prefs()
    entry = prefs.get(str(chat_id), {})
    if not mode:
        cur = entry.get("digest", "off")
        return (f"📰 Digest is currently <b>{esc(cur)}</b>.\n\n"
                "Blunt: rolling intervals from when you subscribe, NOT fixed clock.\n"
                "Usage:\n"
                "  <code>/digest daily</code> — ~every 24h from now\n"
                "  <code>/digest weekly</code> — ~every 7d from now\n"
                "  <code>/digest off</code> — no summaries (and no instant alerts either — those go to owner channel only)")
    if mode not in ("daily", "weekly", "off"):
        return "⚠️ Choose: <code>/digest daily</code> · <code>/digest weekly</code> · <code>/digest off</code>"
    entry["digest"] = mode
    if mode != "off":
        entry["last_sent"] = datetime.now(timezone.utc).isoformat()
    prefs[str(chat_id)] = entry
    save_prefs(prefs)
    print(f"  [digest] {chat_id} → {mode}")
    if mode == "off":
        return "📰 Digest <b>off</b> — no summaries. Note: instant alerts go to the owner channel only, not to you."
    return (f"📰 Digest set to <b>{mode}</b> (rolling "
            f"{'24h' if mode == 'daily' else '7d'} from now, best-effort).\n"
            "You'll get detected changes since last send. "
            "No instant DMs — owner channel gets those.")

def cmd_settings(args, state, changes, chat_id=None) -> str:
    if chat_id is None:
        return "⚙️ No chat context."
    digest = get_digest(chat_id)
    blocked = is_blocked(chat_id)
    return ("\n".join([
        "⚙️ <b>Your settings</b>", "",
        f"📰 Digest : <b>{esc(digest)}</b>  (/digest daily|weekly|off)",
        f"🚫 Status : {'blocked' if blocked else 'active'}",
        f"👑 Owner  : {'yes' if is_owner(chat_id) else 'no'}",
    ]))

def cmd_block(args, state, changes, chat_id=None) -> str:
    if not is_owner(chat_id):
        return "👑 Owner-only command."
    target = (args or "").strip().split()[0] if args else ""
    if not target:
        return "Usage: <code>/block &lt;chat_id&gt;</code>"
    data = load_json(BLOCKED_FILE, {"blocked": []})
    blocked = {str(x) for x in data.get("blocked", [])}
    blocked.add(str(target))
    data["blocked"] = sorted(blocked)
    save_json(BLOCKED_FILE, data)
    print(f"  [admin] blocked {target}")
    return f"🚫 Blocked <code>{esc(target)}</code>."

def cmd_unblock(args, state, changes, chat_id=None) -> str:
    if not is_owner(chat_id):
        return "👑 Owner-only command."
    target = (args or "").strip().split()[0] if args else ""
    data = load_json(BLOCKED_FILE, {"blocked": []})
    blocked = {str(x) for x in data.get("blocked", [])}
    blocked.discard(str(target))
    data["blocked"] = sorted(blocked)
    save_json(BLOCKED_FILE, data)
    return f"✅ Unblocked <code>{esc(target)}</code>."

def cmd_users(args, state, changes, chat_id=None) -> str:
    if not is_owner(chat_id):
        return "👑 Owner-only command."
    prefs = get_prefs()
    subs = sum(1 for p in prefs.values() if p.get("digest", "off") != "off")
    top = sorted(USAGE.items(), key=lambda x: x[1], reverse=True)[:8]
    lines = ["👑 <b>Bot usage</b> (this process)", "",
             f"👥 Known chats (prefs) : {len(prefs)}",
             f"📰 Digest subs         : {subs}",
             f"🤖 Bot uptime          : {uptime()}", ""]
    if top:
        lines.append("<b>Top commands</b>")
        for cmd, n in top:
            lines.append(f"  /{esc(cmd)} — {n}")
    else:
        lines.append("No commands handled yet this run.")
    return "\n".join(lines)

def cmd_announce(args, state, changes, chat_id=None) -> str:
    if not is_owner(chat_id):
        return "👑 Owner-only command."
    if not args:
        return "Usage: <code>/announce &lt;text&gt;</code> — broadcasts to all known chats."
    prefs = get_prefs()
    targets = [cid for cid in prefs.keys()] + ([str(TELEGRAM_CHAT_ID)] if TELEGRAM_CHAT_ID else [])
    seen, sent = set(), 0
    for cid in targets:
        if cid in seen:
            continue
        seen.add(cid)
        try:
            if send_reply(int(cid) if str(cid).lstrip("-").isdigit() else cid,
                          f"📢 <b>Announcement</b>\n\n{args}"):
                sent += 1
        except Exception:
            continue
    return f"📢 Announced to {sent}/{len(seen)} chat(s)."

def build_digest(changes: list, since_iso: str) -> Optional[str]:
    """Compose a digest of changes since since_iso. None = nothing new."""
    try:
        since = datetime.fromisoformat(since_iso).timestamp()
    except Exception:
        since = time.time() - 86400
    items = []
    for c in changes:
        try:
            ts = datetime.fromisoformat(c.get("timestamp", "")).timestamp()
        except Exception:
            continue
        if ts > since:
            items.append(c)
    if not items:
        return None
    counts: dict = {}
    for c in items:
        counts[c.get("event", "?")] = counts.get(c.get("event", "?"), 0) + 1
    summary = " · ".join(f"{EVENT_EMOJI.get(e, '🔔')} {n}" for e, n in sorted(counts.items()))
    lines = ["📰 <b>Your bounty digest (detected changes)</b>", "",
             f"{len(items)} detected change(s): {summary}",
             "<i>Times = detection, not launch. Best-effort coverage.</i>", ""]
    for c in items[-12:]:
        e = EVENT_EMOJI.get(c.get("event"), "🔔")
        lines.append(f"{e} <b>{esc(c.get('name'))}</b> <i>({esc(c.get('platform', '?'))} · detected {fmt_when(c.get('timestamp',''))})</i>")
        added = c.get("added", []) or []
        if added:
            lines.append(f"   ➕ {esc(added[0])}" + (f" <i>+{len(added) - 1} more</i>" if len(added) > 1 else ""))
        lines.append(f"   {esc(c.get('url', ''))}")
    lines.append("\n💡 /diff &lt;name&gt; for scope diffs · /digest off to stop")
    return "\n".join(lines)

def check_and_send_digests() -> bool:
    """Send due digests. Returns True if prefs.json changed (caller commits)."""
    prefs = get_prefs()
    if not prefs:
        return False
    changes = load_json(CHANGES_FILE, [])
    now = time.time()
    changed = False
    for cid, entry in list(prefs.items()):
        mode = entry.get("digest", "off")
        if mode not in ("daily", "weekly"):
            continue
        interval = 86400 if mode == "daily" else 7 * 86400
        try:
            last = datetime.fromisoformat(entry.get("last_sent", "")).timestamp()
        except Exception:
            last = 0
        if now - last < interval:
            continue
        msg = build_digest(changes, entry.get("last_sent", ""))
        if msg is None:
            msg = ("📰 <b>Your bounty digest</b>\n\n"
                   "🌿 No detected changes in this rolling period.\n"
                   "Coverage is 5 feeds + Chaos only; gaps happen.")
        try:
            target = int(cid) if str(cid).lstrip("-").isdigit() else cid
            if send_reply(target, msg):
                entry["last_sent"] = datetime.now(timezone.utc).isoformat()
                prefs[cid] = entry
                changed = True
                print(f"  [digest] sent {mode} to {cid}")
        except Exception as e:
            print(f"  [digest] failed for {cid}: {e}")
    if changed:
        save_prefs(prefs)
    return changed

COMMANDS = {
    "start":   cmd_start,
    "help":    cmd_help,
    "status":  cmd_status,
    "stats":   cmd_stats,
    "sources": cmd_sources,
    "latest":  cmd_latest,
    "new":     cmd_new,
    "changes": cmd_changes,
    "search":  cmd_search,
    "platform": cmd_platform,
    "source":  cmd_source,
    "github":  cmd_github,
    "scope":   cmd_scope,
    "blockchain": cmd_blockchain,
    "diff":    cmd_diff,
    "fresh":   cmd_fresh,
    "repos":   cmd_repos,
    "export":  cmd_export,
    "digest":  cmd_digest,
    "settings": cmd_settings,
    "block":   cmd_block,
    "unblock": cmd_unblock,
    "users":   cmd_users,
    "announce": cmd_announce,
    "top":     cmd_top,
    "refresh": cmd_refresh,
}

BOT_MENU = [
    ("start", "Welcome & quick start"),
    ("help", "All commands"),
    ("status", "Monitor health & last write (blunt)"),
    ("stats", "Program statistics"),
    ("sources", "Data sources + limits"),
    ("latest", "Last 5 detected changes"),
    ("new", "Recently detected programs"),
    ("changes", "Last 15 detected changes"),
    ("search", "Search programs — /search wordpress"),
    ("platform", "Filter by platform — /platform hackerone"),
    ("source", "Programs with SOURCE_CODE assets"),
    ("github", "Programs with GitHub repos"),
    ("scope", "Program scope — /scope github"),
    ("blockchain", "Blockchain bounties — /blockchain uniswap"),
    ("diff", "What changed in scope — /diff netflix"),
    ("fresh", "Freshly detected last 7d — /fresh 30"),
    ("repos", "GitHub repos in scope"),
    ("export", "SC scope file (truncated detail + full ids)"),
    ("digest", "Rolling daily/weekly summary"),
    ("settings", "Your settings"),
    ("top", "Rough ranking (H1-biased, read caveats)"),
    ("refresh", "Force data refresh now"),
]

def handle_text(text: str, state: dict, changes: list, chat_id=None) -> str:
    parts = text.strip().split(maxsplit=1)
    cmd = parts[0].lower().lstrip("/").split("@")[0]  # strip / and @BotName suffix
    args = parts[1].strip() if len(parts) > 1 else ""
    handler = COMMANDS.get(cmd)
    if handler:
        try:
            if chat_id is not None and is_blocked(chat_id) and not is_owner(chat_id):
                return "🚫 You are blocked from using this bot."
            if cmd != "refresh":
                warn = check_rate(chat_id) if chat_id is not None else None
                if warn:
                    return warn
            USAGE[cmd] = USAGE.get(cmd, 0) + 1
            try:
                return handler(args, state, changes, chat_id)
            except TypeError:
                return handler(args, state, changes)
        except Exception as e:
            print(f"  ✗ /{cmd} error:\n{traceback.format_exc()}")
            return f"💥 Error handling /{esc(cmd)}: {esc(e)}"
    if cmd.isalpha() and text.startswith("/"):
        return f"🤔 Unknown command /{esc(cmd)} — try /help"
    return "👋 I respond to commands — type /help"

# ── Telegram I/O ───────────────────────────────────────────────────────────────

def tg_call(method: str, payload: dict, http_timeout: int = 15, retries: int = 2):
    for i in range(retries + 1):
        try:
            r = requests.post(f"{API}/{method}", json=payload, timeout=http_timeout)
            if r.status_code == 429:
                time.sleep(r.json().get("parameters", {}).get("retry_after", 15)); continue
            return r
        except Exception as e:
            if i == retries:
                print(f"  ✗ {method}: {e}")
                return None
            time.sleep(3)
    return None

def send_reply(chat_id: int, text: str) -> bool:
    ok_all = True
    # Telegram hard limit is 4096 chars — split on line boundaries
    chunks_sent = 0
    while text and chunks_sent < 10:
        chunk, rest = text[:3800], text[3800:]
        if rest:
            cut = chunk.rfind("\n")
            if cut > 500:
                chunk, rest = chunk[:cut], chunk[cut:] + rest
        r = tg_call("sendMessage", {
            "chat_id": chat_id, "text": chunk,
            "parse_mode": "HTML", "disable_web_page_preview": True})
        ok = bool(r and r.ok)
        ok_all = ok_all and ok
        text = rest                    # advance — never resend the same chunk
        chunks_sent += 1
        if ok:
            time.sleep(0.6)  # stay under 1 msg/sec per chat
    return ok_all

def set_menu():
    r = tg_call("setMyCommands", {"commands": [
        {"command": c, "description": d} for c, d in BOT_MENU]})
    if r and r.ok:
        print("  ✓ command menu registered")

def get_updates(offset: int, long_poll: bool = True) -> Optional[List[dict]]:
    """None = API error (handled by caller); [] = no updates."""
    global _CONFLICT_STREAK, _HEALED_CONFLICT
    poll_secs = 25 if long_poll else 0
    r = tg_call("getUpdates", {"offset": offset, "limit": 100, "timeout": poll_secs},
                http_timeout=poll_secs + 15, retries=1)
    if r is None:
        return None
    if r.ok:
        _CONFLICT_STREAK = 0
        return r.json().get("result", [])
    code = r.status_code
    body = r.text[:200]
    if code == 409:  # another poller alive (overlap) or stale webhook
        # NEVER exit on 409: exiting completes the job, which triggers the
        # partner workflow, which would 409 too — an exit loop. Stay alive
        # with backoff; Telegram keeps queueing updates server-side and the
        # survivor/duplicates resolve when the other instance goes away.
        _CONFLICT_STREAK += 1
        print(f"  ⚠ 409 conflict x{_CONFLICT_STREAK} (overlap/stale webhook) — staying alive: {body}")
        if not _HEALED_CONFLICT:
            _HEALED_CONFLICT = True
            print("  ⚠ attempting one-time webhook delete (heals stale-webhook case)")
            tg_call("deleteWebhook", {"drop_pending_updates": True})
        return None  # caller backs off; does NOT advance offset
    if code == 401:
        # Bad/rotated token. NEVER SystemExit here: that completes the job,
        # triggers the partner workflow instantly, and spin-loops the chain
        # at full speed burning Actions quota. Return None so the poll loop
        # backs off; the startup getMe probe sleeps out the term instead.
        print(f"  ✗✗✗ TELEGRAM_TOKEN INVALID (401) — backing off, not exiting: {body}")
        return None
    print(f"  ✗ getUpdates HTTP {code}: {body}")
    return None

# ── Inline monitor (schedule-independent) ─────────────────────────────────────

def git_sync(commit_msg: str, add_files: list):
    """Commit + push with auto-resolve. Never raises. Freshest snapshot wins
    on state.json conflicts (bot just re-fetched upstream APIs)."""
    try:
        for f in add_files:
            subprocess.run(f"git add {f} 2>/dev/null || true", shell=True)
        subprocess.run(
            f'git -c user.name="BountyBot[bot]" '
            f'-c user.email=bountybot@users.noreply.github.com '
            f'commit -m "{commit_msg}" || true',
            shell=True)
        subprocess.run("git fetch origin main || true", shell=True)
        subprocess.run(
            "git pull --rebase --autostash -X theirs origin main"
            " || git rebase --abort || true",
            shell=True)
        r = subprocess.run("git push", shell=True)
        if r.returncode != 0:
            print("  [git] push needed retry…")
            subprocess.run("git fetch origin main || true", shell=True)
            subprocess.run(
                "git pull --rebase --autostash -X theirs origin main"
                " || git rebase --abort || true",
                shell=True)
            subprocess.run("git push || echo 'push failed — next cycle will retry'",
                           shell=True)
    except Exception as e:
        print(f"  [git] sync error (non-fatal): {e}")


def run_monitor_cycle():
    """Run monitor.py inline and commit its state — notifications no longer
    depend on GitHub's (delayed) cron schedules."""
    print("  [/auto] monitor cycle starting …")
    try:
        env = dict(os.environ, MONITOR_BUDGET_SEC="270")  # must finish < timeout
        r = subprocess.run([sys.executable, "-u", "monitor.py"], timeout=300, env=env)
    except Exception as e:
        print(f"  [/auto] monitor crashed: {e}")
        return
    if r.returncode != 0:
        print("  [/auto] monitor exited non-zero — keeping old state")
        return
    # commit state + offset (persisting offset here shrinks restart-replay to ~zero)
    git_sync("chore: auto state [skip ci]",
             ["state.json", "changes_log.json", "bot_offset.json"])
    print("  [/auto] monitor cycle done")

_MONITOR_THREAD: Optional[threading.Thread] = None

def maybe_run_monitor_cycle():
    """Start an inline monitor cycle in a DAEMON thread. Polls are never
    blocked for minutes while monitor.py scrapes slow blockchain pages —
    that blocking was a big source of 'bot is dead' sightings."""
    global _MONITOR_THREAD, LAST_MONITOR_AT
    if _SHUTDOWN:
        return
    if _MONITOR_THREAD is not None and _MONITOR_THREAD.is_alive():
        return
    if time.time() - LAST_MONITOR_AT < MONITOR_INTERVAL:
        return
    LAST_MONITOR_AT = time.time()

    def _worker():
        try:
            run_monitor_cycle()
        except Exception:
            print("  [/auto] background monitor thread died:")
            traceback.print_exc()

    _MONITOR_THREAD = threading.Thread(target=_worker, name="monitor-cycle",
                                       daemon=True)
    _MONITOR_THREAD.start()

# ── Main loop (resident long-poll) ────────────────────────────────────────────

def save_offset(last_update_id: int, last_announce: float):
    """Persist poll offset (+ circuit-breaker fields) atomically."""
    try:
        prev = load_json(OFFSET_FILE, {})
    except Exception:
        prev = {}
    data = dict(prev) if isinstance(prev, dict) else {}
    data["last_update_id"] = last_update_id
    data["last_announce"] = last_announce
    save_json(OFFSET_FILE, data)

def main():
    global LAST_MONITOR_AT
    print(f"\n{'─'*58}")
    print(f"  Telegram Bot — resident mode")
    print(f"  started {datetime.now(timezone.utc).isoformat()}")
    print(f"  max runtime: {BOT_MAX_MINUTES} min")
    print(f"  diagnostics: token={'present' if TELEGRAM_TOKEN else 'MISSING'}"
          f" ({len(TELEGRAM_TOKEN)} chars) · chat_id={TELEGRAM_CHAT_ID!r}")
    print(f"{'─'*58}\n")
    if not TELEGRAM_TOKEN:
        print("✗✗✗ TELEGRAM_TOKEN missing — sleeping out the term (no crash spin).")
        time.sleep(max(60, BOT_MAX_MINUTES * 60))
        return
    for _sig in ("SIGTERM", "SIGINT"):
        try:
            signal.signal(getattr(signal, _sig), _on_term)
        except Exception:
            pass

    offset_data = load_json(OFFSET_FILE, {"last_update_id": 0})
    offset = int(offset_data.get("last_update_id", 0)) + 1
    last_announce = float(offset_data.get("last_announce", 0) or 0)

    # Crash-loop circuit breaker: rapid restarts in a row (<5 min apart) used
    # to spin the workflow chain at full speed and burn the Actions quota
    # (then EVERYTHING stops). Back off instead — still self-heals.
    now = time.time()
    last_start = float(offset_data.get("last_start", 0) or 0)
    if now - last_start < 300:
        fails = int(offset_data.get("fails", 0) or 0) + 1  # fast restart: extend streak
    else:
        fails = 1  # healthy gap: fresh streak starting with this boot
    offset_data = dict(offset_data, last_start=now, fails=fails)
    save_json(OFFSET_FILE, {**offset_data,
                            "last_update_id": max(0, offset - 1),
                            "last_announce": last_announce})
    if fails >= 3:
        print(f"  ✗✗✗ {fails} fast restarts in a row — backing off 30 min (no quota burn)")
        time.sleep(1800)
        return
    if fails >= 2:
        print(f"  ⚠ fast-restart streak x{fails} — continuing, watching closely")

    # Token sanity probe: a bad/rotated token returned 401 inside get_updates,
    # which raised SystemExit → instant chain spin. Sleep out the term instead.
    try:
        pr = requests.post(f"{API}/getMe", timeout=15)
        if pr.status_code == 401:
            print("  ✗✗✗ TELEGRAM_TOKEN INVALID (401) — sleeping out the term, "
                  "fix the repo secret and /help will work again. NOT crash-looping.")
            end = BOT_STARTED_AT + BOT_MAX_MINUTES * 60
            while time.time() < end and not _SHUTDOWN:
                time.sleep(60)
            return
    except Exception as e:
        print(f"  ⚠ getMe probe failed ({e}) — continuing, poll loop will retry")

    set_menu()

    # Announce ONLY on manual dispatch, at most once per hour, and only after
    # verifying polling actually works. Prevents ping storms from crash-loops
    # or queued manual runs executing back-to-back.
    if ANNOUNCE and (time.time() - last_announce) > 3600:
        probe = get_updates(offset, long_poll=False)
        if probe is not None:
            cid = int(TELEGRAM_CHAT_ID) if TELEGRAM_CHAT_ID.lstrip("-").isdigit() else TELEGRAM_CHAT_ID
            send_reply(cid,
                "🤖 <b>Bot online</b> — best-effort resident (restarts ~5.5h, gaps happen).\n"
                "⚠️ Times are detection time. Instant alerts → this channel only.\n"
                "📖 /help for commands · 📊 /status for blunt health")
            last_announce = time.time()
            save_json(OFFSET_FILE, {"last_update_id": offset - 1, "last_announce": last_announce})
        else:
            print("  ⚠ poll check failed — NOT announcing (bot would be lying)")

    last_heartbeat = 0.0
    api_fail_streak = 0

    while True:
        try:
            if _SHUTDOWN:
                print("\n🛑 shutdown requested — saving offset and exiting")
                save_offset(offset - 1, last_announce)
                break
            ran_out = (time.time() - BOT_STARTED_AT) / 60 >= BOT_MAX_MINUTES
            if ran_out:
                print(f"\n⏱ runtime limit reached ({BOT_MAX_MINUTES} min) — exiting gracefully")
                print(f"  uptime: {uptime()} · offset: {offset-1}")
                save_offset(offset - 1, last_announce)
                break

            if time.time() - last_heartbeat > 600:
                print(f"  ♥ {datetime.now(timezone.utc).strftime('%H:%M:%S')} alive · "
                      f"uptime {uptime()} · offset {offset-1}")
                last_heartbeat = time.time()

            # inline monitor cycle, NON-BLOCKING (background thread) — polls stay live
            maybe_run_monitor_cycle()

            # digest sender — due daily/weekly summaries per user prefs
            try:
                if check_and_send_digests():
                    git_sync("chore: digest prefs [skip ci]", ["prefs.json"])
            except Exception as e:
                print(f"  [digest] sender error: {e}")

            try:
                updates = get_updates(offset, long_poll=True)
            except SystemExit:
                raise  # invalid token — die loudly, do not loop
            except Exception:
                traceback.print_exc()
                updates = None

            if updates is None:
                api_fail_streak += 1
                backoff = min(300, 15 * api_fail_streak)
                print(f"  ⚠ API failure #{api_fail_streak} — retrying in {backoff}s (staying alive)")
                time.sleep(backoff)
                continue
            api_fail_streak = 0

            if not updates:
                continue

            state = load_json(STATE_FILE, {})
            changes = load_json(CHANGES_FILE, [])

            # Public mode: allow ANY chat (alerts keep going to TELEGRAM_CHAT_ID only)
            # offset advances for ALL updates regardless, so nothing is reprocessed
            batch = []
            for u in updates:
                offset = u["update_id"] + 1
                msg = u.get("message") or u.get("edited_message") or {}
                chat_id = (msg.get("chat") or {}).get("id")
                text = msg.get("text", "")
                if not chat_id or not text:
                    continue
                # no owner filter — public bot; log public users for visibility
                if TELEGRAM_CHAT_ID and str(chat_id) != str(TELEGRAM_CHAT_ID):
                    print(f"  👤 public user {chat_id}: {text[:30]}")
                if is_blocked(chat_id) and not is_owner(chat_id):
                    print(f"  🚫 blocked chat {chat_id} (advancing offset)")
                    continue
                batch.append((chat_id, text))

            if len(batch) > 3:
                # backlog burst (bot was offline while user kept sending) —
                # answer only the LAST command plus a summary, not N duplicates
                chat_id, last_text = batch[-1]
                print(f"  ← backlog burst: {len(batch)} queued commands — replying once")
                reply_result(chat_id,
                    f"✅ Processed {len(batch)} queued commands (backlog flush — "
                    f"bot was restarting)\n\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
                    + handle_text(last_text, state, changes, chat_id))
            else:
                for chat_id, text in batch:
                    try:
                        print(f"  ← {text[:60]}")
                        # /export answers with a file — intercept before text handling
                        _parts = text.strip().split(maxsplit=1)
                        _cmd = _parts[0].lower().lstrip("/").split("@")[0]
                        if _cmd == "export":
                            _warn = check_rate(chat_id)
                            if _warn:
                                send_reply(chat_id, _warn)
                            else:
                                result = cmd_export(_parts[1].strip() if len(_parts) > 1 else "",
                                                    state, changes, chat_id)
                                USAGE["export"] = USAGE.get("export", 0) + 1
                                reply_result(chat_id, result)
                        else:
                            reply_result(chat_id, handle_text(text, state, changes, chat_id))
                    except Exception:
                        print(f"  ⚠ failed to handle: {text[:40]}")
                        traceback.print_exc()

            save_offset(offset - 1, last_announce)
            # confirm processed updates server-side (shrinks crash-replay window)
            try:
                get_updates(offset, long_poll=False)
            except Exception:
                pass  # next batch re-confirms; never die here
        except SystemExit:
            save_offset(offset - 1, last_announce)
            raise
        except Exception:
            # NOTHING in one poll iteration may kill the resident bot.
            print("  💥 loop iteration failed — staying alive:")
            traceback.print_exc()
            time.sleep(15)
            continue

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\nbye"); raise SystemExit(0)
    except Exception as e:
        print(f"\n💥 Fatal: {e}"); traceback.print_exc(); raise
