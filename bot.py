#!/usr/bin/env python3
"""
Telegram Bot — Bug Bounty Source Code Monitor (resident mode)
Runs as a long-polling process 24/7: replies are instant.
Data: state.json + changes_log.json written by monitor.py.
/refresh runs monitor.py inline — no PAT needed.
"""

import html, json, os, subprocess, sys, time, traceback
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
MONITOR_INTERVAL = 30 * 60          # run monitor.py inline every 30 min
LAST_MONITOR_AT  = time.time() - (MONITOR_INTERVAL - 120)  # first cycle ~2 min after boot

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡",
                  "federacy":"🟣","chaos":"🌍"}
PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy", "other"]
EVENT_EMOJI = {
    "new_program":"🆕", "scope_added":"📦",
    "scope_updated":"🔄", "bounty_enabled":"💰", "new_external":"🌍",
}

# ── Utils ──────────────────────────────────────────────────────────────────────

def esc(s) -> str:
    return html.escape(str(s or ""), quote=False)

def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default

def save_json(path, data):
    json.dump(data, open(path, "w"), indent=2)

def get_programs(state: dict) -> dict:
    return {k: v for k, v in state.items() if k != "_meta"}

def qualifying(programs: dict) -> dict:
    return {k: v for k, v in programs.items()
            if k.split(":",1)[0] != "chaos" and v.get("bounty") and v.get("source")}

def externals(programs: dict) -> dict:
    return {k: v for k, v in programs.items() if k.split(":",1)[0] == "chaos"}

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

# ── Command handlers (pure: return reply text) ────────────────────────────────

def cmd_start(args, state, changes) -> str:
    return (
        "👋 <b>Bug Bounty Monitor Bot</b>\n\n"
        "I watch <b>the whole bug bounty world</b> for programs that "
        "<b>pay bounties</b> and have <b>source code in scope</b>:\n"
        "  🟢 HackerOne · 🔴 Bugcrowd · 🔵 Intigriti\n"
        "  🟡 YesWeHack · 🟣 Federacy (full scope analysis)\n"
        "  🌍 Worldwide index — HackenProof, BugBountyCH, direct &amp; self-hosted programs\n\n"
        "🔔 You get a ping automatically when:\n"
        "  • A new matching program launches\n"
        "  • A program adds source code to scope\n"
        "  • A program starts paying bounties\n"
        "  • A new bounty program appears outside major platforms\n\n"
        "📖 Type /help to see everything I can do."
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
        "  /platform &lt;name&gt; — hackerone | bugcrowd | intigriti | yeswehack | federacy | other\n"
        "  /source — Programs with SOURCE_CODE scope assets\n"
        "  /github — Programs with GitHub repos in scope\n\n"
        "⚙️ <b>Control</b>\n"
        "  /refresh — Force a data refresh now\n\n"
        "💡 Data auto-refreshes every 30 min · I reply instantly"
    )

def cmd_status(args, state, changes) -> str:
    meta = state.get("_meta", {})
    programs = get_programs(state)
    if not programs and not meta:
        return "⚠️ No data yet — the monitor hasn't run. Send /refresh to force it now."
    lines = [
        "🟢 <b>Monitor Status</b>", "",
        f"🕒 Last data refresh : {fmt_when(meta.get('updated_at',''))} ({fmt_ts(meta.get('updated_at',''))})",
        f"📦 Total programs    : {meta.get('total', len(programs))}",
        f"💰 Bounty + source   : {meta.get('qualifying', len(qualifying(programs)))}",
        f"🌍 Worldwide watch   : {meta.get('external', len(externals(programs)))}",
        f"📜 Changes logged    : {len(changes)}",
        f"🤖 Bot uptime        : {uptime()}",
        "", "🔁 Monitor: every 30 min (inline + cron backup) · Bot: 24/7 resident",
    ]
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
        "📡 <b>Data Sources</b>\n\n"
        "<b>Full scope analysis</b> (every 30 min)\n"
        "  arkadiyt/bounty-targets-data:\n"
        "  🟢 HackerOne · 🔴 Bugcrowd · 🔵 Intigriti\n"
        "  🟡 YesWeHack · 🟣 Federacy\n"
        "  → per-target scope: bounty flag, source-code detection\n\n"
        "<b>Worldwide index</b> (program-level watch)\n"
        "  🌍 ProjectDiscovery Chaos — 800+ programs:\n"
        "  HackenProof, BugBountyCH, direct &amp; self-hosted\n"
        "  → new bounty programs outside major platforms\n\n"
        "💡 Combo = every public bug bounty program with known scope data, worldwide."
    )

def _changes_list(changes: list, n: int, event_filter: Optional[str] = None) -> str:
    items = [c for c in changes if event_filter is None or c.get("event") == event_filter]
    if not items:
        return "🌿 No changes logged yet — baseline only. New activity will appear here."
    lines = [f"📜 <b>Last {min(n, len(items))} change(s)</b> — {len(items)} total", ""]
    for c in reversed(items[-n:]):
        e = EVENT_EMOJI.get(c.get("event"), "🔔")
        plat = c.get("platform", "?")
        lines.append(f"{e} <b>{esc(c.get('name'))}</b>")
        lines.append(f"   {PLATFORM_EMOJI.get(plat,'⚪')} {plat} · {fmt_when(c.get('timestamp',''))}")
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
        return "🌿 No new programs yet. I'll ping you the moment one launches."
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
    lines = [f"🔎 <b>Results for \"{esc(args)}\"</b> — {total} match(es)", ""]
    shown = 0
    for v in name_hits[:10]:
        plat = v.get("platform","?")
        lines.append(f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b>")
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
        lines = [f"🌍 <b>Worldwide programs</b> — {len(ext)}  <i>(HackenProof, BugBountyCH, direct…)</i>", ""]
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
    lines = [
        f"{PLATFORM_EMOJI.get(plat,'⚪')} <b>{esc(v.get('name'))}</b> — {plat}", "",
        f"🔗 {esc(v.get('url',''))}",
        f"💰 Bounty: {'✅' if v.get('bounty') else '❌'}", "",
        f"📁 <b>Source-code targets ({len(sc)}):</b>",
    ]
    for t in sc:
        lines.append(f"  • <code>{esc(t.get('identifier'))}</code>  [{esc(t.get('asset_type'))}]")
    if not sc:
        lines.append("  (none detected)")
    return "\n".join(lines)

def cmd_refresh(args, state, changes) -> str:
    """Runs monitor.py inline — no PAT needed."""
    print("  [/refresh] running monitor.py …")
    try:
        r = subprocess.run([sys.executable, "monitor.py"],
                           capture_output=True, text=True, timeout=300)
    except Exception as e:
        return f"⚠️ Refresh failed to start: {esc(e)}"
    if r.returncode != 0:
        tail = (r.stdout or "") + (r.stderr or "")
        return f"⚠️ Monitor exited with error:\n<code>{esc(tail[-400:])}</code>"
    # monitor already sent any change notifications itself
    meta = load_json(STATE_FILE, {}).get("_meta", {})
    ext_q = meta.get("external", "?")
    return ("🔄 <b>Data refreshed!</b>\n\n"
            f"💰 Bounty + source : {meta.get('qualifying','?')}\n"
            f"🌍 Worldwide       : {ext_q}\n"
            f"📦 Total programs  : {meta.get('total','?')}\n\n"
            f"🕒 {fmt_ts(meta.get('updated_at',''))} — /latest for new changes")

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
    "refresh": cmd_refresh,
}

BOT_MENU = [
    ("start", "Welcome & quick start"),
    ("help", "All commands"),
    ("status", "Monitor health & last run"),
    ("stats", "Program statistics"),
    ("sources", "Data sources I watch"),
    ("latest", "Last 5 changes"),
    ("new", "Recently added programs"),
    ("changes", "Last 15 changes"),
    ("search", "Search programs — /search wordpress"),
    ("platform", "Filter by platform — /platform hackerone"),
    ("source", "Programs with SOURCE_CODE assets"),
    ("github", "Programs with GitHub repos"),
    ("scope", "Program scope — /scope github"),
    ("refresh", "Force data refresh now"),
]

def handle_text(text: str, state: dict, changes: list) -> str:
    parts = text.strip().split(maxsplit=1)
    cmd = parts[0].lower().lstrip("/").split("@")[0]  # strip / and @BotName suffix
    args = parts[1].strip() if len(parts) > 1 else ""
    handler = COMMANDS.get(cmd)
    if handler:
        try:
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
    poll_secs = 25 if long_poll else 0
    r = tg_call("getUpdates", {"offset": offset, "limit": 100, "timeout": poll_secs},
                http_timeout=poll_secs + 15, retries=1)
    if r is None:
        return None
    if r.ok:
        return r.json().get("result", [])
    code = r.status_code
    body = r.text[:200]
    if code == 409:  # webhook conflict — heal and retry
        print(f"  ⚠ 409 conflict — deleting webhook: {body}")
        tg_call("deleteWebhook", {"drop_pending_updates": False})
        r2 = tg_call("getUpdates", {"offset": offset, "limit": 100, "timeout": 0},
                     http_timeout=15, retries=1)
        return r2.json().get("result", []) if (r2 and r2.ok) else None
    if code == 401:
        print(f"  ✗✗✗ TELEGRAM_TOKEN INVALID (401) — check the repo secret!"); raise SystemExit(1)
    print(f"  ✗ getUpdates HTTP {code}: {body}")
    return None

# ── Inline monitor (schedule-independent) ─────────────────────────────────────

def run_monitor_cycle():
    """Run monitor.py inline and commit its state — notifications no longer
    depend on GitHub's (delayed) cron schedules."""
    print("  [/auto] monitor cycle starting …")
    try:
        r = subprocess.run([sys.executable, "-u", "monitor.py"], timeout=300)
    except Exception as e:
        print(f"  [/auto] monitor crashed: {e}")
        return
    if r.returncode != 0:
        print("  [/auto] monitor exited non-zero — keeping old state")
        return
    # commit state + offset (persisting offset here shrinks restart-replay to ~zero)
    for cmd in [
        "git add state.json changes_log.json bot_offset.json",
        'git -c user.name="BountyBot[bot]" -c user.email=bountybot@users.noreply.github.com '
        'commit -m "chore: auto state [skip ci]"',
    ]:
        subprocess.run(cmd, shell=True)
    # safe push: rebase local commit on remote; NEVER reset --hard (would rewind
    # local state/offset files); on any failure just skip — next cycle catches up
    subprocess.run(
        "git pull --rebase --autostash origin main"
        " && git push"
        " || git rebase --abort",
        shell=True)
    print("  [/auto] monitor cycle done")

# ── Main loop (resident long-poll) ────────────────────────────────────────────

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
        print("✗✗✗ TELEGRAM_TOKEN missing — aborting."); raise SystemExit(1)

    offset_data = load_json(OFFSET_FILE, {"last_update_id": 0})
    offset = int(offset_data.get("last_update_id", 0)) + 1
    last_announce = float(offset_data.get("last_announce", 0) or 0)
    save_json(OFFSET_FILE, {"last_update_id": max(0, offset - 1), "last_announce": last_announce})

    set_menu()

    # Announce ONLY on manual dispatch, at most once per hour, and only after
    # verifying polling actually works. Prevents ping storms from crash-loops
    # or queued manual runs executing back-to-back.
    if ANNOUNCE and (time.time() - last_announce) > 3600:
        probe = get_updates(offset, long_poll=False)
        if probe is not None:
            cid = int(TELEGRAM_CHAT_ID) if TELEGRAM_CHAT_ID.lstrip("-").isdigit() else TELEGRAM_CHAT_ID
            send_reply(cid,
                "🤖 <b>Bot online</b> — resident mode, replying instantly 24/7.\n"
                "📖 /help for commands · 📊 /status for health")
            last_announce = time.time()
            save_json(OFFSET_FILE, {"last_update_id": offset - 1, "last_announce": last_announce})
        else:
            print("  ⚠ poll check failed — NOT announcing (bot would be lying)")

    last_heartbeat = 0.0
    api_fail_streak = 0

    while True:
        ran_out = (time.time() - BOT_STARTED_AT) / 60 >= BOT_MAX_MINUTES
        if ran_out:
            print(f"\n⏱ runtime limit reached ({BOT_MAX_MINUTES} min) — exiting gracefully")
            print(f"  uptime: {uptime()} · offset: {offset-1}")
            break

        if time.time() - last_heartbeat > 600:
            print(f"  ♥ {datetime.now(timezone.utc).strftime('%H:%M:%S')} alive · "
                  f"uptime {uptime()} · offset {offset-1}")
            last_heartbeat = time.time()

        # inline monitor cycle — every 30 min, independent of cron schedules
        if time.time() - LAST_MONITOR_AT >= MONITOR_INTERVAL:
            LAST_MONITOR_AT = time.time()
            run_monitor_cycle()

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

        # collect this batch's owner commands (offset advances for ALL updates
        # regardless, so nothing is ever reprocessed)
        batch = []
        for u in updates:
            offset = u["update_id"] + 1
            msg = u.get("message") or u.get("edited_message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            text = msg.get("text", "")
            if not chat_id or not text:
                continue
            if TELEGRAM_CHAT_ID and str(chat_id) != str(TELEGRAM_CHAT_ID):
                print(f"  ⛔ ignored chat {chat_id}")
                continue
            batch.append((chat_id, text))

        if len(batch) > 3:
            # backlog burst (bot was offline while user kept sending) —
            # answer only the LAST command plus a summary, not N duplicates
            chat_id, last_text = batch[-1]
            print(f"  ← backlog burst: {len(batch)} queued commands — replying once")
            send_reply(chat_id,
                f"✅ Processed {len(batch)} queued commands (backlog flush — "
                f"bot was restarting)\n\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
                + handle_text(last_text, state, changes))
        else:
            for chat_id, text in batch:
                try:
                    print(f"  ← {text[:60]}")
                    send_reply(chat_id, handle_text(text, state, changes))
                except Exception:
                    print(f"  ⚠ failed to handle: {text[:40]}")
                    traceback.print_exc()

        save_json(OFFSET_FILE, {"last_update_id": offset - 1, "last_announce": last_announce})
        # confirm processed updates server-side (shrinks crash-replay window)
        get_updates(offset, long_poll=False)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\nbye"); raise SystemExit(0)
    except Exception as e:
        print(f"\n💥 Fatal: {e}"); traceback.print_exc(); raise
