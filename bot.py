#!/usr/bin/env python3
"""
Telegram Bot — Bug Bounty Source Code Monitor
Runs on GitHub Actions every 5 min, processes queued messages via getUpdates.
Data source: state.json + changes_log.json written by monitor.py.
"""

import html, json, os, time
from datetime import datetime, timezone
from typing import List, Optional
import requests

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
GH_PAT           = os.environ.get("GH_PAT", "")  # personal access token (repo + actions scope) for /refresh
REPO             = os.environ.get("GITHUB_REPOSITORY", "Het-Kalariya/Bounty-monitor")

OFFSET_FILE = "bot_offset.json"
STATE_FILE  = "state.json"
CHANGES_FILE = "changes_log.json"
API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡"}
EVENT_EMOJI = {
    "new_program":"🆕", "scope_added":"📦",
    "scope_updated":"🔄", "bounty_enabled":"💰",
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
    """All program entries (skip the _meta key)."""
    return {k: v for k, v in state.items() if k != "_meta"}

def qualifying(programs: dict) -> dict:
    return {k: v for k, v in programs.items() if v.get("bounty") and v.get("source")}

def fmt_ts(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %H:%M UTC")
    except Exception:
        return iso or "?"

def fmt_when(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso).replace(tzinfo=None)
        secs = (datetime.utcnow() - dt).total_seconds()
        if secs < 60:       return "just now"
        if secs < 3600:     return f"{int(secs//60)}m ago"
        if secs < 86400:    return f"{int(secs//3600)}h ago"
        return f"{int(secs//86400)}d ago"
    except Exception:
        return "?"
# ── Command handlers (pure: return reply text) ────────────────────────────────

def cmd_start(args, state, changes) -> str:
    return (
        "👋 <b>Bug Bounty Monitor Bot</b>\n\n"
        "I watch HackerOne, Bugcrowd, Intigriti &amp; YesWeHack for programs that "
        "<b>pay bounties</b> and have <b>source code in scope</b>.\n\n"
        "🔔 You get a ping automatically when:\n"
        "  • A new matching program launches\n"
        "  • A program adds source code to scope\n"
        "  • A program starts paying bounties\n\n"
        "📖 Type /help to see everything I can do."
    )

def cmd_help(args, state, changes) -> str:
    return (
        "🤖 <b>Commands</b>\n\n"
        "📊 <b>Info</b>\n"
        "  /status — Monitor health &amp; last run\n"
        "  /stats — Program statistics\n\n"
        "🔔 <b>Activity</b>\n"
        "  /latest — Last 5 changes\n"
        "  /new — Recently added programs\n"
        "  /changes — Last 15 changes\n\n"
        "🔎 <b>Search</b>\n"
        "  /search &lt;query&gt; — Search programs &amp; repos\n"
        "     e.g. /search wordpress · /search svg\n"
        "  /scope &lt;program&gt; — Show a program's source-code scope\n"
        "     e.g. /scope github\n\n"
        "🗂 <b>Browse</b>\n"
        "  /platform — Counts per platform\n"
        "  /platform &lt;name&gt; — hackerone | bugcrowd | intigriti | yeswehack\n"
        "  /source — Programs with SOURCE_CODE scope assets\n"
        "  /github — Programs with GitHub repos in scope\n\n"
        "⚙️ <b>Control</b>\n"
        "  /refresh — Force a monitor run now\n\n"
        "💡 Data refreshes every 30 min · replies within ~5 min"
    )

def cmd_status(args, state, changes) -> str:
    meta = state.get("_meta", {})
    programs = get_programs(state)
    if not programs and not meta:
        return "⚠️ No data yet — the monitor hasn't run. Wait for the next cycle or use /refresh."
    lines = [
        "🟢 <b>Monitor Status</b>", "",
        f"🐍 State schema   : v{meta.get('schema','?')}",
        f"🕒 Last run       : {fmt_when(meta.get('updated_at',''))} ({fmt_ts(meta.get('updated_at',''))})",
        f"📦 Total programs : {meta.get('total', len(programs))}",
        f"💰 Bounty + SC    : {meta.get('qualifying', len(qualifying(programs)))}",
        f"📜 Changes logged : {len(changes)}",
        f"🤖 Bot polled     : {datetime.now(timezone.utc).strftime('%d %b %H:%M UTC')}",
        "", "🔁 Monitor schedule: every 30 min · Bot poll: every 5 min",
    ]
    return "\n".join(lines)

def cmd_stats(args, state, changes) -> str:
    programs = get_programs(state)
    if not programs:
        return "⚠️ No data yet — wait for the next monitor cycle."
    qual = qualifying(programs)
    lines = ["📊 <b>Statistics</b>", "",
             f"📦 Total programs   : {len(programs)}",
             f"💰 Bounty + source  : {len(qual)}", "",
             "<b>Per platform</b>  <i>(bounty+SC / total)</i>"]
    for p in ["hackerone", "bugcrowd", "intigriti", "yeswehack"]:
        tot = sum(1 for v in programs.values() if v.get("platform") == p)
        q   = sum(1 for v in qual.values()      if v.get("platform") == p)
        lines.append(f"{PLATFORM_EMOJI.get(p,'⚪')} {p:12s} {q:3d} / {tot}")
    # top source-code hosts
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
    items = [c for c in changes if c.get("event") == "new_program"]
    if not items:
        return "🌿 No new programs yet. I'll ping you the moment one launches."
    out = _changes_list(items, 10)
    return out.replace("change(s)", "new program(s)")

def cmd_search(args, state, changes) -> str:
    if not args:
        return "🔎 Usage: <code>/search &lt;query&gt;</code>\ne.g. <code>/search wordpress</code>"
    q = args.lower()
    programs = get_programs(state)
    name_hits, repo_hits = [], []
    for k, v in programs.items():
        if not (v.get("bounty") and v.get("source")):
            continue
        if q in (v.get("name","").lower()) or q in (k.split(":",1)[-1].lower()):
            name_hits.append(v)
            continue
        for t in v.get("sc_targets", []):
            if q in (t.get("identifier","").lower()) or q in (t.get("description","").lower()):
                repo_hits.append((v, t)); break
    total = len(name_hits) + len(repo_hits)
    if total == 0:
        return f"🔍 No matches for <b>{esc(args)}</b> among bounty+source programs.\nTry /platform to browse, or /source &amp; /github."
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
    if total > 10:
        lines.append(f"\n… and {total - 10} more — refine your query")
    hint_prog = name_hits[0] if name_hits else (repo_hits[0][0] if repo_hits else None)
    if hint_prog:
        first_word = (hint_prog.get("name","") or "?").split()[0]
        lines.append(f"\n💡 Full scope: /scope {esc(first_word)}")
    return "\n".join(lines)

def cmd_platform(args, state, changes) -> str:
    programs = get_programs(state)
    qual = qualifying(programs)
    if not args:
        lines = ["🗂 <b>Programs per platform</b>  <i>(bounty+SC / total)</i>", ""]
        for p in ["hackerone", "bugcrowd", "intigriti", "yeswehack"]:
            tot = sum(1 for v in programs.values() if v.get("platform") == p)
            q   = sum(1 for v in qual.values()      if v.get("platform") == p)
            lines.append(f"{PLATFORM_EMOJI.get(p,'⚪')} <b>{p}</b> — {q} / {tot}")
        lines.append("\nUsage: <code>/platform hackerone</code>")
        return "\n".join(lines)
    p = args.lower().strip()
    if p not in PLATFORM_EMOJI:
        return (f"⚠️ Unknown platform \"{esc(args)}\"\n"
                f"Choose: hackerone · bugcrowd · intigriti · yeswehack")
    entries = sorted((v for v in qual.values() if v.get("platform") == p),
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
    for v in qualifying(programs).values():
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
    if len(matches) == 1 or all(m.get("name") == matches[0].get("name") for m in matches[:2]):
        v = matches[0]
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
    names = sorted({m.get("name","") for m in matches})[:10]
    more = f"\n… and {len(matches)-10} more" if len(matches) > 10 else ""
    return ("🔍 Multiple matches — be more specific:\n\n"
            + "\n".join(f"• {esc(n)}" for n in names) + more)

def cmd_refresh(args, state, changes) -> str:
    if not GH_PAT:
        return ("⚠️ /refresh needs a <b>GH_PAT</b> secret.\n\n"
                "Setup:\n"
                "1. github.com → Settings → Developer settings → "
                "Personal access tokens → <b>Generate new token</b>\n"
                "2. Scopes: <code>repo</code> + <code>workflow</code>\n"
                "3. Repo → Settings → Secrets → Actions → add <code>GH_PAT</code>\n\n"
                "Until then, data auto-refreshes every 30 min anyway.")
    try:
        r = requests.post(
            f"https://api.github.com/repos/{REPO}/actions/workflows/monitor.yml/dispatches",
            headers={"Authorization": f"Bearer {GH_PAT}",
                     "Accept": "application/vnd.github+json"},
            json={"ref": "main"}, timeout=15)
        if r.status_code == 204:
            return ("🔄 Monitor triggered!\n"
                    "📊 Fresh data in ~1 min — /status /stats /latest after that.")
        return f"⚠️ GitHub API error {r.status_code}: {esc(r.text[:200])}"
    except Exception as e:
        return f"⚠️ Refresh failed: {esc(e)}"

COMMANDS = {
    "start":   cmd_start,
    "help":    cmd_help,
    "status":  cmd_status,
    "stats":   cmd_stats,
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
    ("latest", "Last 5 changes"),
    ("new", "Recently added programs"),
    ("changes", "Last 15 changes"),
    ("search", "Search programs — /search wordpress"),
    ("platform", "Filter by platform — /platform hackerone"),
    ("source", "Programs with SOURCE_CODE assets"),
    ("github", "Programs with GitHub repos"),
    ("scope", "Program scope — /scope github"),
    ("refresh", "Force monitor run now"),
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
            return f"💥 Error handling /{esc(cmd)}: {esc(e)}"
    if cmd.isalpha() and text.startswith("/"):
        return f"🤔 Unknown command /{esc(cmd)} — try /help"
    return "👋 I respond to commands — type /help"

# ── Telegram I/O ───────────────────────────────────────────────────────────────

def tg_post(method: str, payload: dict, retries: int = 2):
    for i in range(retries + 1):
        try:
            r = requests.post(f"{API}/{method}", json=payload, timeout=15)
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
    # Telegram hard limit is 4096 chars — split on line boundaries
    while text:
        chunk, text = text[:3800], text[3800:]
        if text:
            cut = chunk.rfind("\n")
            if cut > 500:
                chunk, text = chunk[:cut], chunk[cut:] + text
        r = tg_post("sendMessage", {
            "chat_id": chat_id, "text": chunk,
            "parse_mode": "HTML", "disable_web_page_preview": True})
        ok = bool(r and r.ok)
        if ok:
            time.sleep(0.6)  # stay under 1 msg/sec per chat
    return ok

def set_menu():
    r = tg_post("setMyCommands", {"commands": [
        {"command": c, "description": d} for c, d in BOT_MENU]})
    if r and r.ok:
        print("  ✓ command menu registered")

def get_updates(offset: int) -> List[dict]:
    r = tg_post("getUpdates", {"offset": offset, "limit": 100, "timeout": 0}, retries=1)
    if r and r.ok:
        return r.json().get("result", [])
    return []

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'─'*50}\n  Telegram Bot — {datetime.now(timezone.utc).isoformat()}\n{'─'*50}")
    if not TELEGRAM_TOKEN:
        print("✗ TELEGRAM_TOKEN missing — aborting."); raise SystemExit(1)

    offset_data = load_json(OFFSET_FILE, {"last_update_id": 0})
    offset = int(offset_data.get("last_update_id", 0)) + 1
    save_json(OFFSET_FILE, {"last_update_id": max(0, offset - 1)})  # ensure file exists

    set_menu()

    state = load_json(STATE_FILE, {})
    changes = load_json(CHANGES_FILE, [])
    if not state:
        print("  ⚠ no state.json yet — monitor must run first")

    processed = 0
    while True:
        updates = get_updates(offset)
        if not updates:
            break
        for u in updates:
            offset = u["update_id"] + 1
            msg = u.get("message") or u.get("edited_message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            text = msg.get("text", "")
            if not chat_id or not text:
                continue
            # security: only talk to the configured owner chat
            if TELEGRAM_CHAT_ID and str(chat_id) != str(TELEGRAM_CHAT_ID):
                print(f"  ⛔ ignored chat {chat_id}")
                continue
            print(f"  ← {text[:60]}")
            send_reply(chat_id, handle_text(text, state, changes))
            processed += 1
        save_json(OFFSET_FILE, {"last_update_id": offset - 1})
        if len(updates) < 100:
            break

    print(f"  ✓ processed {processed} message(s), offset={offset-1}")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        print(f"\n💥 Fatal: {e}"); traceback.print_exc(); raise
