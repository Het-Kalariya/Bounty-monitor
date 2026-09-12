#!/usr/bin/env python3
"""
Bug Bounty Source Code Monitor
Monitors HackerOne, Bugcrowd, Intigriti, YesWeHack for:
  - Real monetary bounties
  - Source code (GitHub/GitLab) in scope
Enriches state.json with full program details for the Telegram bot.
"""

import hashlib, json, os, time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import requests

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATE_FILE       = "state.json"
CHANGES_FILE     = "changes_log.json"
MAX_CHANGES      = 200
SCHEMA_VERSION   = 2  # bump to force a silent re-baseline on format changes

PLATFORM_URLS: Dict[str, str] = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
SOURCE_CODE_SUBSTRINGS  = ["github.com/", "gitlab.com/", "bitbucket.org/",
                            "source code", "open-source", "open source"]
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡"}
EVENT_LABELS   = {
    "new_program":    ("🆕","New program — source code in scope + bounty"),
    "scope_added":    ("📦","Source code ADDED to in-scope"),
    "scope_updated":  ("🔄","Scope updated — still has source code"),
    "bounty_enabled": ("💰","Now paying bounties (has source code scope)"),
}

# ── Normalizers ────────────────────────────────────────────────────────────────

def _norm_scope(items, id_key, type_key, desc_key=""):
    out = []
    for t in items:
        out.append({
            "asset_type":  str(t.get(type_key, "") or ""),
            "identifier":  str(t.get(id_key,   "") or ""),
            "description": str(t.get(desc_key, "") or "") if desc_key else "",
        })
    return out

def _normalize(prog: dict, platform: str) -> Optional[dict]:
    try:
        s = prog.get("targets", {}).get("in_scope", [])
        if platform == "hackerone":
            h = prog.get("handle","")
            return {"handle":h,"name":prog.get("name",h),"url":f"https://hackerone.com/{h}",
                    "platform":platform,"has_bounty":bool(prog.get("offers_bounties",False)),
                    "in_scope":_norm_scope(s,"asset_identifier","asset_type","instruction")}
        if platform == "bugcrowd":
            n = prog.get("name",""); pay = prog.get("max_payout") or 0
            return {"handle":n,"name":n,"url":prog.get("url",""),"platform":platform,
                    "has_bounty":int(pay)>0,
                    "in_scope":_norm_scope(s,"target","type","name")}
        if platform == "intigriti":
            h = prog.get("handle",""); mb = prog.get("min_bounty") or {}
            bv = mb.get("value",0) if isinstance(mb,dict) else 0
            return {"handle":h,"name":prog.get("name",h),
                    "url":prog.get("url",f"https://app.intigriti.com/programs/{h}"),
                    "platform":platform,"has_bounty":(bv or 0)>0,
                    "in_scope":_norm_scope(s,"endpoint","type","description")}
        if platform == "yeswehack":
            n = prog.get("name",""); mb = prog.get("min_bounty") or 0
            slug = n.lower().replace(" ","-")
            return {"handle":slug,"name":n,"url":f"https://yeswehack.com/programs/{slug}",
                    "platform":platform,"has_bounty":(mb or 0)>0,
                    "in_scope":_norm_scope(s,"target","type")}
    except Exception as e:
        print(f"    [{platform}] normalize error: {e}")
    return None

# ── Helpers ────────────────────────────────────────────────────────────────────

def is_sc(t: dict) -> bool:
    if t.get("asset_type","").upper() in SOURCE_CODE_ASSET_TYPES: return True
    blob = (t.get("identifier","")+" "+t.get("description","")).lower()
    return any(s in blob for s in SOURCE_CODE_SUBSTRINGS)

def sc_targets(prog: dict) -> List[dict]:
    return [t for t in prog["in_scope"] if is_sc(t)]

def has_source(prog: dict) -> bool:
    return bool(sc_targets(prog))

def scope_hash(prog: dict) -> str:
    s = json.dumps(sorted(json.dumps(t,sort_keys=True) for t in prog["in_scope"]))
    return hashlib.sha1(s.encode()).hexdigest()

# ── Telegram ───────────────────────────────────────────────────────────────────

def tg_send(text: str, retries=3) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[TELEGRAM OFF] {text[:80]}"); return False
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    for i in range(retries):
        try:
            r = requests.post(url, json={"chat_id":TELEGRAM_CHAT_ID,"text":text,
                "parse_mode":"HTML","disable_web_page_preview":True}, timeout=15)
            if r.status_code == 429:
                time.sleep(r.json().get("parameters",{}).get("retry_after",30)); continue
            r.raise_for_status(); return True
        except Exception as e:
            print(f"  Telegram error ({i+1}): {e}"); time.sleep(5)
    return False

def build_message(prog: dict, platform: str, event: str) -> str:
    emoji,title = EVENT_LABELS.get(event,("🔔","Update"))
    sc = sc_targets(prog); ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"{emoji} <b>{title}</b>","",
             f"{PLATFORM_EMOJI.get(platform,'⚪')} <b>Platform:</b>  {platform.capitalize()}",
             f"📋 <b>Program:</b>   {prog['name']}",f"🔗 <b>URL:</b>       {prog['url']}","",
             f"📁 <b>Source Code Targets ({len(sc)}):</b>"]
    for t in sc[:6]:
        lines.append(f"  • <code>{t['identifier']}</code>  [{t['asset_type']}]")
    if len(sc)>6: lines.append(f"  … and {len(sc)-6} more")
    lines.append(f"\n⏰ {ts}")
    return "\n".join(lines)

# ── State & Changes ────────────────────────────────────────────────────────────

def load_state() -> dict:
    return json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}

def save_state(state: dict):
    json.dump(state, open(STATE_FILE,"w"), indent=2)

def load_changes() -> list:
    return json.load(open(CHANGES_FILE)) if os.path.exists(CHANGES_FILE) else []

def append_change(changes: list, prog: dict, platform: str, event: str):
    changes.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event":     event,
        "platform":  platform,
        "handle":    prog["handle"],
        "name":      prog["name"],
        "url":       prog["url"],
        "sc_targets": sc_targets(prog)[:8],
    })
    if len(changes) > MAX_CHANGES:
        changes[:] = changes[-MAX_CHANGES:]

def save_changes(changes: list):
    json.dump(changes, open(CHANGES_FILE,"w"), indent=2)

# ── Fetch ──────────────────────────────────────────────────────────────────────

def fetch(platform: str, url: str) -> List[dict]:
    try:
        r = requests.get(url, timeout=45); r.raise_for_status()
        raw = r.json()
        out = [n for item in raw if (n := _normalize(item, platform))]
        print(f"  ✓ {platform:12s} → {len(out):4d} programs"); return out
    except Exception as e:
        print(f"  ✗ {platform:12s} → ERROR: {e}"); return []

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'─'*58}\n  Bug Bounty Source Code Monitor\n  {datetime.now(timezone.utc).isoformat()}\n{'─'*58}\n")
    prev = load_state()
    # Old/incompatible state format → silent re-baseline (prevents notification floods)
    first_run = (not prev) or prev.get("_meta", {}).get("schema") != SCHEMA_VERSION
    changes = load_changes()
    new_state: dict = {}
    events: List[Tuple[dict,str,str]] = []

    if first_run: print("📌 FIRST RUN / SCHEMA UPGRADE — building baseline\n")
    print("Fetching platforms…")

    for platform, url in PLATFORM_URLS.items():
        for prog in fetch(platform, url):
            key = f"{platform}:{prog['handle']}"
            h   = scope_hash(prog)
            hb  = prog["has_bounty"]
            hs  = has_source(prog)
            sc  = sc_targets(prog)

            new_state[key] = {
                "hash": h, "bounty": hb, "source": hs,
                "name": prog["name"], "url": prog["url"], "platform": platform,
                "sc_targets": sc[:10],
            }

            if first_run or not (hb and hs): continue
            p = prev.get(key)
            if p is None:
                events.append((prog, platform, "new_program"))
            elif p["hash"] != h:
                was = p.get("source", False)
                events.append((prog, platform, "scope_added" if (hs and not was) else "scope_updated"))
            elif not p.get("bounty") and hb:
                events.append((prog, platform, "bounty_enabled"))

    total = len(new_state)
    qualifying = sum(1 for v in new_state.values() if v["bounty"] and v["source"])
    new_state["_meta"] = {
        "schema": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "qualifying": qualifying,
    }
    save_state(new_state)
    print(f"\n📊 {qualifying} programs match (bounty + source) out of {total} total\n")

    if first_run:
        tg_send(f"✅ <b>Bug Bounty Monitor is LIVE!</b>\n\n"
                f"📊 <b>Baseline snapshot:</b>\n"
                f"  • Total programs tracked : {total}\n"
                f"  • Bounty + source code   : {qualifying}\n\n"
                f"🔔 Notifying on new programs, scope changes, bounty changes\n"
                f"🤖 Bot ready — type /help in Telegram\n"
                f"🔁 Checks every 30 min\n"
                f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        save_changes(changes)
        print("✅ Baseline done.\n"); return

    print(f"📬 Sending {len(events)} notification(s)…")
    for prog, platform, event in events:
        append_change(changes, prog, platform, event)
        tg_send(build_message(prog, platform, event)); time.sleep(1)
    if not events: print("  ✓ No changes this cycle.")

    save_changes(changes)
    print("\n✅ Done.\n")

if __name__ == "__main__":
    try: main()
    except Exception as e:
        import traceback; print(f"\n💥 Fatal: {e}"); traceback.print_exc(); raise
