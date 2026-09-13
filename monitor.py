#!/usr/bin/env python3
"""
Bug Bounty Source Code Monitor — v3 (worldwide)
Big platforms (full scope analysis):
  HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy
Worldwide index (program-level watch, catches HackenProof, BugBountyCH,
direct/self-hosted programs):
  ProjectDiscovery Chaos — 800+ programs
Notifies on:
  - new program with bounty + source code in scope
  - source code added to an existing program
  - program starts paying bounties
  - new bounty program discovered outside major platforms
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
SCHEMA_VERSION   = 6  # bump to force a silent re-baseline on format changes

PLATFORM_URLS: Dict[str, str] = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "federacy":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json",
}
CHAOS_URL = "https://chaos-data.projectdiscovery.io/index.json"
MAJOR_PLATFORMS = set(PLATFORM_URLS)

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
SOURCE_CODE_SUBSTRINGS  = ["github.com/", "gitlab.com/", "bitbucket.org/",
                            "source code", "open-source", "open source"]
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡",
                   "federacy":"🟣","chaos":"🌍"}
EVENT_LABELS   = {
    "new_program":    ("🆕","New program — source code in scope + bounty"),
    "scope_added":    ("📦","Source code ADDED to in-scope"),
    "scope_updated":  ("🔄","Scope updated — still has source code"),
    "bounty_enabled": ("💰","Now paying bounties (has source code scope)"),
    "new_external":   ("🌍","New bounty program — outside major platforms"),
    "new_repo":       ("🐙","New GitHub repo in scope"),
}

# ── Normalizers ────────────────────────────────────────────────────────────────

def _norm_scope(items, id_key, type_key, desc_key=""):
    out = []
    for t in items or []:
        out.append({
            "asset_type":  str(t.get(type_key, "") or ""),
            "identifier":  str(t.get(id_key,   "") or ""),
            "description": str(t.get(desc_key, "") or "") if desc_key else "",
        })
    return out

def _normalize(prog: dict, platform: str) -> Optional[dict]:
    """Returns program dict with has_bounty + bounty_min/max/ccy (0/'' = unknown)."""
    try:
        s = prog.get("targets", {}).get("in_scope", [])
        bmin = bmax = 0
        ccy = ""
        if platform == "hackerone":
            h = prog.get("handle","")
            return {"handle":h,"name":prog.get("name",h),"url":f"https://hackerone.com/{h}",
                    "platform":platform,"has_bounty":bool(prog.get("offers_bounties",False)),
                    "bounty_min":0,"bounty_max":0,"bounty_ccy":"",
                    "resp_eff":prog.get("response_efficiency_percentage"),
                    "bounty_days":prog.get("average_time_to_bounty_awarded"),
                    "in_scope":_norm_scope(s,"asset_identifier","asset_type","instruction")}
        if platform == "bugcrowd":
            n = prog.get("name",""); pay = prog.get("max_payout") or 0
            return {"handle":n,"name":n,"url":prog.get("url",""),"platform":platform,
                    "has_bounty":int(pay)>0,
                    "bounty_min":0,"bounty_max":int(pay),"bounty_ccy":"USD" if pay else "",
                    "in_scope":_norm_scope(s,"target","type","name")}
        if platform == "intigriti":
            h = prog.get("handle","")
            mn = prog.get("min_bounty") or {}; mx = prog.get("max_bounty") or {}
            bmin = int(mn.get("value",0) or 0) if isinstance(mn,dict) else 0
            bmax = int(mx.get("value",0) or 0) if isinstance(mx,dict) else 0
            ccy  = str(mx.get("currency","") or "") if isinstance(mx,dict) else ""
            return {"handle":h,"name":prog.get("name",h),
                    "url":prog.get("url",f"https://app.intigriti.com/programs/{h}"),
                    "platform":platform,"has_bounty":(bmin or bmax)>0,
                    "bounty_min":bmin,"bounty_max":bmax,"bounty_ccy":ccy,
                    "in_scope":_norm_scope(s,"endpoint","type","description")}
        if platform == "yeswehack":
            n = prog.get("name",""); mb = prog.get("min_bounty") or 0
            mx = prog.get("max_bounty") or 0
            slug = n.lower().replace(" ","-")
            return {"handle":slug,"name":n,"url":f"https://yeswehack.com/programs/{slug}",
                    "platform":platform,"has_bounty":(mb or mx)>0,
                    "bounty_min":int(mb),"bounty_max":int(mx),"bounty_ccy":"EUR" if (mb or mx) else "",
                    "in_scope":_norm_scope(s,"target","type")}
        if platform == "federacy":
            n = prog.get("name","")
            return {"handle":n,"name":n,"url":prog.get("url",""),"platform":platform,
                    "has_bounty":bool(prog.get("offers_awards",False)),
                    "bounty_min":0,"bounty_max":0,"bounty_ccy":"",
                    "in_scope":_norm_scope(s,"target","type")}
    except Exception as e:
        print(f"    [{platform}] normalize error: {e}")
    return None

def _normalize_chaos(e: dict) -> Optional[dict]:
    """Chaos index entry → external program record."""
    try:
        name = str(e.get("name","") or "").strip()
        if not name: return None
        platform = str(e.get("platform","") or "").strip() or "direct"
        return {
            "handle":  name.lower().replace(" ","-"),
            "name":    name,
            "url":     str(e.get("program_url") or e.get("URL") or ""),
            "platform":"chaos",
            "origin":  platform,               # hackenproof / bugbountych / direct / ...
            "has_bounty": bool(e.get("bounty", False)),
            "domains":  int(e.get("count", 0) or 0),   # in-scope domain count
            "in_scope": [],
        }
    except Exception:
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

def norm_id(identifier: str) -> str:
    """Canonical form for diffing: lowercase, strip trailing slash/whitespace."""
    return (identifier or "").strip().rstrip("/").lower()

def sc_ids_list(prog: dict) -> List[str]:
    """Full sorted normalized ids of source-code targets (not truncated)."""
    return sorted({norm_id(t.get("identifier","")) for t in sc_targets(prog) if norm_id(t.get("identifier",""))})

def github_repos_list(prog: dict) -> List[str]:
    """Extract github.com/org/repo from source-code target identifiers."""
    repos = set()
    for t in sc_targets(prog):
        ident = (t.get("identifier") or "").lower()
        m = ident.find("github.com/")
        if m == -1:
            continue
        rest = ident[m + len("github.com/"):].strip().strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) >= 2:
            repos.add(f"{parts[0]}/{parts[1]}")
    return sorted(repos)

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
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if event == "new_external":
        return "\n".join([
            f"{emoji} <b>{title}</b>","",
            f"📋 <b>Program:</b>   {prog['name']}",
            f"🌐 <b>Found via:</b>  {prog.get('origin','direct')} (worldwide index)",
            f"🔗 <b>URL:</b>       {prog['url']}","",
            "ℹ️ No scope detail in the worldwide index — check the program page",
            f"\n⏰ {ts}",
        ])
    sc = sc_targets(prog)
    lines = [f"{emoji} <b>{title}</b>","",
             f"{PLATFORM_EMOJI.get(platform,'⚪')} <b>Platform:</b>  {platform.capitalize()}",
             f"📋 <b>Program:</b>   {prog['name']}",f"🔗 <b>URL:</b>       {prog['url']}",""]
    if event == "new_repo":
        gh_new = prog.get("_github_new", []) or []
        if gh_new:
            lines.append(f"🐙 <b>New repos ({len(gh_new)}):</b>")
            for r in gh_new[:6]:
                lines.append(f"  • <code>github.com/{r}</code>")
            if len(gh_new) > 6: lines.append(f"  … and {len(gh_new)-6} more")
        else:
            lines.append(f"📁 <b>Source Code Targets ({len(sc)}):</b>")
            for t in sc[:6]:
                lines.append(f"  • <code>{t['identifier']}</code>  [{t['asset_type']}]")
    elif event in ("scope_added", "scope_updated"):
        added = prog.get("_added", []) or []
        removed = prog.get("_removed", []) or []
        if added:
            lines.append(f"➕ <b>Added ({len(added)}):</b>")
            for a in added[:6]:
                lines.append(f"  • <code>{a}</code>")
            if len(added) > 6: lines.append(f"  … and {len(added)-6} more")
            lines.append("")
        if removed:
            lines.append(f"➖ <b>Removed ({len(removed)}):</b>")
            for r in removed[:4]:
                lines.append(f"  • <code>{r}</code>")
            if len(removed) > 4: lines.append(f"  … and {len(removed)-4} more")
            lines.append("")
        if not added and not removed:
            lines.append(f"📁 <b>Source Code Targets ({len(sc)}):</b>")
            for t in sc[:6]:
                lines.append(f"  • <code>{t['identifier']}</code>  [{t['asset_type']}]")
            if len(sc)>6: lines.append(f"  … and {len(sc)-6} more")
    else:
        lines.append(f"📁 <b>Source Code Targets ({len(sc)}):</b>")
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
        "added":     list(prog.get("_added", []) or [])[:20],
        "removed":   list(prog.get("_removed", []) or [])[:20],
        "github_repos": list(prog.get("_github_new", []) or [])[:20],
    })
    if len(changes) > MAX_CHANGES:
        changes[:] = changes[-MAX_CHANGES:]

def save_changes(changes: list):
    json.dump(changes, open(CHANGES_FILE,"w"), indent=2)

# ── Fetch ──────────────────────────────────────────────────────────────────────

def fetch(platform: str, url: str) -> Optional[List[dict]]:
    """None = fetch failed (caller must carry over previous state)."""
    try:
        r = requests.get(url, timeout=45); r.raise_for_status()
        raw = r.json()
        out = [n for item in raw if (n := _normalize(item, platform))]
        print(f"  ✓ {platform:12s} → {len(out):4d} programs"); return out
    except Exception as e:
        print(f"  ✗ {platform:12s} → ERROR: {e}"); return None

def fetch_chaos() -> Optional[List[dict]]:
    try:
        r = requests.get(CHAOS_URL, timeout=45); r.raise_for_status()
        raw = r.json()
        out = [n for e in raw if (n := _normalize_chaos(e)) and n["has_bounty"]]
        print(f"  ✓ {'chaos':12s} → {len(out):4d} bounty programs (worldwide)")
        return out
    except Exception as e:
        print(f"  ✗ {'chaos':12s} → ERROR: {e}"); return None

def carry_over(prev: dict, new_state: dict, prefix: str) -> int:
    stale = {k: v for k, v in prev.items() if k.startswith(prefix)}
    new_state.update(stale)
    return len(stale)

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'─'*58}\n  Bug Bounty Source Code Monitor v3 (worldwide)\n  {datetime.now(timezone.utc).isoformat()}\n{'─'*58}\n")
    prev = load_state()
    # Old/incompatible state format → silent re-baseline (prevents notification floods)
    first_run = (not prev) or prev.get("_meta", {}).get("schema") != SCHEMA_VERSION
    changes = load_changes()
    new_state: dict = {}
    events: List[Tuple[dict,str,str]] = []

    if first_run: print("📌 FIRST RUN / SCHEMA UPGRADE — building baseline\n")
    print("Fetching worldwide index (domain counts)…")
    chaos = fetch_chaos()
    # name → in-scope domain count (competition proxy: surface per researcher)
    chaos_domains = {}
    if chaos is None:
        pass  # fetched later; carry-over handled below
    else:
        for prog in chaos:
            chaos_domains[prog["name"].lower()] = max(
                chaos_domains.get(prog["name"].lower(), 0), prog.get("domains", 0))

    print("Fetching platforms…")

    # ── Big platforms: full scope analysis ──
    for platform, url in PLATFORM_URLS.items():
        progs = fetch(platform, url)
        if progs is None:
            n = carry_over(prev, new_state, f"{platform}:")
            print(f"  ↻ {platform} unavailable — carried over {n} stale entries (no events)")
            continue
        for prog in progs:
            key = f"{platform}:{prog['handle']}"
            h   = scope_hash(prog)
            hb  = prog["has_bounty"]
            sc  = sc_targets(prog)
            hs  = bool(sc)
            ids = sc_ids_list(prog)
            gh  = github_repos_list(prog)

            new_state[key] = {
                "hash": h, "bounty": hb, "source": hs,
                "name": prog["name"], "url": prog["url"], "platform": platform,
                "bounty_min": prog.get("bounty_min", 0),
                "bounty_max": prog.get("bounty_max", 0),
                "bounty_ccy": prog.get("bounty_ccy", ""),
                "domains": chaos_domains.get(prog["name"].lower(), 0),
                "resp_eff": prog.get("resp_eff"),
                "bounty_days": prog.get("bounty_days"),
                "sc_targets": sc[:10],
                "sc_ids": ids,
                "github_repos": gh,
            }

            if first_run or not (hb and hs): continue
            p = prev.get(key)
            if p is None:
                events.append((prog, platform, "new_program"))
            elif p.get("hash") != h:
                old_ids = set(p.get("sc_ids") or [])
                new_ids = set(ids)
                added = sorted(new_ids - old_ids)[:20]
                removed = sorted(old_ids - new_ids)[:20]
                # fallback for pre-v6 states without sc_ids: diff display targets
                if not old_ids and not added:
                    added = [norm_id(t.get("identifier","")) for t in sc[:20]
                             if norm_id(t.get("identifier",""))]
                old_gh = set(p.get("github_repos") or [])
                gh_new = sorted(set(gh) - old_gh)[:20]
                prog["_added"] = added
                prog["_removed"] = removed
                prog["_github_new"] = gh_new
                was = p.get("source", False)
                events.append((prog, platform, "scope_added" if (hs and not was) else "scope_updated"))
                if gh_new:
                    events.append((prog, platform, "new_repo"))
            elif not p.get("bounty") and hb:
                events.append((prog, platform, "bounty_enabled"))
            else:
                # hash unchanged but v6 adds repo tracking: catch repos missed pre-v6
                old_gh = set((p.get("github_repos") or []))
                gh_new = sorted(set(gh) - old_gh)[:20]
                if gh_new and p.get("sc_ids") is None:
                    prog["_added"] = []
                    prog["_removed"] = []
                    prog["_github_new"] = gh_new
                    events.append((prog, platform, "new_repo"))

    # Names already covered by big platforms (avoid duplicate chaos entries)
    known_names = {v.get("name","").lower() for k, v in new_state.items()}

    # ── Worldwide index: program-level watch ──
    if chaos is None:
        n = carry_over(prev, new_state, "chaos:")
        print(f"  ↻ chaos unavailable — carried over {n} stale entries (no events)")
    else:
        seen = set()
        for prog in chaos:
            if prog["name"].lower() in known_names: continue
            key = f"chaos:{prog['handle']}"
            if key in seen: continue
            seen.add(key)
            new_state[key] = {
                "hash": "", "bounty": True, "source": False,
                "name": prog["name"], "url": prog["url"], "platform": "chaos",
                "origin": prog["origin"], "bounty_min": 0, "bounty_max": 0, "bounty_ccy": "",
                "domains": prog.get("domains", 0), "resp_eff": None, "bounty_days": None,
                "sc_targets": [],
            }
            if first_run or prev.get(key): continue
            events.append((prog, "chaos", "new_external"))

    total = sum(1 for k in new_state if k != "_meta")
    qualifying = sum(1 for k, v in new_state.items() if k != "_meta" and v.get("bounty") and v.get("source"))
    external = sum(1 for k in new_state if k.startswith("chaos:"))
    new_state["_meta"] = {
        "schema": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": total, "qualifying": qualifying, "external": external,
    }
    save_state(new_state)
    print(f"\n📊 {qualifying} bounty+source · {external} worldwide programs · {total} total\n")

    if first_run:
        tg_send(f"✅ <b>Bug Bounty Monitor v3 is LIVE! (worldwide)</b>\n\n"
                f"📊 <b>Baseline snapshot:</b>\n"
                f"  • Bounty + source code      : {qualifying}\n"
                f"  • Worldwide (outside big-5) : {external}\n"
                f"  • Total programs tracked    : {total}\n\n"
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
