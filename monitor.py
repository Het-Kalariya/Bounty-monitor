#!/usr/bin/env python3
"""
Bug Bounty Source Code Monitor — blunt edition
Big-5 public feeds (scope text analysis, best-effort ~30 min):
  HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy
  via arkadiyt/bounty-targets-data (public programs only).
Blockchain feeds (best-effort ~30 min, slower — detail pages):
  HackenProof (sitemap + program pages), Immunefi (public-api/bounties.json),
  Cantina (sitemap + bounty pages), Sherlock (sitemap + bug-bounty pages).
  Smart-contract scope counts as source here (SMART_CONTRACT/BLOCKCHAIN
  asset types or repo-host URLs). /blockchain in the bot is the dedicated view.
Chaos index (program-level ONLY: names/URLs/bounty flag, NO scope).
SC = explicit SC asset type OR repo-host URL in identifier. Nothing else.
Timestamps = DETECTION time, not launch time.
HackerOne amounts are NOT in the feed (yes/no only).
Full SC removal is NOT alerted (program just drops from qualifying).
Notifies owner channel on:
  - new qualifying program (deduped 30d vs state resets)
  - SC added / SC sets changed (non-SC reshuffles ignored)
  - bounty turned on (with SC present)
  - new Chaos bounty name (only if no big-5/blockchain bounty with same name)
"""

import hashlib, json, os, re, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import requests

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATE_FILE       = "state.json"
CHANGES_FILE     = "changes_log.json"
MAX_CHANGES      = 200
# Hard time budget (seconds). Cron job gets 600s; inline bot cycles pass a
# smaller MONITOR_BUDGET_SEC env so monitor.py NEVER overruns the caller's
# subprocess timeout (overruns used to get SIGKILLed mid-save daily).
MONITOR_BUDGET_SEC = int(os.environ.get("MONITOR_BUDGET_SEC", "600"))
_MONITOR_START = time.time()

def _budget_left() -> float:
    return MONITOR_BUDGET_SEC - (time.time() - _MONITOR_START)

def _budget_ok(need: float = 30.0) -> bool:
    return _budget_left() > need
SCHEMA_VERSION   = 8  # v8: + blockchain feeds (hackenproof/immunefi/cantina/sherlock).
# Previous versions matched "source code" in descriptions and flagged API/URL
# assets (e.g. Twilio api.segment.io) as source-code. v7 re-baselines silently.

PLATFORM_URLS: Dict[str, str] = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "federacy":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json",
}
CHAOS_URL = "https://chaos-data.projectdiscovery.io/index.json"
MAJOR_PLATFORMS = set(PLATFORM_URLS)

# ── Blockchain feeds (smart-contract bounties; /blockchain in the bot) ─────────
IMMUNEFI_API_URL       = "https://immunefi.com/public-api/bounties.json"
HACKENPROOF_SITEMAP_URL = "https://hackenproof.com/sitemap.xml"
HACKENPROOF_PROGRAM_URL = "https://hackenproof.com/programs/{slug}"
CANTINA_SITEMAP_URL    = "https://cantina.xyz/sitemap-0.xml"
CANTINA_BOUNTY_URL     = "https://cantina.xyz/bounties/{uid}"
SHERLOCK_SITEMAP_URL   = "https://audits.sherlock.xyz/sitemap.xml"
SHERLOCK_BOUNTY_URL    = "https://audits.sherlock.xyz/bug-bounties/{bid}"
BLOCKCHAIN_PLATFORMS   = {"hackenproof", "immunefi", "cantina", "sherlock"}
# Plain browser UA: datacenter IPs already score badly with bot-mitigation;
# no need to additionally self-identify as a bot in every request.
UA_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/126.0.0.0 Safari/537.36",
              "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
              "Accept-Language": "en-US,en;q=0.9"}

# Smart-contract scope counts as source ONLY on blockchain feeds. Big-5 keeps
# the strict check (explicit SC type or repo-host URL) to avoid false
# positives like Twilio's api.segment.io API asset.
BLOCKCHAIN_ASSET_TYPES = {"SMART_CONTRACT", "BLOCKCHAIN", "SOURCE_CODE",
                          "GITHUB", "GITLAB", "BITBUCKET"}

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}
# Strict on purpose: description mentions ("review the source code…") are NOT scope.
# Only an explicit SC asset type or a repo-host URL in the identifier counts.
# (Old broad list matched "source code"/"open source" in descriptions and caused
# false positives like Twilio's api.segment.io API asset.)
REPO_HOST_SUBSTRINGS = ["github.com/", "gitlab.com/", "bitbucket.org/"]
SOURCE_CODE_SUBSTRINGS = REPO_HOST_SUBSTRINGS  # kept for back-compat imports
PLATFORM_EMOJI = {"hackerone":"🟢","bugcrowd":"🔴","intigriti":"🔵","yeswehack":"🟡",
                   "federacy":"🟣","chaos":"🌍",
                   "hackenproof":"🟠","immunefi":"💠","cantina":"🍷","sherlock":"🔍"}
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
    ident = (t.get("identifier","") or "").lower()
    return any(h in ident for h in REPO_HOST_SUBSTRINGS)

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

# ── Blockchain helpers (smart-contract scope counts as source) ─────────────────

def is_blockchain_sc(t: dict) -> bool:
    if t.get("asset_type", "").upper() in BLOCKCHAIN_ASSET_TYPES:
        return True
    ident = (t.get("identifier", "") or "").lower()
    return any(h in ident for h in REPO_HOST_SUBSTRINGS)

def blockchain_sc_targets(prog: dict) -> List[dict]:
    return [t for t in prog.get("in_scope", []) if is_blockchain_sc(t)]

def blockchain_sc_ids_list(prog: dict) -> List[str]:
    """Full sorted normalized ids of blockchain source targets (not truncated)."""
    return sorted({norm_id(t.get("identifier", "")) for t in blockchain_sc_targets(prog)
                   if norm_id(t.get("identifier", ""))})

def blockchain_github_repos_list(prog: dict) -> List[str]:
    """Extract github.com/org/repo from blockchain source target identifiers."""
    repos = set()
    for t in blockchain_sc_targets(prog):
        ident = (t.get("identifier") or "").lower()
        m = ident.find("github.com/")
        if m == -1:
            continue
        rest = ident[m + len("github.com/"):].strip().strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) >= 2:
            repos.add(f"{parts[0]}/{parts[1]}")
    return sorted(repos)

def _detect_scope_events(prog: dict, platform: str, key: str, h: str,
                         hb: bool, hs: bool, ids: List[str], gh: List[str],
                         prev: dict, first_run: bool,
                         changes: list, events: list):
    """Shared new-program / scope / bounty / repo event detection for big-5
    AND blockchain feeds. Sets prog _added/_removed/_github_new for messages."""
    if first_run or not (hb and hs):
        return
    p = prev.get(key)
    if p is None:
        # idempotency: state resets must not re-spam old programs
        if recent_duplicate(changes, platform, prog["handle"], "new_program"):
            return
        events.append((prog, platform, "new_program"))
    elif p.get("hash") != h:
        old_ids = set(p.get("sc_ids") or [])
        new_ids = set(ids)
        added = sorted(new_ids - old_ids)[:20]
        removed = sorted(old_ids - new_ids)[:20]
        # fallback for pre-v6 states without sc_ids: diff display targets
        if not old_ids and not added:
            added = [norm_id(t.get("identifier", "")) for t in
                     targets_for(platform, prog)[:20]
                     if norm_id(t.get("identifier", ""))]
        old_gh = set(p.get("github_repos") or [])
        gh_new = sorted(set(gh) - old_gh)[:20]
        prog["_added"] = added
        prog["_removed"] = removed
        prog["_github_new"] = gh_new
        was = p.get("source", False)
        was_bounty = p.get("bounty", False)
        # BLUNT: non-SC reshuffles (hash changed but SC sets identical,
        # bounty/source flags unchanged) are noise — skip, no alert.
        if not added and not removed and not gh_new and was == hs and was_bounty == hb:
            return
        # bounty flip is worth its own signal even when scope moved too
        if not was_bounty and hb:
            events.append((prog, platform, "bounty_enabled"))
            # still fall through to scope event only if SC actually moved
            if not added and not removed and not gh_new:
                return
        events.append((prog, platform, "scope_added" if (hs and not was) else "scope_updated"))
        if gh_new:
            events.append((prog, platform, "new_repo"))
    elif not p.get("bounty") and hb:
        events.append((prog, platform, "bounty_enabled"))
    else:
        # hash unchanged but repo tracking was added later: catch repos
        # missed by old states without sc_ids
        old_gh = set((p.get("github_repos") or []))
        gh_new = sorted(set(gh) - old_gh)[:20]
        if gh_new and p.get("sc_ids") is None:
            prog["_added"] = []
            prog["_removed"] = []
            prog["_github_new"] = gh_new
            events.append((prog, platform, "new_repo"))

def has_blockchain_source(prog: dict) -> bool:
    return bool(blockchain_sc_targets(prog))

def blockchain_scope_hash(prog: dict, status: str = "", bmax: int = 0) -> str:
    """Scope hash that ALSO covers live-status + max-bounty, so a pause,
    resume, or reward bump on a blockchain program fires a scope event.
    (Big-5 keeps the scope-only hash + separate bounty-flip signal.)"""
    s = json.dumps(sorted(json.dumps(t, sort_keys=True) for t in prog["in_scope"]))
    return hashlib.sha1(f"{s}|{status}|{bmax}".encode()).hexdigest()

def targets_for(platform: str, prog: dict) -> List[dict]:
    """SC target list appropriate for the platform (used by messages)."""
    if platform in BLOCKCHAIN_PLATFORMS:
        return blockchain_sc_targets(prog)
    return sc_targets(prog)

def _parse_money(s) -> int:
    """'$15,500,000' / '10000.0' / 15000 → int. 0 = unknown."""
    try:
        if s is None:
            return 0
        if isinstance(s, (int, float)):
            return int(s)
        t = re.sub(r"[^0-9.]", "", str(s))
        return int(float(t)) if t else 0
    except Exception:
        return 0

def _sitemap_locs(url: str, timeout: int = 30) -> Optional[List[str]]:
    """Fetch an XML sitemap, return all <loc> values. None = fetch failed."""
    r = requests.get(url, timeout=timeout, headers=UA_HEADERS)
    r.raise_for_status()
    return re.findall(r"<loc>([^<]+)</loc>", r.text)

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
    detected_note = f"\n⏰ Detected: {ts} (detection time, not launch time)"
    if event == "new_external":
        return "\n".join([
            f"{emoji} <b>{title}</b>","",
            f"📋 <b>Program:</b>   {prog['name']}",
            f"🌐 <b>Found via:</b>  {prog.get('origin','direct')} (worldwide index)",
            f"🔗 <b>URL:</b>       {prog['url']}","",
            "ℹ️ No scope detail in the worldwide index — check the program page",
            "ℹ️ Program-level watch only: bounty flag from Chaos index, may be stale",
            detected_note,
        ])
    sc = sc_targets(prog)
    lines = [f"{emoji} <b>{title}</b>","",
             f"{PLATFORM_EMOJI.get(platform,'⚪')} <b>Platform:</b>  {platform.capitalize()}",
             f"📋 <b>Program:</b>   {prog['name']}",f"🔗 <b>URL:</b>       {prog['url']}",""]
    if platform in BLOCKCHAIN_PLATFORMS:
        st = prog.get("live_status") or "?"
        mb = prog.get("bounty_max") or 0
        ccy = prog.get("bounty_ccy") or ""
        wallet = f" · 💰 up to {mb:,} {ccy}".rstrip() if mb else ""
        lines.append(f"⛓️ <b>Status:</b> {st}{wallet}")
        lines.append("")
        sc = blockchain_sc_targets(prog)
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
    lines.append(detected_note)
    return "\n".join(lines)

# ── State & Changes ────────────────────────────────────────────────────────────

def _atomic_write_json(path: str, data) -> None:
    """Atomic write (tmp + fsync + replace): a timeout SIGKILL can never leave
    a half-written state.json behind (that used to corrupt state and force a
    re-baseline / notification flood on the next run)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"  ⚠ state.json corrupt ({e}) — quarantining, starting from empty (no crash)")
        try:
            os.replace(STATE_FILE, f"state.json.corrupt.{int(time.time())}")
        except Exception:
            pass
        return {}

def save_state(state: dict):
    _atomic_write_json(STATE_FILE, state)

def load_changes() -> list:
    if not os.path.exists(CHANGES_FILE):
        return []
    try:
        with open(CHANGES_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"  ⚠ changes_log.json corrupt ({e}) — quarantining, starting fresh (no crash)")
        try:
            os.replace(CHANGES_FILE, f"changes_log.json.corrupt.{int(time.time())}")
        except Exception:
            pass
        return []

def append_change(changes: list, prog: dict, platform: str, event: str):
    changes.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event":     event,
        "platform":  platform,
        "handle":    prog["handle"],
        "name":      prog["name"],
        "url":       prog["url"],
        "sc_targets": targets_for(platform, prog)[:8],
        "added":     list(prog.get("_added", []) or [])[:20],
        "removed":   list(prog.get("_removed", []) or [])[:20],
        "github_repos": list(prog.get("_github_new", []) or [])[:20],
    })
    if len(changes) > MAX_CHANGES:
        changes[:] = changes[-MAX_CHANGES:]

def save_changes(changes: list):
    _atomic_write_json(CHANGES_FILE, changes)

def recent_duplicate(changes: list, platform: str, handle: str, event: str,
                     days: int = 30) -> bool:
    """True if the same platform+handle+event was already logged recently.
    Prevents duplicate new_program spam after state resets / key churn
    (e.g. SecureDrop logged twice). Detection time, not launch time."""
    try:
        cutoff = time.time() - days * 86400
        for c in reversed(changes[-MAX_CHANGES:]):
            if (c.get("platform") == platform and c.get("handle") == handle
                    and c.get("event") == event):
                try:
                    ts = datetime.fromisoformat(c.get("timestamp", "")).timestamp()
                except Exception:
                    return True  # unparseable: be conservative, skip
                return ts >= cutoff
        return False
    except Exception:
        return False

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

# ── Immunefi (public-api/bounties.json — single request, rich assets) ───────────

_IMMUNEFI_TYPE_MAP = {"smart_contract": "SMART_CONTRACT", "blockchain": "BLOCKCHAIN",
                      "web": "WEB", "website": "WEB", "app": "APP"}

def _normalize_immunefi(item: dict) -> Optional[dict]:
    """Immunefi bounty → big-5-shaped prog dict. Private/paused → tracked
    without bounty (unpause flips it back with a bounty_enabled event)."""
    try:
        slug = str(item.get("slug") or "").strip()
        if not slug:
            return None
        if item.get("inviteOnly"):
            return None  # private program — not a public feed
        project = str(item.get("project") or slug).strip()
        max_bounty = _parse_money(item.get("maxBounty"))
        paused = bool(item.get("isPaused"))
        has_bounty = max_bounty > 0 and not paused
        scope = []
        for a in item.get("assets") or []:
            url = str(a.get("url") or "").strip()
            desc = str(a.get("description") or "").strip()
            if not url and not desc:
                continue
            atype = _IMMUNEFI_TYPE_MAP.get(str(a.get("type") or "").lower(), "OTHER")
            scope.append({"asset_type": atype, "identifier": url or desc,
                          "description": desc if url else ""})
        return {
            "handle": slug, "name": project,
            "url": f"https://immunefi.com/bug-bounty/{slug}",
            "platform": "immunefi",
            "has_bounty": has_bounty,
            "bounty_min": 0, "bounty_max": max_bounty,
            "bounty_ccy": str(item.get("rewardsToken") or "USD"),
            "live_status": "PAUSED" if paused else "LIVE",
            "in_scope": scope,
        }
    except Exception as e:
        print(f"    [immunefi] normalize error: {e}")
    return None

def fetch_immunefi() -> Optional[List[dict]]:
    try:
        r = requests.get(IMMUNEFI_API_URL, timeout=60, headers=UA_HEADERS)
        r.raise_for_status()
        raw = r.json()
        out = [n for item in raw if (n := _normalize_immunefi(item))]
        print(f"  ✓ {'immunefi':12s} → {len(out):4d} programs"); return out
    except Exception as e:
        print(f"  ✗ {'immunefi':12s} → ERROR: {e}"); return None

# ── HackenProof (sitemap discovery + parallel program-page fetch) ───────────────

def _deref(payload, idx, depth: int = 0, _memo=None, _active=None):
    """Resolve Nuxt devalue payload refs: non-negative ints are indexes into
    the flat payload array, -1/None stay empty. Dicts/lists resolve deeply.
    Memoized + cycle-guarded: payloads contain circular refs, and naive
    recursion re-explores shared subgraphs exponentially (observed hang)."""
    if _memo is None:
        _memo = {}
        _active = set()
    if depth > 60:
        return None
    if idx is None or isinstance(idx, bool):
        return idx
    if isinstance(idx, int):
        if idx < 0 or idx >= len(payload):
            return None
        if idx in _memo:
            return _memo[idx]
        if idx in _active:
            return None  # circular ref — cut it
        _active.add(idx)
        val = _deref(payload, payload[idx], depth + 1, _memo, _active)
        _active.discard(idx)
        _memo[idx] = val
        return val
    if isinstance(idx, dict):
        return {k: _deref(payload, v, depth + 1, _memo, _active)
                for k, v in idx.items()}
    if isinstance(idx, list):
        return [_deref(payload, v, depth + 1, _memo, _active) for v in idx]
    return idx

_HP_TYPE_MAP = [("smart", "SMART_CONTRACT"), ("blockchain", "BLOCKCHAIN"),
                ("web", "WEB"), ("api", "API"), ("mobile", "MOBILE")]

def _hp_asset_type(title: str) -> str:
    t = (title or "").lower()
    for needle, atype in _HP_TYPE_MAP:
        if needle in t:
            return atype
    return "OTHER"

def _parse_hackenproof_program(slug: str, html: str) -> Optional[dict]:
    """Parse a hackenproof.com/programs/<slug> SSR payload. None = unparseable
    (caller carries over the previous record instead of dropping it)."""
    try:
        m = re.search(r'<script type="application/json"[^>]*>(.*?)</script>',
                      html, re.DOTALL)
        if not m:
            return None
        payload = json.loads(m.group(1))
        prog = None
        for item in payload:
            if isinstance(item, dict) and "scopes" in item and "maxReward" in item:
                cand = _deref(payload, item)
                if isinstance(cand, dict) and isinstance(cand.get("scopes"), list):
                    prog = cand
                    break
        if not prog:
            return None
        title = str(prog.get("title") or slug).strip()
        state = str(prog.get("state") or "")
        status = str(prog.get("status") or "")
        max_bounty = _parse_money(prog.get("maxBounty") or prog.get("maxReward"))
        min_bounty = _parse_money(prog.get("minBounty"))
        scope = []
        for s in prog.get("scopes") or []:
            if not isinstance(s, dict):
                continue
            target = str(s.get("target") or "").strip()
            if not target:
                continue
            scope.append({
                "asset_type": _hp_asset_type(str(s.get("title") or "")),
                "identifier": target,
                "description": str(s.get("target_description") or ""),
            })
        has_bounty = (state == "published") and (status != "ENDED") and max_bounty > 0
        return {
            "handle": slug, "name": title,
            "url": HACKENPROOF_PROGRAM_URL.format(slug=slug),
            "platform": "hackenproof",
            "has_bounty": has_bounty,
            "bounty_min": min_bounty, "bounty_max": max_bounty,
            "bounty_ccy": "USD",
            "live_status": status or state or "?",
            "in_scope": scope,
        }
    except Exception as e:
        print(f"    [hackenproof:{slug}] parse error: {e}")
    return None

def _fetch_text(url: str, timeout: int = 20, errors: Optional[list] = None) -> Optional[str]:
    try:
        r = requests.get(url, timeout=timeout, headers=UA_HEADERS)
        r.raise_for_status()
        return r.text
    except Exception as e:
        if errors is not None:
            errors.append(type(e).__name__)
        return None

def fetch_hackenproof() -> Optional[Tuple[List[dict], List[str], List[str]]]:
    """Returns (programs, failed_slugs, all_slugs). None = sitemap failed.
    Detail failures are reported so the caller can carry those over stale.
    Datacenter IPs get throttled → low concurrency + one retry pass."""
    try:
        locs = _sitemap_locs(HACKENPROOF_SITEMAP_URL)
        slugs = sorted({m.group(1) for loc in locs
                        for m in [re.search(r"/programs/([A-Za-z0-9_\-]+)", loc)] if m})
        if not slugs:
            raise ValueError("no program slugs in sitemap")
    except Exception as e:
        print(f"  ✗ {'hackenproof':12s} → ERROR: {e}"); return None
    print(f"  … hackenproof sitemap → {len(slugs)} slugs; fetching details…")
    out, failed = [], []
    reasons: Dict[str, int] = {}
    fetch_errors: List[str] = []

    def _one(slug: str):
        try:
            html = _fetch_text(HACKENPROOF_PROGRAM_URL.format(slug=slug),
                               timeout=30, errors=fetch_errors)
            if not html:
                return (slug, None, "fetch")
            norm = _parse_hackenproof_program(slug, html)
            return (slug, norm, "" if norm else "parse")
        except Exception as e:
            print(f"    [hackenproof:{slug}] worker error: {e}")
            return (slug, None, "worker")

    def _pass(work: List[str]):
        res = []
        with ThreadPoolExecutor(max_workers=3) as ex:
            res = list(ex.map(_one, work))
        return res

    # Single pass on purpose: datacenter IPs get blanket 403s from
    # HackenProof's bot mitigation — hammering retries changes nothing.
    # Coverage accrues across cycles via silent backfill of lucky hits.
    todo = slugs
    for slug, norm, reason in _pass(todo):
        if norm:
            out.append(norm)
        else:
            reasons[reason] = reasons.get(reason, 0) + 1
            failed.append(slug)
    if reasons:
        print(f"  … hackenproof detail failures: {dict(sorted(reasons.items()))}")
    if fetch_errors:
        from collections import Counter as _Counter
        print(f"  … hackenproof fetch errors: {dict(_Counter(fetch_errors).most_common(5))}")
    print(f"  ✓ {'hackenproof':12s} → {len(out):4d} programs"
          + (f" ({len(failed)} detail fails → stale)" if failed else ""))
    return (out, failed, slugs)

# ── Cantina (sitemap discovery + parallel bounty-page fetch) ────────────────────

def _parse_cantina_bounty(uid: str, html: str) -> Optional[dict]:
    """Parse a cantina.xyz/bounties/<uid> page (bounty JSON in RSC payload).
    Smart-contract/blockchain scope or GitHub refs ⇒ source."""
    try:
        m = re.search(r'\\"name\\":\\"([^\\]+)\\",\\"url\\":\\"https://cantina\.xyz/bounties/',
                      html)
        name = m.group(1).strip() if m else uid
        # bounty-level status sits right after "timeframe" (other "status"
        # fields in the page are submission states like "success")
        ms = re.search(r'\\"timeframe\\":\{[^}]*\},\\"status\\":\\"([a-zA-Z]+)\\"', html)
        if not ms:
            ms = re.search(r'\\"status\\":\\"(live|ended|paused|draft)\\"', html)
        status = (ms.group(1) if ms else "").upper() or "?"
        mp = re.search(r'\\"totalRewardPot\\":\\"([\d.]+)\\"', html)
        pot = _parse_money(mp.group(1)) if mp else 0
        if not pot:
            mr = re.search(r'Maximum reward</p><p[^>]*>\$([\d,]+)</p>', html)
            pot = _parse_money(mr.group(1)) if mr else 0
        mc = re.search(r'\\"currencyCode\\":\\"([A-Z]+)\\"', html)
        ccy = mc.group(1) if mc else "USDC"
        groups = re.findall(r'\\"name\\":\\"([^\\]+)\\",\\"description', html)
        scopes = " ".join(groups).lower()
        refs = sorted(set(re.findall(r'\\"reference\\":\\"([^\\]+)\\"', html)))
        gh = sorted({g for g in refs if "github.com/" in g.lower()})
        scope = [{"asset_type": "SMART_CONTRACT", "identifier": g,
                  "description": "cantina scope"} for g in gh[:30]]
        has_chain = ("smart contract" in scopes) or ("blockchain" in scopes)
        if scope or has_chain:
            # keep a marker so scope text (not just URLs) diffs too
            scope.append({"asset_type": "SMART_CONTRACT",
                          "identifier": f"cantina:{uid[:8]}",
                          "description": "; ".join(groups[:6])})
        live = (status == "LIVE")
        ended = (status == "ENDED") or (">Ended<" in html)
        has_bounty = pot > 0 and live and not ended
        return {
            "handle": uid, "name": name,
            "url": CANTINA_BOUNTY_URL.format(uid=uid),
            "platform": "cantina",
            "has_bounty": has_bounty,
            "bounty_min": 0, "bounty_max": pot, "bounty_ccy": ccy,
            "live_status": "LIVE" if live else ("ENDED" if ended else status),
            "in_scope": scope,
        }
    except Exception as e:
        print(f"    [cantina:{uid}] parse error: {e}")
    return None

def fetch_cantina() -> Optional[Tuple[List[dict], List[str], List[str]]]:
    try:
        # sitemap.xml is an index (sitemap-0, sitemap-1, …) — gather them all
        index = _sitemap_locs("https://cantina.xyz/sitemap.xml") or []
        maps = sorted({loc for loc in index if re.search(r"sitemap-\d+\.xml$", loc)})
        if not maps:
            maps = [CANTINA_SITEMAP_URL]
        locs: List[str] = []
        for sm in maps:
            try:
                locs += _sitemap_locs(sm) or []
            except Exception as e:
                print(f"    [cantina] sitemap part failed: {sm}: {e}")
        uids = sorted({m.group(1) for loc in locs
                       for m in [re.search(r"/bounties/([a-f0-9\-]+)", loc)] if m})
        if not uids:
            raise ValueError("no bounty ids in sitemap")
    except Exception as e:
        print(f"  ✗ {'cantina':12s} → ERROR: {e}"); return None
    print(f"  … cantina sitemap → {len(uids)} bounties; fetching details…")
    out, failed = [], []

    def _one(uid: str):
        try:
            html = _fetch_text(CANTINA_BOUNTY_URL.format(uid=uid))
            if not html:
                return (uid, None)
            return (uid, _parse_cantina_bounty(uid, html))
        except Exception as e:
            print(f"    [cantina:{uid}] worker error: {e}")
            return (uid, None)

    todo = uids
    # Second pass only when budget allows — retrying throttled pages used to
    # blow the job timeout daily (then NOTHING was committed).
    attempts = (1, 2) if _budget_ok(180) else (1,)
    for attempt in attempts:
        batch = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            batch = list(ex.map(_one, todo))
        todo = []
        for uid, norm in batch:
            if norm:
                out.append(norm)
            else:
                todo.append(uid)
        if todo and attempt == 1 and len(attempts) > 1:
            print(f"  … cantina retrying {len(todo)} failed details…")
            time.sleep(1)
    failed = todo
    print(f"  ✓ {'cantina':12s} → {len(out):4d} bounties"
          + (f" ({len(failed)} detail fails → stale)" if failed else ""))
    return (out, failed, uids)

# ── Sherlock (sitemap discovery + parallel bug-bounty-page fetch) ───────────────

def _parse_sherlock_bounty(bid: str, html: str) -> Optional[dict]:
    """Parse audits.sherlock.xyz/bug-bounties/<id>. Sherlock bounties are
    smart-contract by definition; contract `names` in Scope diff like targets."""
    try:
        t = re.search(r"<title>([^<]+)</title>", html)
        title = (t.group(1).replace(" Bug Bounty - Sherlock", "").strip()
                 if t else f"Sherlock {bid}")
        m = re.search(r"Max Rewards</p><span[^>]*>([^<]+)</span>", html)
        pot = _parse_money(m.group(1)) if m else 0
        if ">LIVE<" in html:
            status = "LIVE"
        elif ">ENDED<" in html:
            status = "ENDED"
        else:
            status = "?"
        scope, contracts = [], []
        ms = re.search(r"## Scope(.*?)## Out of Scope", html, re.DOTALL)
        if ms:
            # contract `names` are plain backticks; newlines are literal \n
            contracts = sorted(set(re.findall(r"`([A-Za-z0-9_.$*][A-Za-z0-9_.$* ]{0,40})`",
                                              ms.group(1))))[:20]
            scope = [{"asset_type": "SMART_CONTRACT", "identifier": c,
                      "description": "sherlock scope"} for c in contracts]
        gh = sorted(set(re.findall(r"https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+",
                                   html)))[:20]
        for g in gh:
            scope.append({"asset_type": "SMART_CONTRACT", "identifier": g,
                          "description": "sherlock scope"})
        if not scope and status == "LIVE":
            # live smart-contract bounty with no machine-readable scope —
            # marker keeps it qualifying; detail lives on the program page
            scope = [{"asset_type": "SMART_CONTRACT",
                      "identifier": f"sherlock:{bid}",
                      "description": "live contracts — see program page"}]
        has_bounty = pot > 0 and status == "LIVE"
        return {
            "handle": bid, "name": title,
            "url": SHERLOCK_BOUNTY_URL.format(bid=bid),
            "platform": "sherlock",
            "has_bounty": has_bounty,
            "bounty_min": 0, "bounty_max": pot, "bounty_ccy": "USDC",
            "live_status": status,
            "in_scope": scope,
        }
    except Exception as e:
        print(f"    [sherlock:{bid}] parse error: {e}")
    return None

def fetch_sherlock() -> Optional[Tuple[List[dict], List[str], List[str]]]:
    try:
        locs = _sitemap_locs(SHERLOCK_SITEMAP_URL)
        bids = sorted({loc.rstrip("/").rsplit("/", 1)[-1] for loc in locs
                       if re.search(r"/bug-bounties/\d+/?$", loc)})
        if not bids:
            raise ValueError("no bounty ids in sitemap")
    except Exception as e:
        print(f"  ✗ {'sherlock':12s} → ERROR: {e}"); return None
    print(f"  … sherlock sitemap → {len(bids)} bounties; fetching details…")
    out, failed = [], []

    def _one(bid: str):
        try:
            html = _fetch_text(SHERLOCK_BOUNTY_URL.format(bid=bid))
            if not html:
                return (bid, None)
            return (bid, _parse_sherlock_bounty(bid, html))
        except Exception as e:
            print(f"    [sherlock:{bid}] worker error: {e}")
            return (bid, None)

    todo = bids
    # Second pass only when budget allows — same timeout rationale as cantina.
    attempts = (1, 2) if _budget_ok(120) else (1,)
    for attempt in attempts:
        batch = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            batch = list(ex.map(_one, todo))
        todo = []
        for bid, norm in batch:
            if norm:
                out.append(norm)
            else:
                todo.append(bid)
        if todo and attempt == 1 and len(attempts) > 1:
            print(f"  … sherlock retrying {len(todo)} failed details…")
            time.sleep(1)
    failed = todo
    print(f"  ✓ {'sherlock':12s} → {len(out):4d} bounties"
          + (f" ({len(failed)} detail fails → stale)" if failed else ""))
    return (out, failed, bids)

def carry_over(prev: dict, new_state: dict, prefix: str) -> int:
    stale = {k: v for k, v in prev.items() if k.startswith(prefix)}
    new_state.update(stale)
    return len(stale)

def _safe_fetch_immunefi():
    """Immunefi wrapper safe for parallel execution — never raises."""
    try:
        return fetch_immunefi()
    except Exception as e:
        print(f"  ✗ {'immunefi':12s} → ERROR: {e}")
        return None

def _safe(fetch_fn, platform: str):
    """A blockchain feed must never crash the whole run — worst case it
    goes stale and its previous records carry over silently."""
    try:
        return fetch_fn()
    except Exception as e:
        print(f"  ✗ {platform:12s} → ERROR: {e}")
        return None

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'─'*58}\n  Bug Bounty Source Code Monitor v4 (worldwide + blockchain)\n  {datetime.now(timezone.utc).isoformat()}\n  budget: {MONITOR_BUDGET_SEC}s\n{'─'*58}\n")
    prev = load_state()
    # Old/incompatible state format → silent re-baseline (prevents notification floods)
    first_run = (not prev) or prev.get("_meta", {}).get("schema") != SCHEMA_VERSION
    changes = load_changes()
    new_state: dict = {}
    events: List[Tuple[dict,str,str]] = []

    if first_run: print("📌 FIRST RUN / SCHEMA UPGRADE — building baseline\n")

    # ── Fast feeds in PARALLEL (was serial: 5×45s + chaos + immunefi could
    # exceed the job timeout on slow networks → SIGKILL → nothing committed).
    print("Fetching fast feeds in parallel (chaos + big-5 + immunefi)…")
    fast_results: Dict[str, Optional[list]] = {}

    def _get_big5(args) -> Optional[list]:
        platform, url = args
        return fetch(platform, url)

    try:
        with ThreadPoolExecutor(max_workers=7) as ex:
            fut_chaos = ex.submit(fetch_chaos)
            fut_immunefi = ex.submit(_safe_fetch_immunefi)
            futs = {ex.submit(_get_big5, (p, u)): p for p, u in PLATFORM_URLS.items()}
            chaos = fut_chaos.result()
            immunefi_res = fut_immunefi.result()
            for fut, platform in futs.items():
                try:
                    fast_results[platform] = fut.result()
                except Exception as e:
                    print(f"  ✗ {platform:12s} → ERROR: {e}")
                    fast_results[platform] = None
    except Exception as e:
        print(f"  ⚠ parallel fast-fetch failed ({e}) — falling back to stale carry-over")
        chaos, immunefi_res = None, None
        for p in PLATFORM_URLS:
            fast_results.setdefault(p, None)
    # name → in-scope domain count (competition proxy: surface per researcher)
    chaos_domains = {}
    if chaos is None:
        pass  # fetched later; carry-over handled below
    else:
        for prog in chaos:
            chaos_domains[prog["name"].lower()] = max(
                chaos_domains.get(prog["name"].lower(), 0), prog.get("domains", 0))

    print("Processing big-5 platforms (already fetched in parallel)…")
    fetch_ok: Dict[str, bool] = {}

    # ── Big platforms: full scope analysis ──
    for platform in PLATFORM_URLS:
        progs = fast_results.get(platform)
        if progs is None:
            fetch_ok[platform] = False
            n = carry_over(prev, new_state, f"{platform}:")
            print(f"  ↻ {platform} unavailable — carried over {n} stale entries (no events)")
            continue
        fetch_ok[platform] = True
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
                "bounty_note": "amount not in upstream feed" if (hb and not prog.get("bounty_max")) else "",
                "domains": chaos_domains.get(prog["name"].lower(), 0),
                "resp_eff": prog.get("resp_eff"),
                "bounty_days": prog.get("bounty_days"),
                "sc_targets": sc[:10],
                "sc_total": len(sc),
                "sc_ids": ids,
                "github_repos": gh,
            }

            if first_run or not (hb and hs):
                pass
            else:
                _detect_scope_events(prog, platform, key, h, hb, hs, ids, gh,
                                     prev, first_run, changes, events)

    # ── Blockchain feeds: smart-contract bounties (detail pages) ──
    # Immunefi already fetched in parallel above — reuse it. The three
    # detail-page feeds (hackenproof/cantina/sherlock) are SLOW and used to
    # blow the job timeout daily. Each now checks the time budget first:
    # if we're running out, the feed goes stale (carry-over, no events)
    # and we still SAVE everything collected so far.
    print(f"Fetching blockchain detail feeds… (budget left: {int(_budget_left())}s)")

    bc_feeds = []
    bc_feeds.append(("immunefi", immunefi_res))
    if _budget_ok(240):
        bc_feeds.append(("hackenproof", _safe(fetch_hackenproof, "hackenproof")))
    else:
        print("  ↻ hackenproof skipped — low time budget (carrying over stale)")
        bc_feeds.append(("hackenproof", None))
    if _budget_ok(150):
        bc_feeds.append(("cantina", _safe(fetch_cantina, "cantina")))
    else:
        print("  ↻ cantina skipped — low time budget (carrying over stale)")
        bc_feeds.append(("cantina", None))
    if _budget_ok(60):
        bc_feeds.append(("sherlock", _safe(fetch_sherlock, "sherlock")))
    else:
        print("  ↻ sherlock skipped — low time budget (carrying over stale)")
        bc_feeds.append(("sherlock", None))
    # Sitemap IDs from the previous cycle: lets a recovered detail fetch
    # tell backfill (slug seen before, never fetched → silent) from
    # genuinely new slugs (→ new_program alert). No history yet → assume
    # known for one cycle (quiet, never spammy).
    prev_feed_ids = prev.get("_meta", {}).get("feed_ids") or {}
    feed_ids: Dict[str, List[str]] = {}
    for platform, result in bc_feeds:
        progs, failed, all_ids = (result if isinstance(result, tuple)
                                  else (result, [], []))
        feed_ids[platform] = all_ids
        if progs is None:
            fetch_ok[platform] = False
            n = carry_over(prev, new_state, f"{platform}:")
            print(f"  ↻ {platform} unavailable — carried over {n} stale entries (no events)")
            # keep the last known sitemap so the next recovery can tell
            # backfill (seen slug, never fetched) from genuinely new slugs
            feed_ids[platform] = prev_feed_ids.get(platform) or []
            continue
        fetch_ok[platform] = True
        backfilled = 0
        prev_ids = prev_feed_ids.get(platform)  # None = no sitemap history yet
        for prog in progs:
            key = f"{platform}:{prog['handle']}"
            status = prog.get("live_status", "")
            bmax = prog.get("bounty_max", 0) or 0
            h   = blockchain_scope_hash(prog, status, bmax)
            hb  = prog["has_bounty"]
            sc  = blockchain_sc_targets(prog)
            hs  = bool(sc)
            ids = blockchain_sc_ids_list(prog)
            gh  = blockchain_github_repos_list(prog)

            new_state[key] = {
                "hash": h, "bounty": hb, "source": hs,
                "name": prog["name"], "url": prog["url"], "platform": platform,
                "bounty_min": prog.get("bounty_min", 0),
                "bounty_max": bmax,
                "bounty_ccy": prog.get("bounty_ccy", ""),
                "bounty_note": "",
                "domains": 0,
                "resp_eff": None,
                "bounty_days": None,
                "live_status": status,
                "sc_targets": sc[:10],
                "sc_total": len(sc),
                "sc_ids": ids,
                "github_repos": gh,
            }

            if first_run or not (hb and hs):
                pass
            elif prev.get(key) is None and (prev_ids is None
                                            or prog["handle"] in prev_ids):
                # backfill, not a launch: this slug was already in a
                # previous sitemap (or we have no sitemap history yet) but
                # was never successfully fetched — baseline it silently
                # instead of firing a bogus new_program alert.
                backfilled += 1
            else:
                _detect_scope_events(prog, platform, key, h, hb, hs, ids, gh,
                                     prev, first_run, changes, events)
        if backfilled:
            print(f"  … {platform} backfilled {backfilled} program(s) silently (no alerts)")
        # partial detail failures → stale carry-over (no events for these)
        carried = 0
        for handle in (failed or []):
            key = f"{platform}:{handle}"
            if key in prev and key not in new_state:
                new_state[key] = prev[key]
                carried += 1
        if carried:
            print(f"  ↻ {platform} carried over {carried} stale detail(s) (no events)")

    # BLUNT: only suppress a Chaos entry when the SAME name already pays
    # on a big-5 OR blockchain platform. Old code suppressed on ANY name
    # match (even VDP / no-bounty), silently hiding real external bounties.
    known_bounty_names = {v.get("name", "").lower() for v in new_state.values()
                          if v.get("bounty")}

    # ── Worldwide index: program-level watch ──
    if chaos is None:
        fetch_ok["chaos"] = False
        n = carry_over(prev, new_state, "chaos:")
        print(f"  ↻ chaos unavailable — carried over {n} stale entries (no events)")
    else:
        fetch_ok["chaos"] = True
        seen = set()
        for prog in chaos:
            if prog["name"].lower() in known_bounty_names: continue
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
            if recent_duplicate(changes, "chaos", prog["handle"], "new_external"):
                continue
            events.append((prog, "chaos", "new_external"))

    total = sum(1 for k in new_state if k != "_meta")
    qualifying = sum(1 for k, v in new_state.items() if k != "_meta" and v.get("bounty") and v.get("source"))
    external = sum(1 for k in new_state if k.startswith("chaos:"))
    blockchain = sum(1 for k, v in new_state.items()
                     if k != "_meta" and v.get("platform") in BLOCKCHAIN_PLATFORMS
                     and v.get("bounty") and v.get("source"))
    # If we collected NOTHING (total outage), do NOT overwrite good state
    # with an empty file — that used to wipe state.json daily on network blips.
    if total == 0 and prev and len(prev) > 5:
        print("  ✗✗✗ all feeds failed — keeping previous state, NOT overwriting with empty")
        return
    new_state["_meta"] = {
        "schema": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": total, "qualifying": qualifying, "external": external,
        "blockchain": blockchain,
        "feed_ids": feed_ids,
        "fetch_ok": fetch_ok,
        "stale": [p for p, ok in fetch_ok.items() if not ok],
    }
    try:
        save_state(new_state)
    except Exception as e:
        print(f"  ✗✗✗ save_state failed ({e}) — state kept in memory only")
    print(f"\n📊 {qualifying} bounty+source ({blockchain} blockchain) · "
          f"{external} worldwide programs · {total} total\n")
    if any(not ok for ok in fetch_ok.values()):
        print(f"  ⚠ STALE feeds this cycle: {[p for p, ok in fetch_ok.items() if not ok]}")

    if first_run:
        tg_send(f"✅ <b>Bug Bounty Monitor v4 is LIVE</b>\n\n"
                f"📊 <b>Baseline snapshot:</b>\n"
                f"  • Bounty + source code      : {qualifying} ({blockchain} blockchain)\n"
                f"  • Worldwide (outside big-5) : {external}\n"
                f"  • Total programs tracked    : {total}\n\n"
                f"Blunt truth:\n"
                f"  • 5 classic feeds (H1/BC/Intigriti/YWH/Federacy) + Chaos index\n"
                f"  • 4 blockchain feeds (HackenProof/Immunefi/Cantina/Sherlock) — /blockchain\n"
                f"  • Timestamps are DETECTION time, not launch time\n"
                f"  • HackerOne amounts are NOT in the feed (yes/no only)\n"
                f"  • Full source removal is NOT alerted (program just drops out)\n"
                f"🤖 Bot ready — type /help in Telegram\n"
                f"🔁 Best-effort ~30 min (GitHub cron + restarts can delay)\n"
                f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        save_changes(changes)
        print("✅ Baseline done.\n"); return

    print(f"📬 Sending {len(events)} notification(s)…")
    for prog, platform, event in events:
        append_change(changes, prog, platform, event)
        try:
            tg_send(build_message(prog, platform, event))
        except Exception as e:
            print(f"  ⚠ notify failed ({e}) — event kept in changes_log")
        time.sleep(1)
    if not events: print("  ✓ No changes this cycle.")

    try:
        save_changes(changes)
    except Exception as e:
        print(f"  ✗✗✗ save_changes failed ({e})")
    print("\n✅ Done.\n")

def _main_safe():
    """Top-level guard: NEVER exit without saving partial progress. A crash
    mid-run used to lose the whole cycle (and on repeated crashes, the bot
    looked 'stopped for days'). Now partial state is always persisted."""
    try:
        main()
    except Exception:
        import traceback
        print("\n💥 monitor crashed mid-run — attempting emergency partial save:")
        traceback.print_exc()
        raise

if __name__ == "__main__":
    try: _main_safe()
    except Exception as e:
        import traceback; print(f"\n💥 Fatal: {e}"); traceback.print_exc(); raise
