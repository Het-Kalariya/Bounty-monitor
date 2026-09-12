#!/usr/bin/env python3
"""
Bug Bounty Source Code Monitor
================================
Monitors HackerOne, Bugcrowd, Intigriti, YesWeHack for programs that:
  1. Pay real monetary bounties
  2. Have source code (GitHub/GitLab repos) in scope

Each platform has a completely different JSON schema — this script
normalizes them all before processing. No Immunefi (malformed JSON).

Data source : arkadiyt/bounty-targets-data (refreshes every ~6 hrs)
Notifications: Telegram Bot
Hosted on    : GitHub Actions (free, every 30 min)
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests

# ─── CONFIG ────────────────────────────────────────────────────────────────────

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATE_FILE       = "state.json"

PLATFORM_URLS: Dict[str, str] = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

SOURCE_CODE_ASSET_TYPES = {"SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET"}

SOURCE_CODE_SUBSTRINGS = [
    "github.com/",
    "gitlab.com/",
    "bitbucket.org/",
    "source code",
    "open-source",
    "open source",
]

PLATFORM_EMOJI = {
    "hackerone": "🟢",
    "bugcrowd":  "🔴",
    "intigriti": "🔵",
    "yeswehack": "🟡",
}

EVENT_LABELS = {
    "new_program":    ("🆕", "New program — source code in scope + bounty"),
    "scope_added":    ("📦", "Source code ADDED to in-scope"),
    "scope_updated":  ("🔄", "Scope updated — still has source code"),
    "bounty_enabled": ("💰", "Now paying bounties (has source code scope)"),
}

# ─── PER-PLATFORM NORMALIZERS ──────────────────────────────────────────────────
# Output format: {"handle", "name", "url", "has_bounty", "in_scope": [{"asset_type","identifier","description"}]}

def _normalize_hackerone(prog: dict) -> Optional[dict]:
    try:
        handle = prog.get("handle", "")
        return {
            "handle":     handle,
            "name":       prog.get("name", handle),
            "url":        f"https://hackerone.com/{handle}",
            "has_bounty": bool(prog.get("offers_bounties", False)),
            "in_scope": [
                {
                    "asset_type":  t.get("asset_type", ""),
                    "identifier":  t.get("asset_identifier", ""),
                    "description": t.get("instruction", "") or "",
                }
                for t in prog.get("targets", {}).get("in_scope", [])
            ],
        }
    except Exception as e:
        print(f"    [hackerone] normalize error: {e}")
        return None

def _normalize_bugcrowd(prog: dict) -> Optional[dict]:
    try:
        name       = prog.get("name", "")
        max_payout = prog.get("max_payout") or 0
        return {
            "handle":     name,
            "name":       name,
            "url":        prog.get("url", ""),
            "has_bounty": int(max_payout) > 0,
            "in_scope": [
                {
                    "asset_type":  t.get("type", ""),
                    "identifier":  t.get("target", t.get("uri", "")) or "",
                    "description": t.get("name", "") or "",
                }
                for t in prog.get("targets", {}).get("in_scope", [])
            ],
        }
    except Exception as e:
        print(f"    [bugcrowd] normalize error: {e}")
        return None

def _normalize_intigriti(prog: dict) -> Optional[dict]:
    try:
        handle     = prog.get("handle", "")
        min_bounty = prog.get("min_bounty") or {}
        # min_bounty is {"value": 50, "currency": "EUR"} or None
        bounty_val = min_bounty.get("value", 0) if isinstance(min_bounty, dict) else 0
        return {
            "handle":     handle,
            "name":       prog.get("name", handle),
            "url":        prog.get("url", f"https://app.intigriti.com/programs/{handle}"),
            "has_bounty": (bounty_val or 0) > 0,
            "in_scope": [
                {
                    "asset_type":  t.get("type", "") or "",
                    "identifier":  t.get("endpoint", "") or "",
                    "description": t.get("description", "") or "",
                }
                for t in prog.get("targets", {}).get("in_scope", [])
            ],
        }
    except Exception as e:
        print(f"    [intigriti] normalize error: {e}")
        return None

def _normalize_yeswehack(prog: dict) -> Optional[dict]:
    try:
        name       = prog.get("name", "")
        min_bounty = prog.get("min_bounty") or 0
        slug       = name.lower().replace(" ", "-")
        return {
            "handle":     slug,
            "name":       name,
            "url":        f"https://yeswehack.com/programs/{slug}",
            "has_bounty": (min_bounty or 0) > 0,
            "in_scope": [
                {
                    "asset_type":  t.get("type", "") or "",
                    "identifier":  t.get("target", "") or "",
                    "description": "",
                }
                for t in prog.get("targets", {}).get("in_scope", [])
            ],
        }
    except Exception as e:
        print(f"    [yeswehack] normalize error: {e}")
        return None

NORMALIZERS = {
    "hackerone": _normalize_hackerone,
    "bugcrowd":  _normalize_bugcrowd,
    "intigriti": _normalize_intigriti,
    "yeswehack": _normalize_yeswehack,
}

# ─── SOURCE CODE DETECTION ─────────────────────────────────────────────────────

def is_source_code_target(t: dict) -> bool:
    if t.get("asset_type", "").upper() in SOURCE_CODE_ASSET_TYPES:
        return True
    blob = (t.get("identifier", "") + " " + t.get("description", "")).lower()
    return any(sub in blob for sub in SOURCE_CODE_SUBSTRINGS)

def get_sc_targets(prog: dict) -> List[dict]:
    return [t for t in prog["in_scope"] if is_source_code_target(t)]

def has_source_code(prog: dict) -> bool:
    return bool(get_sc_targets(prog))

# ─── TELEGRAM ──────────────────────────────────────────────────────────────────

def telegram_send(text: str, retries: int = 3) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"  [TELEGRAM OFF] {text[:100]}")
        return False
    url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text,
                "parse_mode": "HTML", "disable_web_page_preview": True}
    for attempt in range(retries):
        try:
            r = requests.post(url, json=payload, timeout=15)
            if r.status_code == 429:
                wait = r.json().get("parameters", {}).get("retry_after", 30)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return True
        except Exception as e:
            print(f"  Telegram error (attempt {attempt+1}): {e}")
            time.sleep(5)
    return False

def build_message(prog: dict, platform: str, event: str) -> str:
    emoji, title = EVENT_LABELS.get(event, ("🔔", "Update"))
    p_emoji      = PLATFORM_EMOJI.get(platform, "⚪")
    sc           = get_sc_targets(prog)
    ts           = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"{emoji} <b>{title}</b>",
        "",
        f"{p_emoji} <b>Platform:</b>  {platform.capitalize()}",
        f"📋 <b>Program:</b>   {prog['name']}",
        f"🔗 <b>URL:</b>       {prog['url']}",
        "",
        f"📁 <b>Source Code Targets ({len(sc)}):</b>",
    ]
    for t in sc[:6]:
        lines.append(f"  • <code>{t['identifier']}</code>  [{t['asset_type']}]")
    if len(sc) > 6:
        lines.append(f"  … and {len(sc)-6} more")
    lines.append(f"\n⏰ {ts}")
    return "\n".join(lines)

# ─── STATE ─────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def scope_hash(prog: dict) -> str:
    serialized = json.dumps(sorted(json.dumps(t, sort_keys=True) for t in prog["in_scope"]))
    return hashlib.sha1(serialized.encode()).hexdigest()

# ─── FETCH ─────────────────────────────────────────────────────────────────────

def fetch_and_normalize(platform: str, url: str) -> List[dict]:
    try:
        r = requests.get(url, timeout=45)
        r.raise_for_status()
        raw_list = r.json()
        normalize = NORMALIZERS[platform]
        results   = []
        for item in raw_list:
            normed = normalize(item)
            if normed:
                results.append(normed)
        print(f"  ✓ {platform:12s} → {len(results):4d} programs")
        return results
    except Exception as e:
        print(f"  ✗ {platform:12s} → ERROR: {e}")
        return []

# ─── MAIN ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'─'*58}")
    print(f"  Bug Bounty Source Code Monitor")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print(f"{'─'*58}\n")

    prev_state = load_state()
    first_run  = not prev_state
    new_state: dict = {}
    events: List[Tuple[dict, str, str]] = []

    if first_run:
        print("📌 FIRST RUN — building baseline (no spam, only summary)\n")

    print("Fetching & normalizing platforms…")
    for platform, url in PLATFORM_URLS.items():
        programs = fetch_and_normalize(platform, url)

        for prog in programs:
            key = f"{platform}:{prog['handle']}"
            h   = scope_hash(prog)
            hb  = prog["has_bounty"]
            hs  = has_source_code(prog)

            new_state[key] = {"hash": h, "bounty": hb, "source": hs}

            if first_run or not (hb and hs):
                continue

            prev = prev_state.get(key)

            if prev is None:
                events.append((prog, platform, "new_program"))
            elif prev["hash"] != h:
                was_source = prev.get("source", False)
                if hs and not was_source:
                    events.append((prog, platform, "scope_added"))
                elif hs:
                    events.append((prog, platform, "scope_updated"))
            elif not prev.get("bounty") and hb:
                events.append((prog, platform, "bounty_enabled"))

    save_state(new_state)
    qualifying = sum(1 for v in new_state.values() if v["bounty"] and v["source"])
    print(f"\n📊 {qualifying} programs match (bounty + source code) out of {len(new_state)} total\n")

    if first_run:
        msg = (
            f"✅ <b>Bug Bounty Monitor is LIVE!</b>\n\n"
            f"📊 <b>Baseline snapshot:</b>\n"
            f"  • Total programs tracked : {len(new_state)}\n"
            f"  • Bounty + source code   : {qualifying}\n\n"
            f"🔔 You'll be notified when:\n"
            f"  • A new program adds source code scope\n"
            f"  • An existing program adds source code\n"
            f"  • A program starts paying bounties\n\n"
            f"🔁 Checks every 30 min, 24×7\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        telegram_send(msg)
        print("✅ Baseline summary sent to Telegram. Monitor is live!\n")
        return

    print(f"📬 Sending {len(events)} notification(s)…")
    for prog, platform, event in events:
        msg = build_message(prog, platform, event)
        ok  = telegram_send(msg)
        print(f"  {'✓' if ok else '✗'} [{event}] {platform}:{prog['handle']}")
        time.sleep(1)

    if not events:
        print("  ✓ No changes this cycle.")

    print("\n✅ Done.\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()
        raise   # Re-raise so GitHub Actions marks it as failed with the real reason