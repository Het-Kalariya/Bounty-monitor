#!/usr/bin/env python3
"""
Bug Bounty Source Code Monitor
================================
Monitors HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi for programs that:
  1. Pay REAL monetary bounties
  2. Have source code (GitHub/GitLab repos) in scope

Data source: arkadiyt/bounty-targets-data (auto-updated every few hours)
Notifications: Telegram Bot
Run via: GitHub Actions (every 30 min, completely free)
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import requests

# ─── CONFIG ────────────────────────────────────────────────────────────────────

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATE_FILE       = "state.json"

# bounty-targets-data aggregates ALL major platforms automatically
PLATFORM_URLS: Dict[str, str] = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "immunefi":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/immunefi_data.json",
}

# Asset types that are explicitly source code
SOURCE_CODE_ASSET_TYPES = {
    "SOURCE_CODE", "GITHUB", "GITLAB", "BITBUCKET",
}

# Substrings in identifier or instructions that indicate source code
SOURCE_CODE_SUBSTRINGS = [
    "github.com/",
    "gitlab.com/",
    "bitbucket.org/",
    "source code",
    "sourcecode",
    "open-source",
    "open source",
    "repository",
]

PLATFORM_EMOJI = {
    "hackerone": "🟢",
    "bugcrowd":  "🔴",
    "intigriti": "🔵",
    "yeswehack": "🟡",
    "immunefi":  "🟣",
}

EVENT_LABELS = {
    "new_program":    ("🆕", "New program with source code scope + bounty"),
    "scope_added":    ("📦", "Source code ADDED to in-scope"),
    "scope_updated":  ("🔄", "Scope updated — still has source code"),
    "bounty_enabled": ("💰", "Now paying bounties (has source code scope)"),
}

# ─── TELEGRAM ──────────────────────────────────────────────────────────────────

def telegram_send(text: str, retries: int = 3) -> bool:
    """Send message to Telegram with retry + rate-limit handling."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[TELEGRAM DISABLED — set env vars]\n{text[:200]}\n")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":                  TELEGRAM_CHAT_ID,
        "text":                     text,
        "parse_mode":               "HTML",
        "disable_web_page_preview": True,
    }

    for attempt in range(retries):
        try:
            r = requests.post(url, json=payload, timeout=15)
            if r.status_code == 429:
                wait = r.json().get("parameters", {}).get("retry_after", 30)
                print(f"  Rate limited — waiting {wait}s")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return True
        except Exception as e:
            print(f"  Telegram error (attempt {attempt + 1}/{retries}): {e}")
            time.sleep(5)
    return False

# ─── SOURCE CODE DETECTION ─────────────────────────────────────────────────────

def is_source_code_target(target: dict) -> bool:
    """Return True if this scope entry points to source code."""
    asset_type = target.get("asset_type", "").upper().strip()
    if asset_type in SOURCE_CODE_ASSET_TYPES:
        return True
    blob = (
        target.get("asset_identifier", "") + " " +
        target.get("instruction", "")
    ).lower()
    return any(sub in blob for sub in SOURCE_CODE_SUBSTRINGS)

def get_source_code_targets(program: dict) -> List[dict]:
    in_scope = program.get("targets", {}).get("in_scope", [])
    return [t for t in in_scope if is_source_code_target(t)]

def has_source_code(program: dict) -> bool:
    return bool(get_source_code_targets(program))

def offers_bounty(program: dict) -> bool:
    return bool(program.get("offers_bounties", False))

# ─── UTILITIES ─────────────────────────────────────────────────────────────────

def program_key(program: dict, platform: str) -> str:
    handle = (
        program.get("handle") or
        program.get("name")   or
        str(program.get("id", "unknown"))
    )
    return f"{platform}:{handle}"

def scope_hash(program: dict) -> str:
    """Hash the entire in-scope list for change detection."""
    targets = program.get("targets", {}).get("in_scope", [])
    serialized = json.dumps(sorted(json.dumps(t, sort_keys=True) for t in targets))
    return hashlib.sha1(serialized.encode()).hexdigest()

def get_program_url(program: dict, platform: str) -> str:
    if program.get("url"):
        return program["url"]
    if program.get("program_url"):
        return program["program_url"]
    h = program.get("handle", program.get("slug", ""))
    defaults = {
        "hackerone": f"https://hackerone.com/{h}",
        "bugcrowd":  f"https://bugcrowd.com/{h}",
        "intigriti": f"https://app.intigriti.com/programs",
        "yeswehack": f"https://yeswehack.com/programs/{h}",
        "immunefi":  f"https://immunefi.com/bounty/{h}",
    }
    return defaults.get(platform, "#")

# ─── NOTIFICATIONS ─────────────────────────────────────────────────────────────

def build_message(program: dict, platform: str, event: str) -> str:
    emoji, title = EVENT_LABELS.get(event, ("🔔", "Update"))
    p_emoji = PLATFORM_EMOJI.get(platform, "⚪")
    handle  = program.get("handle") or program.get("name", "Unknown")
    url     = get_program_url(program, platform)
    sc      = get_source_code_targets(program)
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"{emoji} <b>{title}</b>",
        "",
        f"{p_emoji} <b>Platform:</b>  {platform.capitalize()}",
        f"📋 <b>Program:</b>   {handle}",
        f"🔗 <b>URL:</b>       {url}",
        "",
        f"📁 <b>Source Code Targets ({len(sc)}):</b>",
    ]

    for t in sc[:6]:
        identifier = t.get("asset_identifier", "N/A")
        atype      = t.get("asset_type", "?")
        lines.append(f"  • <code>{identifier}</code>  [{atype}]")

    if len(sc) > 6:
        lines.append(f"  … and {len(sc) - 6} more")

    lines.append(f"\n⏰ {ts}")
    return "\n".join(lines)

# ─── FETCH ─────────────────────────────────────────────────────────────────────

def fetch_platform(platform: str, url: str) -> List[dict]:
    try:
        r = requests.get(url, timeout=45)
        r.raise_for_status()
        data = r.json()
        print(f"  ✓ {platform:12s} → {len(data):4d} programs")
        return data
    except Exception as e:
        print(f"  ✗ {platform:12s} → ERROR: {e}")
        return []

# ─── STATE ─────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  ✓ State saved ({len(state)} programs tracked)")

# ─── MAIN ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'─' * 58}")
    print(f"  Bug Bounty Source Code Monitor")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print(f"{'─' * 58}\n")

    prev_state = load_state()
    first_run  = not prev_state
    new_state: dict = {}
    events: List[Tuple[dict, str, str]] = []

    if first_run:
        print("📌 FIRST RUN — building baseline state (no spam, just summary)\n")

    print("Fetching platform data…")
    for platform, url in PLATFORM_URLS.items():
        programs = fetch_platform(platform, url)

        for prog in programs:
            key = program_key(prog, platform)
            h   = scope_hash(prog)
            hb  = offers_bounty(prog)
            hs  = has_source_code(prog)

            new_state[key] = {"hash": h, "bounty": hb, "source": hs}

            # Skip detection on first run or programs that don't qualify
            if first_run or not (hb and hs):
                continue

            prev = prev_state.get(key)

            if prev is None:
                # Brand new program with bounty + source code
                events.append((prog, platform, "new_program"))

            elif prev["hash"] != h:
                # Scope changed — was source code newly added?
                was_source = prev.get("source", False)
                if hs and not was_source:
                    events.append((prog, platform, "scope_added"))
                elif hs:
                    events.append((prog, platform, "scope_updated"))

            elif not prev.get("bounty") and hb:
                # Program started offering bounties and has source code
                events.append((prog, platform, "bounty_enabled"))

    print()
    save_state(new_state)

    qualifying = sum(1 for v in new_state.values() if v["bounty"] and v["source"])
    print(f"\n📊 {qualifying} programs have bounty + source code (out of {len(new_state)} total)\n")

    # ── First run: just send a summary ──
    if first_run:
        summary = (
            f"✅ <b>Bug Bounty Monitor is LIVE!</b>\n\n"
            f"📊 <b>Baseline snapshot:</b>\n"
            f"  • Total programs tracked   : {len(new_state)}\n"
            f"  • Bounty + source code     : {qualifying}\n\n"
            f"🔔 You'll be notified instantly when:\n"
            f"  • A new program adds source code scope\n"
            f"  • An existing program adds source code\n"
            f"  • A program starts paying bounties\n\n"
            f"🔁 Runs every 30 minutes, 24x7\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        telegram_send(summary)
        print("✅ Baseline summary sent to Telegram. Monitor is live!\n")
        return

    # ── Normal run: send per-event notifications ──
    print(f"📬 Sending {len(events)} notification(s)…")

    for prog, platform, event in events:
        msg = build_message(prog, platform, event)
        ok  = telegram_send(msg)
        key = program_key(prog, platform)
        print(f"  {'✓' if ok else '✗'} [{event}] {key}")
        time.sleep(1)   # respect Telegram rate limits

    if not events:
        print("  No changes detected this cycle.")

    print("\n✅ Cycle complete.\n")


if __name__ == "__main__":
    main()
