#!/usr/bin/env python3
"""
vdp_hunter.py — /public-BBP backend for the bounty monitor bot.

Finds & ranks recently launched/updated DIRECT vulnerability disclosure
programs (VDPs) and paid bug bounties with fewer observable signs of
researcher attention.

Honesty rules baked in (spec):
- A search hit is a LEAD, never proof. The vendor's CURRENT policy page is
  opened and gated before a candidate may rank. Snippets are never evidence.
- Competition is unobservable → proxy signals only, labelled
  lower-signal / mixed / unknown. Never stated as fact.
- Launch dates are never invented: freshness labels are
  launched / updated / age unknown, each tied to a primary URL.
- Discretionary wording ("may reward", swag, credit, HoF-only) is never
  sold as guaranteed cash; a VDP with no stated bounty fails cash_required.
- No active security testing ever runs here; discovery only reads public
  pages/repos. Search results are cached for a day as LEADS, but cached
  data is never used as current-policy evidence — policies are re-fetched.

Run:   python3 vdp_hunter.py "count=3"          (manual smoke test)
Call:  from bot.py → vdp_hunter.run(args, chat_id=..., tracked=[...])
"""

import html as _html
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

import requests

# ── Config ─────────────────────────────────────────────────────────────────────

STORE_FILE      = os.environ.get("VDP_STORE_FILE", "vdp_store.json")
BUDGET_SEC      = int(os.environ.get("VDP_BUDGET_SEC", "110"))   # whole run
DISCOVER_BUDGET = 45          # seconds max for search phase
VERIFY_WORKERS  = 4
HTTP_TIMEOUT    = 12
DISCOVERY_TTL   = 86400       # cache search LEADS for a day

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 BountyMonitor/VDP-research")

MAJOR_PLATFORMS = ("hackerone.com", "bugcrowd.com", "intigriti.com",
                   "yeswehack.com", "hackenproof.com", "immunefi.com",
                   "cantina.xyz", "sherlock.xyz", "openbugbounty.org",
                   "code4rena.com")

# leads from these hosts are never policy pages (news / social / aggregators)
LEAD_BLOCKLIST = (
    "medium.com", "reddit.com", "news.ycombinator.com", "twitter.com", "x.com",
    "linkedin.com", "facebook.com", "youtube.com", "wikipedia.org",
    "thehackernews.com", "bleepingcomputer.com", "securityweek.com",
    "helpnetsecurity.com", "itsecurityguru.co.uk", "therecord.media",
    "darkreading.com", "infosecurity-magazine.com", "portswigger.net",
    "bugcrowd.com", "hackerone.com", "intigriti.com", "yeswehack.com",
    "hackenproof.com", "immunefi.com", "cantina.xyz", "sherlock.xyz",
    "openbugbounty.org", "code4rena.com", "chaos.projectdiscovery.io",
    "vuldb.com", "cve.org", "nvd.nist.gov", "cvedetails.com",
    "responsible.disclosure", "openbugbounty", "bugbounty.site",
    "disclose.io", "awesome-security", "github.com/arkadiyt",
    "dailysecurityreview.com", "tryhackme.com", "infosecwriteups.com",
)

NICHE_TLDS = {".io", ".ai", ".dev", ".app", ".net", ".org", ".co", ".eu",
              ".de", ".fr", ".es", ".it", ".nl", ".se", ".ch", ".at", ".pl",
              ".in", ".jp", ".sg", ".ch", ".br", ".fi", ".no", ".cz", ".be"}

# query families — ≥3 families, rotated languages, several run with a
# 30-day recency filter (ddg df=m) then widened (no filter)
Q_RECENT = [
    '"responsible disclosure" "reward" "security@" -hackerone -bugcrowd -intigriti -hackenproof',
    '"bug bounty" "critical" "security@" -hackerone -bugcrowd',
    '"launched" "bug bounty" "security@"',
]
Q_WIDE = [
    '"vulnerability disclosure" "hall of fame" "reward"',
    'inurl:responsible-disclosure "reward"',
    '"updated" "responsible disclosure" "reward" "email"',
    '"self-hosted" "security policy" "reward"',
    'site:github.com "SECURITY.md" "bounty" "security@"',
]
Q_REGION = {
    "eu": ['"Offenlegung" "Belohnung" "Sicherheitslücke" "security@"',
           '"divulgation responsable" "récompense"',
           '"divulgación responsable" "recompensa"'],
    "in": ['"bug bounty" "₹" "security@"',
           '"responsible disclosure" "reward" site:.in'],
    "apac": ['"bug bounty" "security@" singapore OR japan OR korea "reward"'],
    "uk":  ['"responsible disclosure" "reward" "security@" UK'],
    "us":  [],
}
Q_CAT = {
    "web3":    ['"bug bounty" "web3" "security@" -immunefi -code4rena -cantina',
                'site:github.com "SECURITY.md" "web3" "bounty"'],
    "product": ['"security policy" "bounty" "self-hosted" version',
                '"software security" "bug bounty" "changelog"'],
    "web":     ['"responsible disclosure" "reward" wildcard "*.com"'],
}

WEIGHTS = {"freshness": 25, "competition": 25, "surface": 20,
           "cve": 15, "reward": 10, "triage": 5}

# ── Small utils ────────────────────────────────────────────────────────────────

def esc(s) -> str:
    return _html.escape(str(s or ""), quote=False)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def load_store() -> dict:
    try:
        d = json.load(open(STORE_FILE))
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    return {"_discovery": {}, "candidates": {}}


def save_store(store: dict):
    tmp = f"{STORE_FILE}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w") as f:
            json.dump(store, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STORE_FILE)
    except Exception:
        pass


def http_get(url: str, want="text", referer=None):
    """Polite single-shot GET. Returns (ok, text_or_json, headers).
    headers['_final_url'] records the post-redirect URL."""
    try:
        r = requests.get(
            url, timeout=HTTP_TIMEOUT,
            headers={"User-Agent": UA, "Accept-Language": "en",
                     "Referer": referer or "https://duckduckgo.com/"},
            allow_redirects=True)
        h = dict(r.headers)
        h["_final_url"] = r.url
        if r.status_code in (403, 429) or r.status_code >= 400:
            return False, "", h
        if want == "json":
            return True, r.json(), h
        return True, r.text, h
    except Exception:
        return False, "", {}


# ── Discovery (leads only — never proof) ───────────────────────────────────────

TAG_RE = re.compile(r"<[^>]+>")
RESULT_HREF_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)
LITE_LINK_RE = re.compile(r'<a[^>]+href="(https?://[^"]+|//duckduckgo[^"]+)"[^>]*class="result-link"[^>]*>(.*?)</a>', re.S)


def _unuddg(href: str) -> str:
    href = _html.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    if "uddg=" in href:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query).get("uddg", [""])[0]
        return urllib.parse.unquote(q)
    return href if href.startswith("http") else ""


def ddg_search(query: str, df: str = None) -> list:
    """DuckDuckGo HTML (+lite fallback) search → [{url,title}]. Leads only."""
    try:
        r = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query, **({"df": df} if df else {})},
            headers={"User-Agent": UA,
                     "Content-Type": "application/x-www-form-urlencoded"},
            timeout=HTTP_TIMEOUT + 3, allow_redirects=True)
        if r.ok:
            out = []
            for href, title in RESULT_HREF_RE.findall(r.text):
                url = _unuddg(href)
                if url:
                    out.append({"url": url, "title": TAG_RE.sub("", title).strip()[:120]})
            if out:
                return out[:14]
            if "No  results" in r.text or "no results" in r.text.lower():
                return []
    except Exception:
        pass
    # lite fallback
    try:
        params = {"q": query}
        if df:
            params["df"] = df
        ok, text, _ = http_get("https://lite.duckduckgo.com/lite/?"
                               + urllib.parse.urlencode(params))
        if ok:
            out = []
            for href, title in LITE_LINK_RE.findall(text):
                url = _unuddg(href)
                if url:
                    out.append({"url": url, "title": TAG_RE.sub("", title).strip()[:120]})
            return out[:14]
    except Exception:
        pass
    return []


def github_discovery(since_iso: str) -> list:
    """Repos whose readme mentions a bounty + security@ (search API, 1 call).
    Returns raw SECURITY.md URLs — still leads until fetched."""
    q = f'"bug bounty" "security@" in:readme pushed:>{since_iso}'
    ok, data, _ = http_get("https://api.github.com/search/repositories"
                           + "?" + urllib.parse.urlencode({"q": q, "sort": "updated", "per_page": 10}),
                           want="json")
    if not ok or not isinstance(data, dict):
        return []
    out = []
    for it in data.get("items", [])[:10]:
        full = it.get("full_name", "")
        if not full:
            continue
        out.append({
            "url": f"https://raw.githubusercontent.com/{full}/HEAD/SECURITY.md",
            "title": full,
            "stars": it.get("stargazers_count"),
        })
    return out


def _plausible_policy(url: str) -> bool:
    u = url.lower()
    host = urllib.parse.urlparse(u).netloc.split(":")[0]
    if any(b in u for b in LEAD_BLOCKLIST):
        # github SECURITY.md / security policy repo pages are the exception
        if "github.com" in host:
            return any(p in u for p in ("/security.md", "/security.txt",
                                        "/blob/main/security", "/blob/master/security"))
        return False
    if not host or host.endswith("duckduckgo.com"):
        return False
    return any(p in u for p in (
        "security", "disclosure", "bug-bounty", "bugbounty", "responsible",
        "vulnerability", "security.txt", "well-known", "hall-of-fame", "bounty"))


def _canonicalize_lead(url: str) -> str:
    u = url
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)/blob/(?:main|master)/"
                 r"(SECURITY\.md|security\.txt|security/.*)$", u, re.I)
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/HEAD/{m.group(3)}"
    return u.split("#")[0]


def discover(opts: dict, store: dict, deadline: float) -> list:
    """Run query families (30d filter first, then widened) + GitHub route.
    Uses the 1-day lead cache where possible; caches fresh leads."""
    leads, seen = [], set()
    disc = store.setdefault("_discovery", {})
    since_iso = (now_utc() - timedelta(days=30)).strftime("%Y-%m-%d")

    families = []
    for q in Q_RECENT:
        families.append((q, "m"))
    for q in Q_WIDE:
        families.append((q, None))
    if opts["region"] in Q_REGION:
        for q in Q_REGION[opts["region"]]:
            families.append((q, None))
    if opts["cat"] in Q_CAT:
        families.extend((q, None) for q in Q_CAT[opts["cat"]])

    def _absorb(items):
        for it in items:
            cu = _canonicalize_lead(it["url"])
            if cu in seen or not _plausible_policy(cu):
                continue
            seen.add(cu)
            it["url"] = cu
            leads.append(it)

    for q, df in families:
        if time.time() > deadline or len(leads) >= 18:
            break
        key = f"{q}|{df}"
        hit = disc.get(key)
        if hit and time.time() - hit.get("ts", 0) < DISCOVERY_TTL:
            _absorb(hit.get("results", []))
            continue
        results = ddg_search(q, df)
        disc[key] = {"ts": int(time.time()), "results": results}
        _absorb(results)
        time.sleep(1.3)   # stay polite with the free search endpoint

    if time.time() < deadline and opts["cat"] != "web":
        key = "gh:readme-bounty"
        hit = disc.get(key)
        if hit and time.time() - hit.get("ts", 0) < DISCOVERY_TTL:
            _absorb(hit.get("results", []))
        else:
            items = github_discovery(since_iso)
            disc[key] = {"ts": int(time.time()), "results": items}
            _absorb(items)
    return leads


# ── Verification: open the CURRENT policy and gate it ──────────────────────────

EMAIL_RE  = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
MONEY_RE  = re.compile(r"[$€£₹]\s?\d[\d,\.]*")
WILD_RE   = re.compile(r"(?:\*\.)?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){1,3}")
ISO_DATE  = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
EN_DATE   = re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(\d{1,2}),?\s+(20\d{2})\b", re.I)
MONTH_NUM = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
             "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

PERM_MARKERS   = ("responsible disclosure", "vulnerability disclosure",
                  "coordinated vulnerability", "security researchers",
                  "report a vulnerability", "security vulnerability",
                  "security issues", "welcome security")
ROUTE_MARKERS  = {"email": EMAIL_RE, "form": r"forms\.gle|docs\.google\.com/forms|typeform",
                  "github-advisory": r"private vulnerability reporting|github security advisor|security/advisories/new"}
CASH_MARKERS   = ("bug bounty", "bounty", "monetary reward", "cash reward",
                  "paid", "payment", "payout", "financial reward")
DISCRETIONARY  = ("may reward", "at our discretion", "at the discretion",
                  "discretionary", "swag", "no monetary", "not offer monetary",
                  "cannot offer", "hall of fame only", "credit only", "goodies")
NO_CASH_WORDS  = ("no bounty", "we do not offer", "non-monetary", "not provide monetary")
SAFE_HARBOR    = ("safe harbor", "safe-harbor", "will not pursue", "good faith",
                  "authorize", "legally")
SLA_RE         = re.compile(r"(?:within|under)\s+\d+\s+(?:business\s+)?(?:hours|days)|acknowledge.*?within", re.I)
CLOSED_MARKERS = ("paused", "temporarily closed", "no longer accepting",
                  "suspended", "discontinued", "program closed", "has ended",
                  "on hold", "closed until")
CVE_MARKERS    = ("self-hosted", "self host", "on-premise", "on-premises", "on prem",
                  "version", "release", "changelog", "download", "sdk", "docker",
                  "package", "open source", "open-source", "api", "mobile app",
                  "desktop app", "appliance", "browser extension", "cli")
LAUNCH_WORDS   = ("we are launching", "we're launching", "pleased to launch",
                  "announcing", "is live", "new program", "we launch",
                  "has launched", "recently launched")
UPDATED_WORDS  = ("last updated", "updated on", "revised", "effective",
                  "last modified", "changelog")
HOF_WORDS      = ("hall of fame", "acknowledg", "thank.*researchers", "credits")


def html_to_text(h: str) -> str:
    h = re.sub(r"(?is)<(script|style|head|nav|footer)[^>]*>.*?</\1>", " ", h)
    h = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>|</h[1-6]>", "\n", h)
    t = TAG_RE.sub(" ", _html.unescape(h))
    return re.sub(r"[ \t]+", " ", t)


def _best_date(text: str, headers: dict, gh_commit_date: str = None):
    """Most plausible policy date + its source. Never invented.
    Returns (iso_or_None, kind, source, evidence)."""
    low = text.lower()
    launched = any(w in low for w in LAUNCH_WORDS)
    # 1) dated "last updated / effective / revised" context
    best = None
    for m in re.finditer(
            r"(?:last\s+updated|updated\s+on|revised|effective(?:\s+as\s+of)?)"
            r"[:\s]*([a-z0-9,\s]*?\d[^\n]{0,25}?\d{4})", low):
        cand = _parse_date_str(m.group(1))
        if cand and (not best or cand > best[0]):
            best = (cand, "updated", "policy wording", m.group(0).strip()[:60])
    if not best:
        for m in ISO_DATE.finditer(text):
            cand = _parse_date_str(m.group(0))
            if cand and _sane(cand):
                ctx = low[max(0, m.start() - 40): m.start()]
                kind = "launched" if launched and any(
                    w in ctx for w in ("launch", "announc", "live", "new")) else "updated"
                if not best or cand > best[0]:
                    best = (cand, kind, "date on page", m.group(0))
    if not best:
        for m in EN_DATE.finditer(text):
            cand = _parse_date_str(m.group(0))
            if cand and _sane(cand):
                if not best or cand > best[0]:
                    best = (cand, "updated", "date on page", m.group(0))
    if not best and gh_commit_date:
        return gh_commit_date[:10], "updated", "git commit (SECURITY.md)", "last commit touching policy"
    if not best and headers.get("Last-Modified"):
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(headers["Last-Modified"])
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%d"), "updated", "HTTP Last-Modified", ""
        except Exception:
            pass
    if not best:
        return None, ("launched" if launched else "unknown"), "none", ""
    d, kind, src, ev = best
    if launched:
        kind = "launched"
    return d.strftime("%Y-%m-%d"), kind, src, ev


def _parse_date_str(s: str):
    m = ISO_DATE.search(s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except Exception:
            return None
    m = EN_DATE.search(s)
    if m:
        try:
            return datetime(int(m.group(3)), MONTH_NUM[m.group(1).lower()[:3]],
                            int(m.group(2)), tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _sane(d: datetime) -> bool:
    return now_utc() + timedelta(days=2) >= d >= datetime(2020, 1, 1, tzinfo=timezone.utc)


ASSET_STOP = {"security.txt", "index.html", "readme.md", "changelog.md",
              "e.g", "i.e", "etc", "e.g.", "i.e.", "vs", "v."}


def _asset_ok(w: str) -> bool:
    """Reject version strings / filenames / abbreviations that fake hostnames."""
    if w in ASSET_STOP:
        return False
    labels = w.strip("*.[]()").split(".")
    if len(labels) < 2:
        return False
    if not all(re.fullmatch(r"[a-z][a-z0-9-]*", l) for l in labels):
        return False                      # rejects 0.1.0, 2.x, 1.2.3
    if not re.fullmatch(r"[a-z]{2,}", labels[-1]):
        return False                      # TLD must be alphabetic (rejects .0/.x)
    return True


def verify(lead: dict, tracked_names=None) -> dict:
    """Fetch the CURRENT policy for a lead and extract gate signals."""
    url = lead["url"]
    c = {"lead_url": url, "title": lead.get("title", ""), "source": lead.get("source", "web"),
         "stars": lead.get("stars"), "ok": False, "why": "", "sig": {}}
    ok, body, headers = http_get(url)
    if not ok or not body:
        c["why"] = "policy page unreachable"
        return c
    is_markdown = "raw.githubusercontent.com" in url or "security.txt" in url.lower()
    text = body if is_markdown else html_to_text(body)
    text_l = text.lower()
    c["ok"] = len(text) > 120
    if not c["ok"]:
        c["why"] = "policy page too small to assess"
        return c
    c["text"] = text[:20000]
    c["final_url"] = headers.get("_final_url") or url
    c["headers"] = {"Last-Modified": headers.get("Last-Modified", "")}
    sig = c["sig"]

    host = urllib.parse.urlparse(c["final_url"]).netloc.split(":")[0]
    mraw = re.match(r"https://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/", c["final_url"])
    if mraw:
        c["key"] = f"gh:{mraw.group(1)}/{mraw.group(2)}"
    else:
        base = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        c["key"] = base or host

    sig["perm"] = any(m in text_l for m in PERM_MARKERS)
    route = None
    emails = sorted({e for e in EMAIL_RE.findall(text)
                     if not e.lower().endswith((".png", ".jpg", ".example", ".gif"))})
    good_emails = [e for e in emails if any(
        p in e.lower() for p in ("security", "bug", "vuln", "sec@", "disclose", "hacker"))]
    sig["email"] = (good_emails or emails)[:1]
    for name, pat in ROUTE_MARKERS.items():
        if re.search(pat, text_l if name != "email" else ""):
            route = name
            break
    sig["route"] = route or ("email" if good_emails else None)

    platforms = [p for p in MAJOR_PLATFORMS if p in text_l]
    sig["platforms"] = platforms

    has_money = bool(MONEY_RE.search(text))
    cash_words = [m for m in CASH_MARKERS if m in text_l]
    no_cash = any(w in text_l for w in NO_CASH_WORDS)
    discretionary = any(w in text_l for w in DISCRETIONARY)
    if no_cash:
        sig["cash"], sig["cash_detail"] = "none", "policy states no monetary rewards"
    elif has_money and cash_words:
        amts = MONEY_RE.findall(text)[:4]
        sig["cash"], sig["cash_detail"] = "explicit", f"amounts on page: {' '.join(amts[:3])}"
    elif cash_words and not discretionary:
        sig["cash"], sig["cash_detail"] = "cash-no-amount", f"cash language: {cash_words[0]}"
    elif discretionary and cash_words:
        sig["cash"], sig["cash_detail"] = "discretionary", "reward wording is discretionary"
    else:
        sig["cash"], sig["cash_detail"] = "none", "no cash language found"

    wilds = sorted({w for w in WILD_RE.findall(text_l) if _asset_ok(w)
                    and not any(x in w for x in (
                        "example.com", "yourdomain", "domain.com", "company.com",
                        "email", "github.com", "twitter", "example.org"))})
    repo_urls = sorted({u for u in re.findall(r"github\.com/[\w.-]+/[\w.-]+", text_l)
                        if u.split("/")[1] not in ("en", "about", "features", "topics",
                                                   "orgs", "site", "blog", "security")})[:5]
    sig["assets"] = (wilds[:6] + [u for u in repo_urls if u not in wilds])[:8]
    sig["has_exclusions"] = ("out of scope" in text_l) or ("exclusions" in text_l) or ("not in scope" in text_l)
    sig["closed"] = [m for m in CLOSED_MARKERS if m in text_l]
    sig["cve_markers"] = sorted({m for m in CVE_MARKERS if m in text_l})
    sig["safe_harbor"] = any(s in text_l for s in SAFE_HARBOR)
    sig["sla"] = bool(SLA_RE.search(text))
    sig["hof"] = any(re.search(w, text_l) for w in HOF_WORDS)
    sig["tracked"] = _is_tracked(c, tracked_names or [])
    return c


def _is_tracked(c: dict, tracked_names: list) -> bool:
    """Is this vendor already on a major platform feed we track? (competition proxy)"""
    key = (c.get("key") or "").lower()
    toks = [t for t in re.split(r"[.\s-]+", key) if len(t) > 2]
    if not toks:
        return False
    for t in tracked_names:
        if key and key in t:
            return True
        if any(tok in t for tok in toks):
            return True
    return False


# ── GitHub policy commit date (evidence, not a lead) ───────────────────────────

def gh_commit_date(repo_full: str) -> str:
    ok, data, _ = http_get(f"https://api.github.com/repos/{repo_full}/commits"
                           "?path=SECURITY.md&per_page=1", want="json")
    if ok and isinstance(data, list) and data:
        return (data[0].get("commit", {}).get("author", {}).get("date", "") or "")[:10]
    return ""


# ── Gates, competition, scoring ────────────────────────────────────────────────

def gate_fails(c: dict, opts: dict) -> list:
    """Hard gates in spec order. Empty list = verified."""
    if not c.get("ok"):
        return ["policy unreachable → needs verification"]
    sig = c.get("sig") or {}
    f = []
    if not sig.get("perm"):
        f.append("no explicit disclosure invitation")
    if not sig.get("route"):
        f.append("no private reporting route")
    if sig.get("closed"):
        f.append(f"closure language: {sig['closed'][0]}")
    if opts["cash_required"] and sig.get("cash") in ("none", "discretionary"):
        f.append("no guaranteed cash (VDP/discretionary only)")
    if opts["direct_only"] and sig.get("platforms"):
        f.append(f"routes through {sig['platforms'][0]}")
    if opts["exclude"] and any(x in c["key"] for x in opts["exclude"]):
        f.append("excluded by user")
    return f


def competition_signals(c: dict) -> tuple:
    """Proxy signals only — competition itself is unobservable.
    Returns (label, score, [evidence strings])."""
    sig = c["sig"]
    ev = []
    if sig.get("route") in ("email", "form", "github-advisory") and not sig.get("platforms"):
        ev.append("direct private route, no platform link")
    if not sig.get("tracked"):
        ev.append("absent from the 9 platform feeds this bot tracks")
    host = urllib.parse.urlparse(c.get("final_url", c["lead_url"] or "")).netloc
    tld = "." + host.split(".")[-1] if "." in host else ""
    if tld in NICHE_TLDS:
        ev.append(f"niche TLD ({tld})")
    if c.get("stars") is not None and c["stars"] < 300:
        ev.append(f"small repo ({c['stars']}★)")
    if not sig.get("hof"):
        ev.append("no hall-of-fame/credits on policy")
    if len(ev) >= 3:
        return "lower-signal", (5 if len(ev) >= 4 else 4), ev[:3]
    if len(ev) == 2:
        return "mixed", 3, ev[:3]
    if len(ev) == 1:
        return "unknown", 2, ev[:3]
    return "unknown", 1, ["too little evidence — treat as unknown"]


def freshness_score(date_iso: str, kind: str, now: datetime) -> tuple:
    """Bands per spec. Returns (score, label)."""
    if not date_iso:
        return 0, "age unknown"
    try:
        d = datetime.strptime(date_iso, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return 0, "age unknown"
    days = (now - d).days
    if days < 0:
        days = 0
    if days <= 30:
        return 5, f"{kind} {date_iso}"
    if days <= 90:
        return 4, f"{kind} {date_iso}"
    if days <= 180:
        return 3, f"{kind} {date_iso}"
    if days <= 365:
        return 2, f"{kind} {date_iso}"
    return 0, f"{kind} {date_iso} (stale)"


def score_candidate(c: dict, opts: dict, now: datetime) -> dict:
    sig = c["sig"]
    f_date = c.get("date_iso")
    f_kind = c.get("date_kind", "unknown")
    fr_score, fr_label = freshness_score(f_date, f_kind, now)

    comp_label, comp_score, comp_ev = competition_signals(c)

    n_assets = len(sig.get("assets") or [])
    surface = min(5, 1 + n_assets)
    if any(m in sig.get("cve_markers", []) for m in ("api", "mobile app", "desktop app")):
        surface = min(5, surface + 1)

    m = len(sig.get("cve_markers") or [])
    if m >= 3 and c.get("stars") is not None:
        cve = 5
    elif m >= 3:
        cve = 4
    elif m == 2:
        cve = 3
    elif m == 1:
        cve = 2
    else:
        cve = 1
    if opts["cat"] == "product" and cve >= 3:
        cve = min(5, cve + 1)
    if opts["cat"] == "web3" and any(x in sig.get("cve_markers", []) for x in ("api", "open source")):
        cve = min(5, cve + 1)

    cash = sig.get("cash")
    reward = {"explicit": 5, "cash-no-amount": 4, "discretionary": 2}.get(cash, 0)
    if not opts["cash_required"] and cash == "discretionary":
        reward = 3

    tri = 1
    if sig.get("route"):
        tri = 2
    if sig.get("sla") or sig.get("safe_harbor"):
        tri = 4
    if sig.get("sla") and sig.get("safe_harbor"):
        tri = 5

    parts = {"freshness": fr_score, "competition": comp_score, "surface": surface,
             "cve": cve, "reward": reward, "triage": tri}
    total = round(sum(WEIGHTS[k] * v / 5 for k, v in parts.items()))
    c["score"] = {"parts": parts, "total": total, "fresh_label": fr_label,
                  "comp_label": comp_label, "comp_ev": comp_ev}
    return c["score"]


# ── Option parsing ──────────────────────────────────────────────────────────────

def parse_args(s: str) -> dict:
    o = {"count": 5, "region": "", "cat": "", "cash_required": True,
         "direct_only": True, "cve_priority": True, "max_age_days": 180,
         "exclude": set(), "update": False}
    toks = (s or "").split()
    if toks and toks[0].isdigit():
        o["count"] = int(toks[0])
        toks = toks[1:]
    for t in toks:
        if "=" not in t:
            if t.lower() in ("update", "updates"):
                o["update"] = True
            continue
        k, v = t.split("=", 1)
        k, v = k.lower().strip(), v.strip()
        if k in ("count", "n"):
            try: o["count"] = int(v)
            except ValueError: pass
        elif k in ("region", "r"):
            o["region"] = v.lower()
        elif k in ("cat", "category"):
            o["cat"] = v.lower() if v.lower() in ("web", "product", "web3") else ""
        elif k in ("cash", "cash_required"):
            o["cash_required"] = v.lower() not in ("0", "false", "no", "off")
        elif k in ("direct", "direct_only"):
            o["direct_only"] = v.lower() not in ("0", "false", "no", "off")
        elif k in ("cve", "cve_priority"):
            o["cve_priority"] = v.lower() not in ("0", "false", "no", "off")
        elif k in ("age", "max_age_days"):
            try: o["max_age_days"] = max(1, min(int(v), 3650))
            except ValueError: pass
        elif k in ("exclude", "excluded", "excluded_programs"):
            o["exclude"] = {x.strip().lower() for x in v.split(",") if x.strip()}
    o["count"] = max(1, min(o["count"], 8))
    if not o["cat"]:
        o["cat"] = "web+product"
    return o


# ── Main entry ─────────────────────────────────────────────────────────────────

def run(args: str, chat_id: str = "", tracked_names=None) -> str:
    t0 = time.time()
    opts = parse_args(args)
    now = now_utc()
    store = load_store()
    tracked_names = tracked_names or []
    caveats, needs_verify = [], []

    # 1) discovery (cached 1d as LEADS; policies themselves are always re-fetched)
    leads = discover(opts, store, t0 + DISCOVER_BUDGET)
    if not leads:
        save_store(store)
        return ("🔎 <b>VDP research</b>\n\n"
                "No usable leads this run (search endpoint blocked or empty).\n"
                "Leads were NOT verified against any policy. Try again in a bit.")

    # 2) verify candidates in parallel until budget
    deadline = t0 + BUDGET_SEC - 12
    cands = []
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as ex:
        futs = []
        for it in leads:
            if time.time() > deadline and len(futs) >= 6:
                break
            it.setdefault("source", "web")
            if "raw.githubusercontent.com" in it["url"]:
                it["source"] = "github"
            futs.append(ex.submit(verify, it, tracked_names))
        for fu in futs:
            try:
                cands.append(fu.result(timeout=max(5, int(deadline - time.time()))))
            except Exception:
                pass

    # 2b) GitHub commit-date evidence for repo policies (cheap, capped)
    for c in cands:
        if time.time() > deadline:
            break
        m = re.match(r"https://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/", c["lead_url"])
        if m:
            cd = gh_commit_date(f"{m.group(1)}/{m.group(2)}")
            if cd:
                c["gh_commit"] = cd

    # 3) dates + gates + scoring
    verified = []
    for c in cands:
        d, kind, src, ev = _best_date(c.get("text", ""), c.get("headers", {}),
                                      c.get("gh_commit"))
        c["date_iso"], c["date_kind"], c["date_source"] = d, kind, src
        fails = gate_fails(c, opts)
        if fails:
            if len(needs_verify) < 5:
                needs_verify.append((c.get("title") or c.get("key") or c["lead_url"],
                                     c["lead_url"], fails[0]))
            continue
        score_candidate(c, opts, now)

        # age gate: documented age beyond max_age only fills leftover slots
        if c["date_iso"]:
            try:
                age_days = (now - datetime.strptime(c["date_iso"], "%Y-%m-%d")
                            .replace(tzinfo=timezone.utc)).days
            except Exception:
                age_days = None
            c["over_age"] = bool(age_days is not None and age_days > opts["max_age_days"])
        else:
            c["over_age"] = False
            c["_unknown_age"] = True
        verified.append(c)

    # dedup suppression for THIS chat unless update requested
    def _sent_before(c):
        rec = store["candidates"].get(_store_key(c))
        return bool(rec and chat_id and chat_id in (rec.get("previously_sent_chat_ids") or []))

    pool = [c for c in verified if opts["update"] or not _sent_before(c)]
    in_age   = [c for c in pool if not c["over_age"]]
    over_age = [c for c in pool if c["over_age"]]
    in_age.sort(key=lambda c: (c["score"]["total"], c.get("date_iso") or "",
                               len(c["sig"].get("assets") or [])), reverse=True)
    over_age.sort(key=lambda c: c["score"]["total"], reverse=True)
    picked = in_age[:opts["count"]]
    if len(picked) < opts["count"] and over_age:
        extra = over_age[:opts["count"] - len(picked)]
        picked += extra
        caveats.append(f"{len(extra)} older-than-{opts['max_age_days']}d program(s) shown to fill the count — labeled below")

    # 4) persist store (dedup + rescan bookkeeping)
    for c in verified:
        k = _store_key(c)
        rec = store["candidates"].get(k, {"first_seen": iso(now)})
        rec.update({"url": c["final_url"] or c["lead_url"], "company": c.get("title") or c.get("key"),
                    "last_verified": iso(now), "last_score": c["score"]["total"],
                    "date": c.get("date_iso"), "date_kind": c.get("date_kind"),
                    "date_source": c.get("date_source"),
                    "score_parts": c["score"]["parts"],
                    "previously_sent_chat_ids": rec.get("previously_sent_chat_ids", [])})
        if c in picked and chat_id and chat_id not in rec["previously_sent_chat_ids"]:
            rec["previously_sent_chat_ids"].append(chat_id)
        store["candidates"][k] = rec
    # prune store to last 300 candidates
    if len(store["candidates"]) > 300:
        keep = sorted(store["candidates"].items(),
                      key=lambda kv: kv[1].get("last_verified", ""), reverse=True)[:300]
        store["candidates"] = dict(keep)
    save_store(store)

    # 5) format reply
    lines = ["🔎 <b>Low-competition direct VDPs</b>",
             f"Checked: {now.strftime('%Y-%m-%d')} UTC · competition is <b>estimated</b> from proxies, never a fact", ""]
    if not picked:
        lines.append("No candidates passed all gates this run.")
        if needs_verify:
            lines.append("")
            lines.append("<b>Needs verification</b> (did NOT rank):")
            for name, url, why in needs_verify[:5]:
                lines.append(f"• {esc(name)} — {esc(why)}\n  {esc(url)}")
        gates_hit = {}
        for c in cands:
            for f in gate_fails(c, opts):
                gates_hit[f.split(" (")[0].split(" →")[0]] = gates_hit.get(f.split(" (")[0].split(" →")[0], 0) + 1
        if gates_hit:
            lines.append("")
            lines.append("Gate removals: " + esc(", ".join(f"{k} x{n}" for k, n in sorted(gates_hit.items(), key=lambda x: -x[1])[:4])))
        lines.append("")
        lines.append(f"💡 Try <code>/public-bbp count={opts['count']} cash=0</code> (allow VDPs) or <code>direct=0</code> (allow platforms).")
        return "\n".join(lines)

    for i, c in enumerate(picked, 1):
        sc = c["score"]
        sig = c["sig"]
        name = (c.get("title") or c.get("key") or "?").strip()[:60]
        fresh_txt = sc["fresh_label"]
        if c.get("date_source") and c["date_iso"]:
            fresh_txt += f" ({c['date_source']})"
        if c.get("_unknown_age"):
            fresh_txt = "age unknown — no dated policy evidence"
        if c.get("over_age"):
            fresh_txt = f"OLDER than {opts['max_age_days']}d — " + fresh_txt
        assets = sig.get("assets") or ["(generic scope statement — verify before hunting)"]
        reward_txt = {"explicit": f"cash {sig.get('cash_detail','')}",
                      "cash-no-amount": "cash promised, no amounts on page",
                      "discretionary": "discretionary wording — not guaranteed cash",
                      "none": "no bounty stated"}[sig.get("cash", "none")]
        cve_level = "high" if sc["parts"]["cve"] >= 4 else ("medium" if sc["parts"]["cve"] == 3 else "low")
        markers = ", ".join(sig.get("cve_markers", [])[:3]) or "few versioned-product markers"
        route_map = {"form": "vendor form", "github-advisory": "GitHub private advisory"}
        if sig.get("email"):
            route_txt = "email " + ", ".join(sig["email"])
        else:
            route_txt = route_map.get(sig.get("route"), "see policy")
        lines.append(f"#{i} <b>{esc(name)}</b> (score {sc['total']}/100)")
        lines.append(f"Freshness: {esc(fresh_txt)}")
        lines.append(f"Competition: {sc['comp_label']} — {esc('; '.join(sc['comp_ev']))}")
        lines.append(f"Scope: {esc(', '.join(assets[:4]))} | Reward: {esc(reward_txt)}")
        lines.append(f"Why hunt: {esc(markers)} · CVE potential: {cve_level}")
        lines.append(f"Report: {esc(route_txt)} | Policy: {esc(c.get('final_url') or c['lead_url'])}")
        lines.append("")

    if len(picked) < opts["count"]:
        lines.append(f"ℹ️ Only {len(picked)} verified program(s) found — never padded with unverified ones.")
    if caveats:
        lines.append("<b>Caveats</b>")
        lines.extend(f"• {esc(x)}" for x in caveats)
    if needs_verify:
        lines.append(f"• {len(needs_verify)} lead(s) failed gates and went to needs-verification (not recommended)")
    lines.append(f"• Region filter (if set) steers search language only — it does not verify vendor HQ")
    lines.append(f"• Policies re-fetched this run ({int(time.time()-t0)}s); discovery leads cached ~1 day. /public-bbp update resurfaces prior picks")
    return "\n".join(lines)


def _store_key(c: dict) -> str:
    return (c.get("key") or urllib.parse.urlparse(c["lead_url"]).netloc or c["lead_url"]).lower()


if __name__ == "__main__":
    print(run(" ".join(sys.argv[1:]) or "count=3"))
