import os
import re
import time
import sqlite3
import threading
import requests
from datetime import date
from urllib.parse import urlparse
from dotenv import load_dotenv

from cache import cache_get, cache_set

# Load environment variables
load_dotenv()

# Get API keys from environment variables
SCALESERP_KEY = os.getenv("SCALESERP_KEY", "")
SCALESERP_KEY2 = os.getenv("SCALESERP_KEY2", "")  # Fallback key
SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")

# ── Rate limiter ─────────────────────────────────────────────────────────────
# Protects paid API credits (ScaleSerp / SerpApi) from being exhausted.
# Limits: max 5 ScaleSerp calls per scan, max 30 ScaleSerp calls per day.
# When either limit is hit the search falls through to DDG (free) automatically.

_RATE_LIMIT_DAILY  = int(os.getenv("SCALESERP_DAILY_LIMIT", "30"))
_RATE_LIMIT_SCAN   = int(os.getenv("SCALESERP_SCAN_LIMIT",  "5"))

_RL_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scaleserp_usage.db"
)
_rl_lock = threading.Lock()


def _rl_init():
    """Create the usage table if it doesn't exist."""
    with sqlite3.connect(_RL_DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS daily_usage (
                day  TEXT PRIMARY KEY,
                hits INTEGER NOT NULL DEFAULT 0
            )
        """)
        con.commit()


def _rl_daily_count() -> int:
    """Return how many ScaleSerp calls have been made today."""
    today = str(date.today())
    try:
        with sqlite3.connect(_RL_DB_PATH) as con:
            row = con.execute(
                "SELECT hits FROM daily_usage WHERE day = ?", (today,)
            ).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def _rl_increment():
    """Increment today's ScaleSerp call counter by 1."""
    today = str(date.today())
    try:
        with _rl_lock:
            with sqlite3.connect(_RL_DB_PATH) as con:
                con.execute("""
                    INSERT INTO daily_usage (day, hits) VALUES (?, 1)
                    ON CONFLICT(day) DO UPDATE SET hits = hits + 1
                """, (today,))
                con.commit()
    except Exception:
        pass


def _rl_daily_exceeded() -> bool:
    return _rl_daily_count() >= _RATE_LIMIT_DAILY


def get_scaleserp_usage() -> dict:
    """Public helper — returns today's usage stats (used by test/dashboard)."""
    count = _rl_daily_count()
    return {
        "today":       count,
        "daily_limit": _RATE_LIMIT_DAILY,
        "scan_limit":  _RATE_LIMIT_SCAN,
        "remaining":   max(0, _RATE_LIMIT_DAILY - count),
        "exceeded":    count >= _RATE_LIMIT_DAILY,
    }


# Initialise DB on module load
_rl_init()

MALWARE_KEYWORDS = {
    "mirai", "hajime", "mozi", "emotet", "qakbot", "cobalt strike", "metasploit",
    "asyncrat", "njrat", "redline", "agenttesla", "formbook", "lokibot", "raccoon",
    "vidar", "lumma", "xmrig", "pdfsider", "darkcomet", "netwire", "remcos",
    "blackmatter", "lockbit", "revil", "conti", "blackcat", "cl0p", "nokoyawa",
    "lazarus", "apt28", "apt29", "apt41", "sandworm", "fancy bear", "cozy bear",
    "ta505", "fin7", "unc2452",
}

APT_ACTORS = {
    "lazarus group", "apt28", "apt29", "apt30", "apt41", "apt10", "apt31",
    "sandworm", "fancy bear", "cozy bear", "wizard spider", "fin7", "fin8",
    "ta505", "ta551", "scattered spider", "volt typhoon", "salt typhoon",
    "unc2452", "unc3944", "muddywater", "mustang panda", "kimsuky", "turla",
    "darkside", "black basta", "akira", "cl0p", "medusa", "lockbit group",
    "conti group", "revil group", "blackcat group",
}

SEVERITY_KEYWORDS = {
    "zero-day": 3, "0-day": 3, "zero day": 3,
    "critical vulnerability": 3, "critical cve": 3,
    "active exploitation": 3, "exploited in the wild": 3,
    "ransomware attack": 2, "data exfiltration": 2,
    "lateral movement": 2, "privilege escalation": 2,
    "command and control": 1, "persistence": 1,
    "initial access": 1, "defense evasion": 1,
}

_CVE_RE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_ATTCK_RE  = re.compile(r'(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9])')
_IP_RE     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|club|info|biz|co)\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
_MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')

_BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "amazonaws.com", "cloudflare.com",
    "apple.com", "facebook.com", "twitter.com", "linkedin.com", "youtube.com",
    "wikipedia.org", "w3.org", "mozilla.org", "python.org",
}

_SKIP_DOMAINS_DEFAULT = [
    "google.com", "bing.com", "youtube.com", "twitter.com", "reddit.com",
    "linkedin.com", "facebook.com", "pastebin.com", "githubusercontent.com",
    "serpapi.com", "scaleserp.com",
]

_TIER1_DOMAINS = {
    "securelist.com", "unit42.paloaltonetworks.com", "blog.talosintelligence.com",
    "research.checkpoint.com", "thedfirreport.com", "mandiant.com",
    "crowdstrike.com", "blogs.blackberry.com",
}

_TIER2_DOMAINS = {
    "any.run", "tria.ge", "nucleon-security.com",
    "malpedia.caad.fkie.fraunhofer.de", "abuse.ch",
    "otx.alienvault.com", "virustotal.com",
}


def _get_gi_config(config):
    return (config or {}).get("google_intel", {})


def _get_domain(url):
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _should_skip(url, skip_set):
    domain = _get_domain(url)
    for skip in skip_set:
        if domain == skip or domain.endswith("." + skip):
            return True
    return False


def _build_queries(indicator, ind_type):
    """
    Build tiered Google dork queries for threat intel hunting.
    Round 1: Tier-1 and Tier-2 targeted site dorks
    Round 2: Broader IOC-focused dorks (no site restriction)
    Round 3: Pure generic search (no filters)
    """
    tier1_sites = (
        "site:securelist.com OR site:unit42.paloaltonetworks.com OR "
        "site:blog.talosintelligence.com OR site:research.checkpoint.com OR "
        "site:thedfirreport.com OR site:mandiant.com OR site:crowdstrike.com OR "
        "site:blogs.blackberry.com"
    )

    tier2_sites = (
        "site:any.run OR site:tria.ge OR site:abuse.ch OR "
        "site:malpedia.caad.fkie.fraunhofer.de OR site:otx.alienvault.com"
    )

    # Round 1 — trusted threat intel sites only
    round1 = [
        f'"{indicator}" ({tier1_sites})',
        f'"{indicator}" ({tier2_sites})',
    ]

    if ind_type == "ip":
        round1 += [
            f'"{indicator}" site:feodotracker.abuse.ch OR site:sslbl.abuse.ch OR site:threatfox.abuse.ch',
        ]
    elif ind_type == "hash":
        round1 += [
            f'"{indicator}" site:bazaar.abuse.ch OR site:hybrid-analysis.com',
        ]

    # Round 2 — broader IOC dorks, no site restriction
    round2 = [
        f'"{indicator}" intext:"indicators of compromise"',
        f'"{indicator}" intext:"command and control" OR intext:"C2 server" OR intext:"botnet"',
        f'"{indicator}" malware threat intelligence report',
    ]

    if ind_type == "ip":
        round2 += [
            f'"{indicator}" intext:"malicious IP" OR intext:"threat actor" OR intext:"attack infrastructure"',
        ]
    elif ind_type == "domain":
        round2 += [
            f'"{indicator}" intext:"phishing" OR intext:"malware distribution" OR intext:"dropper"',
        ]
    elif ind_type == "hash":
        round2 += [
            f'"{indicator}" intext:"malware sample" OR intext:"sandbox analysis"',
        ]

    # Round 3 — pure generic search, no filters at all
    round3 = [
        f'"{indicator}"',
    ]

    return round1, round2, round3


# ── Search backends ──────────────────────────────────────────────────────────

def _search_scaleserp_single(query, api_key, key_name="ScaleSerp"):
    """Query ScaleSerp — real Google results with full dork support."""
    if not api_key:
        print(f"  [{key_name}] No API key found")
        return None, "no_api_key"

    # Daily hard limit — fall through to DDG when exceeded
    if _rl_daily_exceeded():
        used = _rl_daily_count()
        print(f"  [{key_name}] Daily limit reached ({used}/{_RATE_LIMIT_DAILY}) — skipping to DDG")
        return None, "rate_limited"

    try:
        resp = requests.get(
            "https://api.scaleserp.com/search",
            params={
                "api_key":       api_key,
                "q":             query,
                "num":           10,
                "gl":            "us",
                "hl":            "en",
                "google_domain": "google.com",
            },
            timeout=15,
        )
    except requests.exceptions.Timeout:
        print(f"  [{key_name}] Timeout — skipping query")
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        print(f"  [{key_name}] Connection error, check your network")
        return None, "network_error"

    if resp.status_code == 402:
        print(f"  [{key_name}] Out of credits or account suspended")
        return None, "out_of_credits"
    if resp.status_code == 429:
        print(f"  [{key_name}] Rate limit hit")
        return None, "ratelimit"
    if resp.status_code == 401:
        print(f"  [{key_name}] Invalid API key")
        return None, "auth_error"
    if resp.status_code != 200:
        print(f"  [{key_name}] Error {resp.status_code}: {resp.text[:100]}")
        return None, f"http_{resp.status_code}"

    results = resp.json().get("organic_results", [])
    urls = [r["link"] for r in results if "link" in r]
    _rl_increment()  # count this successful call against the daily budget
    remaining = max(0, _RATE_LIMIT_DAILY - _rl_daily_count())
    print(f"  [{key_name}] {len(urls)} results for: {query[:70]}  [{remaining} daily credits left]")
    return urls, None


def _search_serpapi_single(query, api_key):
    """Query SerpApi — real Google results, fallback to ScaleSerp."""
    if not api_key:
        print("  [SerpApi] No API key found")
        return None, "no_api_key"

    try:
        resp = requests.get(
            "https://serpapi.com/search",
            params={
                "api_key": api_key,
                "engine":  "google",
                "q":       query,
                "num":     10,
                "hl":      "en",
                "gl":      "us",
            },
            timeout=15,
        )
    except requests.exceptions.Timeout:
        print(f"  [SerpApi] Timeout — skipping query")
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        print(f"  [SerpApi] Connection error, check your network")
        return None, "network_error"

    if resp.status_code == 429:
        print("  [SerpApi] Rate limit / quota exceeded")
        return None, "ratelimit"
    if resp.status_code == 401:
        print("  [SerpApi] Invalid API key")
        return None, "auth_error"
    if resp.status_code != 200:
        print(f"  [SerpApi] Error {resp.status_code}: {resp.text[:100]}")
        return None, f"http_{resp.status_code}"

    organic = resp.json().get("organic_results", [])
    urls = [r["link"] for r in organic if "link" in r]
    print(f"  [SerpApi] {len(urls)} results for: {query[:70]}")
    return urls, None


def _search_duckduckgo_single(query):
    """DuckDuckGo fallback — free, no API key needed.
    DDG does not support Google-style site: or intext: operators,
    so we skip those queries and only run plain-text searches.
    """
    if "site:" in query or "intext:" in query:
        return [], None  # skip silently, not an error

    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            results = [r["href"] for r in ddgs.text(query, max_results=10)]
        print(f"  [DDG] {len(results)} results for: {query[:70]}")
        return results, None
    except ImportError:
        print("  [DDG] Not installed — run: pip install ddgs")
        return None, "not_installed"
    except Exception as e:
        print(f"  [DDG] Error: {e.__class__.__name__}")
        return None, "error"


def _search_scraper_single(query):
    """Last resort fallback — googlesearch-python scraper."""
    try:
        from googlesearch import search
        results = []
        for url in search(query, num_results=10, lang="en", sleep_interval=2):
            results.append(url)
            time.sleep(0.5)
        return results
    except ImportError:
        print("  [Intel] googlesearch-python not installed")
        return []
    except Exception as e:
        print(f"  [Intel] Scraper error ({e.__class__.__name__})")
        return []


# ── URL collection ───────────────────────────────────────────────────────────

def _collect_urls(indicator, ind_type, gi_cfg):
    # ── FIX: reset per-call so a previous 402 never poisons this request ──
    scale_disabled  = False  # local flag, not a global latch
    scale2_disabled = False

    max_urls   = gi_cfg.get("max_urls", 8)
    skip_set   = set(gi_cfg.get("skip_domains", _SKIP_DOMAINS_DEFAULT))
    scan_limit = gi_cfg.get("scaleserp_scan_limit", _RATE_LIMIT_SCAN)

    use_scale  = bool(SCALESERP_KEY)
    use_scale2 = bool(SCALESERP_KEY2)
    use_serp   = bool(SERPAPI_KEY)

    round1, round2, round3 = _build_queries(indicator, ind_type)

    urls           = []
    seen           = set()
    used_scale     = False
    used_scale2    = False
    used_serp      = False
    used_ddg       = False
    used_scraper   = False
    scale_failed   = False
    scale2_failed  = False
    serp_failed    = False
    ddg_failed     = False
    scale_scan_hits = 0  # per-scan ScaleSerp call counter

    def _add_url(url):
        if len(urls) >= max_urls:
            return
        if url in seen:
            return
        if _should_skip(url, skip_set):
            return
        seen.add(url)
        urls.append(url)

    def _run_query(query):
        nonlocal used_scale, used_scale2, used_serp, used_ddg, used_scraper
        nonlocal scale_failed, scale2_failed, serp_failed, ddg_failed
        nonlocal scale_scan_hits

        if len(urls) >= max_urls:
            return

        # 1. ScaleSerp — primary
        if use_scale and not scale_failed:
            # Per-scan hard cap
            if scale_scan_hits >= scan_limit:
                print(f"  [Intel] ScaleSerp scan limit ({scan_limit}) reached — using DDG for remaining queries")
            else:
                result, err = _search_scaleserp_single(query, SCALESERP_KEY, "ScaleSerp")
                if err in ("out_of_credits", "auth_error", "no_api_key", "ratelimit", "rate_limited"):
                    scale_failed = True
                    print(f"  [Intel] ScaleSerp failed ({err}) — trying fallback key")
                elif err == "timeout":
                    pass
                elif result is not None:
                    scale_scan_hits += 1
                    used_scale = True
                    for u in result:
                        _add_url(u)
                    return

        # 2. ScaleSerp Key2 — fallback key
        if use_scale2 and not scale2_failed and SCALESERP_KEY2 != SCALESERP_KEY:
            if scale_scan_hits >= scan_limit:
                print(f"  [Intel] ScaleSerp2 scan limit ({scan_limit}) reached — using DDG")
            else:
                result, err = _search_scaleserp_single(query, SCALESERP_KEY2, "ScaleSerp2")
                if err in ("out_of_credits", "auth_error", "no_api_key", "ratelimit", "rate_limited"):
                    scale2_failed = True
                    print(f"  [Intel] ScaleSerp2 failed ({err}) — switching to SerpApi")
                elif err == "timeout":
                    pass
                elif result is not None:
                    scale_scan_hits += 1
                    used_scale2 = True
                    for u in result:
                        _add_url(u)
                    return

        # 3. SerpApi
        if use_serp and not serp_failed:
            result, err = _search_serpapi_single(query, SERPAPI_KEY)
            if err in ("auth_error", "no_api_key", "ratelimit"):
                serp_failed = True
                print(f"  [Intel] SerpApi failed ({err}) — switching to DDG")
            elif err == "timeout":
                pass
            elif result is not None:
                used_serp = True
                for u in result:
                    _add_url(u)
                return

        # 4. DuckDuckGo — free fallback
        if not ddg_failed:
            result, err = _search_duckduckgo_single(query)
            if err in ("not_installed", "error"):
                ddg_failed = True
                print("  [Intel] DDG failed — falling back to scraper")
            elif result:
                used_ddg = True
                for u in result:
                    _add_url(u)
                return

        # 5. Scraper — last resort
        time.sleep(2)
        result = _search_scraper_single(query)
        if result:
            used_scraper = True
            for u in result:
                _add_url(u)

    # Run round 1 — trusted sites
    for q in round1:
        _run_query(q)
        if len(urls) >= max_urls:
            break

    # Run round 2 — broader IOC dorks if not enough results
    if len(urls) < 3:
        for q in round2:
            _run_query(q)
            if len(urls) >= max_urls:
                break

    # Run round 3 — pure generic search if still not enough
    if len(urls) < 2:
        for q in round3:
            _run_query(q)
            if len(urls) >= max_urls:
                break

    methods = []
    if used_scale:   methods.append("ScaleSerp")
    if used_scale2:  methods.append("ScaleSerp2")
    if used_serp:    methods.append("SerpApi")
    if used_ddg:     methods.append("DDG")
    if used_scraper: methods.append("scraper")
    method = "+".join(methods) if methods else "none"

    return urls, method


# ── Page fetching ────────────────────────────────────────────────────────────

def _fetch_page(url):
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ThreatIntelBot/1.0)"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        return resp.text
    except Exception:
        return None


def _is_private_ip(ip):
    """Check if an IP is private or invalid"""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b, c, d = [int(p) for p in parts]
    except ValueError:
        return True
    if any(p < 0 or p > 255 for p in [a, b, c, d]):
        return True
    return (a == 10 or
            (a == 192 and b == 168) or
            (a == 172 and 16 <= b <= 31) or
            a == 127)


# ── Signal extraction ────────────────────────────────────────────────────────

def _extract_signals(text, indicator, ind_type=None):
    lower     = text.lower()
    ind_lower = indicator.lower()

    malware = set()
    for kw in MALWARE_KEYWORDS:
        if kw in lower:
            malware.add(kw.title() if " " not in kw else kw)

    apt_actors = set()
    for actor in APT_ACTORS:
        if actor in lower:
            apt_actors.add(actor.title() if " " in actor else actor.upper())

    attck = set(_ATTCK_RE.findall(text))
    cves  = set(_CVE_RE.findall(text))

    severity_hits = {}
    for kw, weight in SEVERITY_KEYWORDS.items():
        if kw in lower:
            severity_hits[kw] = weight

    co_ips, seen_ips = [], set()
    for ip in _IP_RE.findall(text):
        if ip == indicator or _is_private_ip(ip) or ip in seen_ips:
            continue
        seen_ips.add(ip)
        co_ips.append(ip)

    co_domains, seen_domains = [], set()
    for d in _DOMAIN_RE.findall(text):
        dl = d.lower()
        if dl == ind_lower or dl in seen_domains:
            continue
        if any(dl == bd or dl.endswith("." + bd) for bd in _BENIGN_DOMAINS):
            continue
        seen_domains.add(dl)
        co_domains.append(d)

    co_hashes, seen_hashes = [], set()
    for h in _SHA256_RE.findall(text) + _MD5_RE.findall(text):
        hl = h.lower()
        if hl == ind_lower or hl in seen_hashes:
            continue
        seen_hashes.add(hl)
        co_hashes.append(h)

    return malware, apt_actors, attck, cves, severity_hits, co_ips[:10], co_domains[:10], co_hashes[:10]


def _get_url_tier(url, gi_cfg):
    domain    = _get_domain(url)
    tier1_set = set(gi_cfg.get("trusted_sources", {}).get("tier1", list(_TIER1_DOMAINS)))
    tier2_set = set(gi_cfg.get("trusted_sources", {}).get("tier2", list(_TIER2_DOMAINS)))
    for t1 in tier1_set:
        if domain == t1 or domain.endswith("." + t1):
            return 1
    for t2 in tier2_set:
        if domain == t2 or domain.endswith("." + t2):
            return 2
    return 3


# ── Main entry point ─────────────────────────────────────────────────────────

def query_google_intel(indicator, ind_type, api_key=None, config=None):
    cached = cache_get(indicator, "google_intel")
    if cached is not None:
        return cached

    gi_cfg  = _get_gi_config(config)
    enabled = gi_cfg.get("enabled", True)
    if not enabled:
        return None

    urls, search_method = _collect_urls(indicator, ind_type, gi_cfg)

    if not urls:
        print("  [Intel] All search methods failed — skipping")
        return {
            "score": 0, "verdict": "clean", "breakdown": [],
            "urls_fetched": [], "malware_families": [], "attack_ids": [],
            "co_iocs": {"ips": [], "domains": [], "hashes": []},
            "source_tiers": {}, "search_method": search_method,
        }

    all_malware      = set()
    all_apt_actors   = set()
    all_attck        = set()
    all_cves         = set()
    all_severity     = {}
    all_co_ips       = []
    all_co_doms      = []
    all_co_hashes    = []
    seen_ips         = set()
    seen_doms        = set()
    seen_hashes      = set()
    source_tiers     = {}

    for url in urls:
        source_tiers[url] = _get_url_tier(url, gi_cfg)
        text = _fetch_page(url)
        if not text:
            continue
        m, apt, a, cves, sev, ips, doms, hashes = _extract_signals(text, indicator, ind_type)
        all_malware.update(m)
        all_apt_actors.update(apt)
        all_attck.update(a)
        all_cves.update(cves)
        for kw, w in sev.items():
            if kw not in all_severity:
                all_severity[kw] = w
        for ip in ips:
            if ip not in seen_ips and len(all_co_ips) < 10:
                seen_ips.add(ip); all_co_ips.append(ip)
        for d in doms:
            if d.lower() not in seen_doms and len(all_co_doms) < 10:
                seen_doms.add(d.lower()); all_co_doms.append(d)
        for h in hashes:
            if h.lower() not in seen_hashes and len(all_co_hashes) < 10:
                seen_hashes.add(h.lower()); all_co_hashes.append(h)

    malware_families = sorted(all_malware)
    apt_actors       = sorted(all_apt_actors)
    attack_ids       = sorted(all_attck)
    cve_ids          = sorted(all_cves)
    co_iocs = {"ips": all_co_ips, "domains": all_co_doms, "hashes": all_co_hashes}

    scoring = gi_cfg.get("scoring", {})

    n_mal = len(malware_families)
    if n_mal >= 4:   malware_score = scoring.get("malware_four_plus", 4)
    elif n_mal >= 2: malware_score = scoring.get("malware_two_three", 3)
    elif n_mal == 1: malware_score = scoring.get("malware_one", 2)
    else:            malware_score = 0
    malware_score = min(malware_score, scoring.get("malware_cap", 4))

    n_atk = len(attack_ids)
    if n_atk >= 4:   attck_score = scoring.get("attck_four_plus", 3)
    elif n_atk >= 2: attck_score = scoring.get("attck_two_three", 2)
    elif n_atk == 1: attck_score = scoring.get("attck_one", 1)
    else:            attck_score = 0
    attck_score = min(attck_score, scoring.get("attck_cap", 3))

    n_apt = len(apt_actors)
    if n_apt >= 2:   apt_score = 4
    elif n_apt == 1: apt_score = 3
    else:            apt_score = 0
    apt_score = min(apt_score, 4)

    n_cve = len(cve_ids)
    if n_cve >= 3:   cve_score = 2
    elif n_cve >= 1: cve_score = 1
    else:            cve_score = 0
    cve_score = min(cve_score, 2)

    severity_score = min(sum(all_severity.values()), 3)

    tier1_count = sum(1 for t in source_tiers.values() if t == 1)
    tier2_count = sum(1 for t in source_tiers.values() if t == 2)
    has_signals = bool(malware_families or attack_ids or apt_actors or cve_ids)
    if tier1_count >= 2 and has_signals:   tier_bonus = 2
    elif tier1_count >= 1 and has_signals: tier_bonus = 1
    else:                                   tier_bonus = 0

    cap   = gi_cfg.get("cap", 10)
    score = min(
        malware_score + attck_score + apt_score + cve_score + severity_score + tier_bonus,
        cap
    )
    verdict = _gi_verdict(score)

    breakdown = []
    breakdown.append(f"Sources fetched: {len(urls)} ({tier1_count} tier-1, {tier2_count} tier-2)")

    if malware_families:
        breakdown.append(f"Malware families: {', '.join(malware_families)} → +{malware_score}")
    else:
        breakdown.append("Malware families: none → +0")

    if apt_actors:
        breakdown.append(f"APT actors: {', '.join(apt_actors)} → +{apt_score}")
    else:
        breakdown.append("APT actors: none → +0")

    if attack_ids:
        breakdown.append(f"ATT&CK techniques: {', '.join(attack_ids)} → +{attck_score}")
    else:
        breakdown.append("ATT&CK techniques: none → +0")

    if cve_ids:
        breakdown.append(f"CVEs found: {', '.join(list(cve_ids)[:5])} → +{cve_score}")
    else:
        breakdown.append("CVEs found: none → +0")

    if all_severity:
        sev_keys = ', '.join(list(all_severity.keys())[:3])
        breakdown.append(f"Severity signals: {sev_keys} → +{severity_score}")
    else:
        breakdown.append("Severity signals: none → +0")

    if tier_bonus > 0:
        breakdown.append(f"Tier-1 source bonus → +{tier_bonus}")

    ioc_parts = []
    if all_co_ips:    ioc_parts.append(f"{len(all_co_ips)} IP{'s' if len(all_co_ips) != 1 else ''}")
    if all_co_doms:   ioc_parts.append(f"{len(all_co_doms)} domain{'s' if len(all_co_doms) != 1 else ''}")
    if all_co_hashes: ioc_parts.append(f"{len(all_co_hashes)} hash{'es' if len(all_co_hashes) != 1 else ''}")
    if ioc_parts:
        breakdown.append(f"Co-mentioned IOCs: {', '.join(ioc_parts)} → sent to pivot scan")
    else:
        breakdown.append("Co-mentioned IOCs: none → sent to pivot scan")

    if "ScaleSerp" in search_method:
        breakdown.append("Search method: ScaleSerp (Google dorks)")
    elif "SerpApi" in search_method:
        breakdown.append("Search method: SerpApi (Google dorks)")
    elif "DDG" in search_method:
        breakdown.append("Search method: DuckDuckGo (free fallback)")
    elif "scraper" in search_method:
        breakdown.append("Search method: Google scraper fallback")
    else:
        breakdown.append("Search method: none")

    result = {
        "score":            score,
        "verdict":          verdict,
        "breakdown":        breakdown,
        "urls_fetched":     urls,
        "malware_families": malware_families,
        "apt_actors":       apt_actors,
        "attack_ids":       attack_ids,
        "cve_ids":          cve_ids,
        "severity_hits":    list(all_severity.keys()),
        "co_iocs":          co_iocs,
        "source_tiers":     source_tiers,
        "search_method":    search_method,
    }

    cache_set(indicator, "google_intel", result)
    return result


def _gi_verdict(score):
    if score <= 0:   return "clean"
    elif score <= 2: return "suspicious"
    elif score <= 5: return "low_risk"
    elif score <= 8: return "medium_risk"
    else:            return "high"