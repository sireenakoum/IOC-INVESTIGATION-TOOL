import re
import time
import requests
import trafilatura
from urllib.parse import urlparse
from dotenv import load_dotenv

from cache import cache_get, cache_set, LOCAL_USER_ID
from .enrichment import get_known_entities

# Load environment variables
load_dotenv()

MALWARE_KEYWORDS_SEED = {
    "mirai", "hajime", "mozi", "emotet", "qakbot", "cobalt strike", "metasploit",
    "asyncrat", "njrat", "redline", "agenttesla", "formbook", "lokibot", "raccoon",
    "vidar", "lumma", "xmrig", "pdfsider", "darkcomet", "netwire", "remcos",
    "blackmatter", "lockbit", "revil", "conti", "blackcat", "cl0p", "nokoyawa",
    "lazarus", "apt28", "apt29", "apt41", "sandworm", "fancy bear", "cozy bear",
    "ta505", "fin7", "unc2452",
}

APT_ACTORS_SEED = {
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

# Used only in _extract_signals() to keep well-known infra/platform domains out of
# co-mentioned IOC lists (e.g. a "github.com" link in an article isn't a pivot-worthy
# co-domain). Not consulted for fetch filtering — see _SKIP_DOMAINS_DEFAULT for that.
_BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "amazonaws.com", "cloudflare.com",
    "apple.com", "facebook.com", "twitter.com", "linkedin.com", "youtube.com",
    "wikipedia.org", "w3.org", "mozilla.org", "python.org",
}

# Used in _should_skip() to exclude domains from being fetched at all — search
# engine chrome and reference/encyclopedic sites that never carry indicator-specific
# threat intel, so they shouldn't burn a fetch or land in "Sources Fetched".
_SKIP_DOMAINS_DEFAULT = [
    "google.com", "bing.com", "youtube.com", "twitter.com", "reddit.com",
    "linkedin.com", "facebook.com", "pastebin.com", "githubusercontent.com",
    "wikipedia.org", "wiktionary.org", "britannica.com", "investopedia.com",
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
    Build plain-text search queries for threat intel hunting via DuckDuckGo.
    DDG doesn't support Google-style site:/intext: dork operators, so every
    query here is plain keyword text (trusted-source prioritization instead
    happens post-fetch, see _get_url_tier). Round 1 always runs; round 2 is
    a top-up that only runs if round 1 came up short.
    """
    round1 = [
        f'"{indicator}"',
        f'"{indicator}" malware threat intelligence report',
        f'"{indicator}" indicators of compromise',
    ]

    if ind_type == "ip":
        round1.append(f'"{indicator}" malicious IP threat actor attack infrastructure')
    elif ind_type == "domain":
        round1.append(f'"{indicator}" phishing malware distribution dropper')
    elif ind_type == "hash":
        round1.append(f'"{indicator}" malware sample sandbox analysis')

    round2 = [
        f'"{indicator}" command and control botnet C2 server',
        f'"{indicator}" securelist unit42 talos crowdstrike mandiant threat report',
    ]

    return round1, round2


# ── Search backend ───────────────────────────────────────────────────────────

def _search_duckduckgo_single(query):
    """DuckDuckGo — free, no API key needed.

    ddgs fans out across several backend search engines and only raises once
    every one of them has failed/returned nothing, so any exception here means
    the whole search came up dry — not just one engine. RatelimitException/
    TimeoutException are called out explicitly (rate-limiting or blocking is
    the prime suspect for this ever firing); the generic branch still prints
    str(e), since that's where ddgs' aggregated failure reason (e.g. which
    engine failed and why) actually lives — swallowing it down to just the
    exception class name was hiding the useful part.
    """
    try:
        from ddgs import DDGS
        from ddgs.exceptions import RatelimitException, TimeoutException
        with DDGS() as ddgs:
            results = [r["href"] for r in ddgs.text(query, max_results=10)]
        print(f"  [DDG] {len(results)} results for: {query[:70]}")
        if not results:
            print(f"  [DDG] Zero results (search completed, nothing matched) for: {query[:70]}")
        return results, None
    except ImportError:
        print("  [DDG] Not installed — run: pip install ddgs")
        return None, "not_installed"
    except RatelimitException as e:
        print(f"  [DDG] RATE LIMITED for query '{query[:70]}': {e}")
        return None, "rate_limited"
    except TimeoutException as e:
        print(f"  [DDG] TIMED OUT for query '{query[:70]}': {e}")
        return None, "timeout"
    except Exception as e:
        print(f"  [DDG] Error for query '{query[:70]}': {e.__class__.__name__}: {e}")
        return None, "error"


# ── URL collection ───────────────────────────────────────────────────────────

def _collect_urls(indicator, ind_type, gi_cfg):
    max_urls = gi_cfg.get("max_urls", 8)
    skip_set = set(gi_cfg.get("skip_domains", _SKIP_DOMAINS_DEFAULT))

    round1, round2 = _build_queries(indicator, ind_type)

    urls           = []
    seen           = set()
    used_ddg       = False
    ddg_failed     = False
    ddg_fail_reason = None

    def _add_url(url):
        if url in seen:
            return

        if _should_skip(url, skip_set):
            return
        seen.add(url)
        urls.append(url)

    def _run_query(query):
        nonlocal used_ddg, ddg_failed, ddg_fail_reason

        if ddg_failed:
            return

        result, err = _search_duckduckgo_single(query)
        if err in ("not_installed", "error", "rate_limited", "timeout"):
            ddg_failed = True
            ddg_fail_reason = err
            print(f"  [Intel] DDG failed ({err}) — aborting remaining queries for indicator {indicator!r}")
        elif result:
            used_ddg = True
            for u in result:
                _add_url(u)

    # Run round 1 — plain-text search
    for q in round1:
        _run_query(q)

    # Run round 2 — broader plain-text search, top-up only if still not enough
    if len(urls) < 2:
        for q in round2:
            _run_query(q)

    # Prioritize trusted sources when trimming to the configured max, rather
    # than whichever query happened to fill the quota first.
    urls.sort(key=lambda u: _get_url_tier(u, gi_cfg))
    urls = urls[:max_urls]

    method = "DDG" if used_ddg else "none"
    return urls, method, ddg_fail_reason


# ── Page fetching ────────────────────────────────────────────────────────────

def _extract_main_content(html, url=None):
    """Strip nav/sidebar/ads/related-content, keep just the article body.
    Falls back to the raw HTML if extraction fails or returns something
    too small to be real content — some sources (feeds, minimal pages)
    aren't structured as articles at all, and losing all signal from
    those would be worse than the noise this is meant to fix."""
    try:
        extracted = trafilatura.extract(
            html, url=url, include_comments=False, include_tables=True
        )
        if extracted and len(extracted.strip()) > 50:
            return extracted
    except Exception:
        pass
    print(f"  [Intel] Content extraction fell back to raw HTML for {url}")
    return html


def _fetch_page(url):
    """Returns (text, error). error is None on success, otherwise a short
    reason tag ("blocked", "http_error", "timeout", "error") so callers can
    tell a fetch failure apart from a page that simply loaded but didn't
    mention the indicator."""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ThreatIntelBot/1.0)"},
            timeout=10,
        )
        if resp.status_code != 200:
            if resp.status_code in (403, 429):
                print(f"  [Intel] Fetch BLOCKED/rate-limited for {url} — HTTP {resp.status_code}")
                return None, "blocked"
            print(f"  [Intel] Fetch failed for {url} — HTTP {resp.status_code}")
            return None, "http_error"
        return _extract_main_content(resp.text, url=url), None
    except requests.exceptions.Timeout:
        print(f"  [Intel] Fetch timed out for {url}")
        return None, "timeout"
    except requests.exceptions.RequestException as e:
        print(f"  [Intel] Fetch error for {url}: {e.__class__.__name__}: {e}")
        return None, "error"
    except Exception as e:
        print(f"  [Intel] Unexpected fetch error for {url}: {e.__class__.__name__}: {e}")
        return None, "error"


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


# ── Enriched entity sets ─────────────────────────────────────────────────────
# Seed keyword sets stay hardcoded as a permanent baseline (always active, even
# on a fresh DB). They're unioned with entities learned live from OTX/ThreatFox
# and bulk-imported from MITRE ATT&CK (see sources/enrichment.py). The union is
# cached briefly since this runs once per fetched page per scan.

_entity_cache = {"malware": set(), "apt_actor": set(), "loaded_at": 0,
                 "malware_pattern": None, "apt_actor_pattern": None}
_ENTITY_CACHE_TTL = 300  # 5 minutes — avoids a DB query on every fetched page


def _build_pattern(terms):
    """One compiled alternation pattern for a whole term set, with word
    boundaries — much faster than looping and searching per-keyword
    when the set has thousands of entries. Longer terms sorted first
    so multi-word phrases (e.g. 'cobalt strike') match before any
    shorter substring overlap could occur."""
    if not terms:
        return None
    escaped = sorted((re.escape(t) for t in terms), key=len, reverse=True)
    return re.compile(r'\b(?:' + '|'.join(escaped) + r')\b', re.IGNORECASE)


def _get_enriched_set(entity_type, seed_set):
    now = time.time()
    if now - _entity_cache["loaded_at"] > _ENTITY_CACHE_TTL:
        _entity_cache["malware"] = get_known_entities("malware")
        _entity_cache["apt_actor"] = get_known_entities("apt_actor")
        merged_malware = MALWARE_KEYWORDS_SEED | _entity_cache["malware"]
        merged_apt = APT_ACTORS_SEED | _entity_cache["apt_actor"]
        _entity_cache["malware_pattern"] = _build_pattern(merged_malware)
        _entity_cache["apt_actor_pattern"] = _build_pattern(merged_apt)
        _entity_cache["loaded_at"] = now
    return seed_set | _entity_cache[entity_type]


def _get_enriched_pattern(entity_type, seed_set):
    _get_enriched_set(entity_type, seed_set)  # ensures cache is fresh
    key = "malware_pattern" if entity_type == "malware" else "apt_actor_pattern"
    return _entity_cache[key]


# ── Signal extraction ────────────────────────────────────────────────────────

def _extract_signals(text, indicator, ind_type=None):
    lower     = text.lower()
    ind_lower = indicator.lower()

    malware = set()
    malware_pattern = _get_enriched_pattern("malware", MALWARE_KEYWORDS_SEED)
    if malware_pattern:
        for match in malware_pattern.finditer(text):
            matched_text = match.group(0)
            malware.add(matched_text.title() if " " not in matched_text else matched_text)

    apt_actors = set()
    apt_pattern = _get_enriched_pattern("apt_actor", APT_ACTORS_SEED)
    if apt_pattern:
        for match in apt_pattern.finditer(text):
            matched_text = match.group(0)
            apt_actors.add(matched_text.title() if " " in matched_text else matched_text.upper())

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

def query_google_intel(indicator, ind_type, api_key=None, config=None, user_id=LOCAL_USER_ID):
    cached = cache_get(indicator, "google_intel", user_id)
    if cached is not None:
        return cached

    gi_cfg  = _get_gi_config(config)
    enabled = gi_cfg.get("enabled", True)
    if not enabled:
        return None

    urls, search_method, ddg_fail_reason = _collect_urls(indicator, ind_type, gi_cfg)

    if not urls:
        if ddg_fail_reason:
            print(f"  [Intel] Search failed ({ddg_fail_reason}) for indicator {indicator!r} — "
                  f"returning empty result, NOT a genuine no-results")
            search_status, search_error = "blocked", ddg_fail_reason
        else:
            print(f"  [Intel] Search completed with zero URLs for indicator {indicator!r} — genuine no-results")
            search_status, search_error = "no_results", None
        _empty_ev = {"malware": {}, "apt_actors": {}, "attck": {}, "cves": {}, "severity": {}, "co_iocs": {}}
        return {
            "score": 0, "verdict": "clean", "breakdown": [],
            "urls_fetched": [], "malware_families": [], "attack_ids": [],
            "co_iocs": {"ips": [], "domains": [], "hashes": []},
            "source_tiers": {}, "search_method": search_method,
            "search_status": search_status, "search_error": search_error,
            "evidence_sources": _empty_ev,
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
    malware_sources  = {}
    apt_sources      = {}
    attck_sources    = {}
    cve_sources      = {}
    severity_sources = {}
    co_ioc_sources   = {}

    fetch_failures = 0
    for url in urls:
        text, _fetch_err = _fetch_page(url)
        if not text:
            fetch_failures += 1
            continue
        # Plain substring check — won't catch defanged mentions (e.g. "46[.]60[.]55[.]125"),
        # a known limitation. Trade-off accepted: avoids counting irrelevant pages as
        # sources at the cost of occasionally missing a legitimately defanged mention.
        if indicator.lower() not in text.lower():
            print(f"  [Intel] Skipping {url} — indicator not found in fetched content")
            continue
        source_tiers[url] = _get_url_tier(url, gi_cfg)
        m, apt, a, cves, sev, ips, doms, hashes = _extract_signals(text, indicator, ind_type)
        for item in m:    malware_sources.setdefault(item, []).append(url)
        for item in apt:  apt_sources.setdefault(item, []).append(url)
        for item in a:    attck_sources.setdefault(item, []).append(url)
        for item in cves: cve_sources.setdefault(item, []).append(url)
        for kw in sev:    severity_sources.setdefault(kw, []).append(url)
        all_malware.update(m)
        all_apt_actors.update(apt)
        all_attck.update(a)
        all_cves.update(cves)
        for kw, w in sev.items():
            if kw not in all_severity:
                all_severity[kw] = w
        for ip in ips:
            co_ioc_sources.setdefault(ip, []).append(url)
            if ip not in seen_ips and len(all_co_ips) < 10:
                seen_ips.add(ip); all_co_ips.append(ip)
        for d in doms:
            co_ioc_sources.setdefault(d.lower(), []).append(url)
            if d.lower() not in seen_doms and len(all_co_doms) < 10:
                seen_doms.add(d.lower()); all_co_doms.append(d)
        for h in hashes:
            co_ioc_sources.setdefault(h.lower(), []).append(url)
            if h.lower() not in seen_hashes and len(all_co_hashes) < 10:
                seen_hashes.add(h.lower()); all_co_hashes.append(h)

    if urls and fetch_failures == len(urls):
        print(f"  [Intel] ALL {len(urls)} page fetches failed for indicator {indicator!r} — "
              f"likely blocked/rate-limited, NOT a genuine no-results")
    elif fetch_failures:
        print(f"  [Intel] {fetch_failures}/{len(urls)} page fetches failed for indicator {indicator!r}")

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

    # search_status reflects pipeline health, not how much intel was found —
    # "no_results" means the search/fetch pipeline ran cleanly and genuinely
    # found nothing; "blocked" means fetches failed hard enough that an empty
    # result can't be trusted as a real negative.
    all_fetches_failed = bool(urls) and fetch_failures == len(urls)
    if all_fetches_failed:
        search_status, search_error = "blocked", "all_fetches_failed"
    elif has_signals:
        search_status, search_error = "success", None
    else:
        search_status, search_error = "no_results", None

    breakdown = []
    breakdown.append(f"Sources fetched: {len(urls)} ({tier1_count} tier-1, {tier2_count} tier-2)")
    if fetch_failures:
        breakdown.append(f"Fetch failures: {fetch_failures}/{len(urls)}")

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

    if search_method == "DDG":
        breakdown.append("Search method: DuckDuckGo")
    else:
        breakdown.append("Search method: none")

    if search_status == "blocked":
        breakdown.append(f"Search status: BLOCKED ({search_error}) — result may not reflect a real no-match")

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
        "search_status":    search_status,
        "search_error":     search_error,
        "evidence_sources": {
            "malware":    malware_sources,
            "apt_actors": apt_sources,
            "attck":      attck_sources,
            "cves":       cve_sources,
            "severity":   severity_sources,
            "co_iocs":    co_ioc_sources,
        },
    }

    cache_set(indicator, "google_intel", result, user_id)
    return result


def _gi_verdict(score):
    if score <= 0:   return "clean"
    elif score <= 2: return "suspicious"
    elif score <= 5: return "low_risk"
    elif score <= 8: return "medium_risk"
    else:            return "high"