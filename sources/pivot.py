import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .scoring import VERDICT_DISPLAY

_BENIGN_IP_PREFIXES = (
    "173.194.",   # Google
    "142.250.",   # Google
    "216.58.",    # Google
    "8.8.",       # Google DNS
    "1.1.",       # Cloudflare DNS
    "104.16.",    # Cloudflare
    "13.107.",    # Microsoft
    "52.96.",     # Microsoft
)


def _detect_pivot_type(ioc):
    """Classify a pivot IOC as hash, url, ip, or domain. Returns None if unrecognisable."""
    s = ioc.strip()
    if len(s) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in s):
        return "hash"
    if s.lower().startswith(("http://", "https://")):
        return "url"
    try:
        addr = ipaddress.ip_address(s)
        if addr.version == 6:
            return None  # skip IPv6 — not supported by most sources
        return "ip"
    except ValueError:
        pass
    if "." in s:
        return "domain"
    return None



def _extract_host(url_str):
    """Return the bare hostname from a URL string, without scheme or port."""
    try:
        netloc = urlparse(url_str).netloc
        if not netloc:
            netloc = urlparse("http://" + url_str).netloc
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return netloc.lower()
    except Exception:
        return ""


def extract_pivot_iocs(sources_results, original_indicator):
    """Collect pivot IOC candidates from all primary scan results.

    sources_results keys: "vt", "otx", "google_intel", "threatfox",
                          "urlhaus", "urlscan", "censys", "shodan"

    Returns up to 10 IOCs ordered hashes → domains → urls, deduplicated.
    IPs are never included as pivot targets.
    """
    hashes  = []
    ips     = []
    domains = []
    urls    = []
    seen        = set()
    sources_map = {}  # ioc -> list of source names
    orig_norm = original_indicator.strip().lower()

    def _add(ioc, bucket, source):
        ioc = (ioc or "").strip()
        if not ioc:
            return
        if ioc.lower() == orig_norm:
            return
        try:
            addr = ipaddress.ip_address(ioc)
            if addr.version == 6:
                return  # skip IPv6
        except ValueError:
            pass  # not an IP, continue
        if any(ioc.startswith(p) for p in _BENIGN_IP_PREFIXES):
            return  # skip known benign infrastructure
        if ioc in seen:
            if source not in sources_map[ioc]:
                sources_map[ioc].append(source)
            return
        seen.add(ioc)
        sources_map[ioc] = [source]
        if bucket == "hash":
            hashes.append(ioc)
        elif bucket == "ip":
            ips.append(ioc)
        elif bucket == "domain":
            domains.append(ioc)
        else:
            urls.append(ioc)

    vt           = sources_results.get("vt")
    otx          = sources_results.get("otx")
    google_intel = sources_results.get("google_intel")
    threatfox    = sources_results.get("threatfox")
    urlhaus      = sources_results.get("urlhaus")
    urlscan      = sources_results.get("urlscan")
    censys       = sources_results.get("censys")
    shodan       = sources_results.get("shodan")

    # ── VT relations ────────────────────────────────────────────────────────
    if vt:
        rels = vt.get("relations") or {}
        # Files VT itself already flagged malicious in relations data are already
        # credited via score_vt's "communicating/downloaded files" bonus — pivoting
        # on them just re-confirms the same VT signal and double-counts it.
        for item in rels.get("communicating_files") or []:
            if item.get("malicious", 0) > 0:
                continue
            _add(item.get("id"), "hash", "VirusTotal")
        for item in rels.get("downloaded_files") or []:
            if item.get("malicious", 0) > 0:
                continue
            _add(item.get("id"), "hash", "VirusTotal")
        for item in rels.get("resolutions") or []:
            _add(item.get("hostname"), "domain", "VirusTotal")
            _add(item.get("ip"), "ip", "VirusTotal")
        for item in rels.get("contacted_domains") or []:
            _add(item.get("id"), "domain", "VirusTotal")
        for item in rels.get("contacted_urls") or []:
            _add(item.get("id"), "url", "VirusTotal")

    # ── OTX passive DNS ─────────────────────────────────────────────────────
    # hostnames always; addresses are IPs so _add() will reject them automatically
    if otx:
        for r in otx.get("passive_dns") or []:
            _add(r.get("hostname"), "domain", "OTX")
            _add(r.get("address"), "ip", "OTX")

    # ── Google Intel ────────────────────────────────────────────────────────
    if google_intel:
        co = google_intel.get("co_iocs") or {}
        for d in co.get("domains") or []:
            _add(d, "domain", "Google Intel")
        for h in co.get("hashes") or []:
            _add(h, "hash", "Google Intel")
        for ip in co.get("ips") or []:
            _add(ip, "ip", "Google Intel")

    # ── ThreatFox ───────────────────────────────────────────────────────────
    if threatfox:
        for ioc in threatfox.get("iocs") or []:
            val = ioc.get("ioc")
            typ = ioc.get("ioc_type")
            if not val:
                continue
            if typ == "sha256_hash":
                _add(val, "hash", "ThreatFox")
            elif typ == "domain":
                _add(val, "domain", "ThreatFox")
            elif typ == "url":
                _add(val, "url", "ThreatFox")

    # ── URLhaus ─────────────────────────────────────────────────────────────
    if urlhaus:
        for u in urlhaus.get("urls") or []:
            host = _extract_host(u.get("url") or "")
            if host:
                _add(host, "domain", "URLhaus")

    # ── URLscan ─────────────────────────────────────────────────────────────
    # domains[] observed during the scan of the original indicator
    if urlscan:
        for d in urlscan.get("domains") or []:
            _add(d, "domain", "URLscan")
        ip = urlscan.get("ip")
        if ip:
            _add(ip, "ip", "URLscan")

    # ── Censys ──────────────────────────────────────────────────────────────
    if censys:
        for h in censys.get("hostnames") or []:
            _add(h, "domain", "Censys")
        for d in censys.get("dns_names") or []:
            _add(d, "domain", "Censys")

    # ── Shodan ──────────────────────────────────────────────────────────────
    if shodan:
        for h in shodan.get("hostnames") or []:
            _add(h, "domain", "Shodan")
        for d in shodan.get("domains") or []:
            _add(d, "domain", "Shodan")

    MAX_PIVOTS = 3

    # Source priority: higher = more maliciousness signal
    _SOURCE_PRIORITY = {
        "ThreatFox":   3,
        "VirusTotal":  2,
        "OTX":         1,
    }

    def _ioc_priority(ioc):
        srcs = sources_map.get(ioc, [])
        priority = max((_SOURCE_PRIORITY.get(s, 0) for s in srcs), default=0)
        return (priority, len(srcs))

    all_candidates = hashes + domains + urls  # IPs excluded per docstring
    all_candidates.sort(key=_ioc_priority, reverse=True)
    pivot_iocs = all_candidates[:MAX_PIVOTS]
    return pivot_iocs, sources_map


def _scan_single_pivot(ioc, config, original_norm):
    from .vt import vt_check
    from .otx import otx_check
    from .scoring import combined_verdict

    if ioc.strip().lower() == original_norm:
        return (ioc, None,0)

    ioc_type = _detect_pivot_type(ioc)
    if ioc_type is None:
        return (ioc, None,0)

    vt_r = otx_r = None

    if ioc_type == "hash":
        vt_r  = vt_check(ioc, "hash", skip_rescan=True)
        otx_r = otx_check(ioc, "hash", skip_passive_dns=True)

    elif ioc_type == "domain":
        vt_r  = vt_check(ioc, "domain", skip_rescan=True)
        otx_r = otx_check(ioc, "domain", skip_passive_dns=True)

    elif ioc_type == "url":
        host  = _extract_host(ioc)
        vt_r  = vt_check(host, "domain", skip_rescan=True) if host else None
        otx_r = otx_check(host, "domain", skip_passive_dns=True) if host else None

    elif ioc_type == "ip":
        vt_r  = vt_check(ioc, "ip", skip_rescan=True)
        otx_r = otx_check(ioc, "ip", skip_passive_dns=True)

    result = combined_verdict(
        vt=vt_r, otx=otx_r, abuse=None, shodan=None,
        greynoise=None, hybrid=None,
        threatfox=None, urlhaus=None, urlscan=None,
        config=config,
        pivot_result=None,
    )

    return (ioc, result["final_verdict"], result.get("score", 0))


def run_pivot_scan(pivot_iocs, sources_map, config, original_indicator):
    """Scan each pivot IOC one level deep using type-appropriate sources.

    Uses the existing cache — already-scanned IOCs cost nothing.
    Passes pivot_result=None to combined_verdict to prevent recursion.
    """
    _EMPTY = {
        "pivot_iocs":        [],
        "malicious_pivots":  [],
        "suspicious_pivots": [],
        "pivot_verdicts":    {},
        "pivot_scores":      {},
        "breakdown":         [],
        "pivot_detail":      [],
        "sources_map":       {},
    }

    if not pivot_iocs:
        return _EMPTY

    original_norm = original_indicator.strip().lower()
    print(f"\n  [Pivot] Scanning {len(pivot_iocs)} pivot IOC(s)...")

    malicious_pivots  = []
    suspicious_pivots = []
    pivot_verdicts    = {}
    scores_map        = {}

    _MALICIOUS = {"medium_risk", "high"}
    _SUSPICIOUS = {"suspicious", "low_risk"}

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_scan_single_pivot, ioc, config, original_norm): ioc
            for ioc in pivot_iocs
        }
        try:
            completed = as_completed(futures, timeout=45)
            for future in completed:
                try:
                    ioc, verdict, score = future.result(timeout=10)
                except Exception:
                    ioc = futures[future]
                    print(f"  [Pivot] {ioc[:55]} → timed out or errored, skipping")
                    continue
                if verdict is None:
                    continue
                pivot_verdicts[ioc] = verdict
                scores_map[ioc] = score
                if verdict in _MALICIOUS:
                    malicious_pivots.append(ioc)
                elif verdict in _SUSPICIOUS:
                    suspicious_pivots.append(ioc)
        except TimeoutError:
            print(f"  [Pivot] Overall timeout reached — using results collected so far")
            for future, ioc in futures.items():
                if not future.done():
                    print(f"  [Pivot] {ioc[:55]} → skipped (timeout)")
                    future.cancel()

    summary_lines = []
    if malicious_pivots:
        summary_lines.append(f"Malicious pivots: {len(malicious_pivots)}")
    if suspicious_pivots:
        summary_lines.append(f"Suspicious pivots: {len(suspicious_pivots)}")
    if not malicious_pivots and not suspicious_pivots:
        summary_lines.append(f"Pivot IOCs {len(pivot_iocs)} scanned → +0 (all clean or no data)")

    detail_lines = []
    if pivot_verdicts:
        detail_lines.append(f"Pivot scan: {len(pivot_verdicts)} IOC(s) checked")
        for ioc, v in pivot_verdicts.items():
            src_label = ", ".join(sources_map.get(ioc, ["unknown"]))
            verdict_display = VERDICT_DISPLAY.get(v, v)
            pivot_score = scores_map.get(ioc, 0)
            detail_lines.append(f"  {ioc:<64} → {verdict_display} (score: {pivot_score})  (via {src_label})")

    return {
        "pivot_iocs":        list(pivot_verdicts.keys()),
        "malicious_pivots":  malicious_pivots,
        "suspicious_pivots": suspicious_pivots,
        "pivot_verdicts":    pivot_verdicts,
        "pivot_scores":      {ioc: scores_map.get(ioc, 0) for ioc in pivot_verdicts},
        "breakdown":         summary_lines,
        "pivot_detail":      detail_lines,
        "sources_map":       sources_map,
    }