import datetime
import ipaddress
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
from urllib.parse import urlparse

import cache
from cache import LOCAL_USER_ID
from output import get_last_result
from .scoring import VERDICT_DISPLAY, resolve_vendor

_pivot_log_lock = threading.Lock()

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
    IPs are excluded from the primary candidate pool, but are used as a
    fallback to fill out to MAX_PIVOTS if hash/domain/url candidates fall short.
    """
    hashes  = []
    ips     = []
    domains = []
    urls    = []
    seen         = set()
    sources_map  = {}  # ioc -> list of source names
    relation_map = {}  # ioc -> list of relation labels
    orig_norm = original_indicator.strip().lower()

    def _add(ioc, bucket, source, relation=None):
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
            if relation and relation not in relation_map.get(ioc, []):
                relation_map.setdefault(ioc, []).append(relation)
            return
        seen.add(ioc)
        sources_map[ioc] = [source]
        if relation:
            relation_map[ioc] = [relation]
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
            _add(item.get("id"), "hash", "VirusTotal", relation="communicated with")
        for item in rels.get("downloaded_files") or []:
            if item.get("malicious", 0) > 0:
                continue
            _add(item.get("id"), "hash", "VirusTotal", relation="downloaded by")
        for item in rels.get("resolutions") or []:
            _add(item.get("hostname"), "domain", "VirusTotal", relation="resolved to")
            _add(item.get("ip"), "ip", "VirusTotal", relation="resolved from")
        for item in rels.get("contacted_domains") or []:
            _add(item.get("id"), "domain", "VirusTotal", relation="contacted domain")
        for item in rels.get("contacted_urls") or []:
            _add(item.get("id"), "url", "VirusTotal", relation="contacted URL")

    # ── OTX passive DNS ─────────────────────────────────────────────────────
    # hostnames always; addresses are IPs so _add() will reject them automatically
    if otx:
        for r in otx.get("passive_dns") or []:
            _add(r.get("hostname"), "domain", "OTX", relation="passive DNS: resolved to")
            _add(r.get("address"), "ip", "OTX", relation="passive DNS: resolved from")

    # ── Google Intel ────────────────────────────────────────────────────────
    if google_intel:
        co = google_intel.get("co_iocs") or {}
        for d in co.get("domains") or []:
            _add(d, "domain", "Google Intel", relation="co-mentioned in report")
        for h in co.get("hashes") or []:
            _add(h, "hash", "Google Intel", relation="co-mentioned in report")
        for ip in co.get("ips") or []:
            _add(ip, "ip", "Google Intel", relation="co-mentioned in report")

    # ── ThreatFox ───────────────────────────────────────────────────────────
    if threatfox:
        for ioc in threatfox.get("iocs") or []:
            val = ioc.get("ioc")
            typ = ioc.get("ioc_type")
            if not val:
                continue
            if typ == "sha256_hash":
                _add(val, "hash", "ThreatFox", relation="same threat cluster")
            elif typ == "domain":
                _add(val, "domain", "ThreatFox", relation="same threat cluster")
            elif typ == "url":
                _add(val, "url", "ThreatFox", relation="same threat cluster")

    # ── URLhaus ─────────────────────────────────────────────────────────────
    if urlhaus:
        for u in urlhaus.get("urls") or []:
            host = _extract_host(u.get("url") or "")
            if host:
                _add(host, "domain", "URLhaus", relation="hosted malicious URL")

    # ── URLscan ─────────────────────────────────────────────────────────────
    # domains[] observed during the scan of the original indicator
    if urlscan:
        for d in urlscan.get("domains") or []:
            _add(d, "domain", "URLscan", relation="observed on page")
        ip = urlscan.get("ip")
        if ip:
            _add(ip, "ip", "URLscan", relation="resolved IP")

    # ── Censys ──────────────────────────────────────────────────────────────
    if censys:
        for h in censys.get("hostnames") or []:
            _add(h, "domain", "Censys", relation="associated hostname")
        for d in censys.get("dns_names") or []:
            _add(d, "domain", "Censys", relation="associated hostname")

    # ── Shodan ──────────────────────────────────────────────────────────────
    if shodan:
        for h in shodan.get("hostnames") or []:
            _add(h, "domain", "Shodan", relation="associated hostname")
        for d in shodan.get("domains") or []:
            _add(d, "domain", "Shodan", relation="associated hostname")

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

    all_candidates = hashes + domains + urls  # IPs excluded from the primary pool
    all_candidates.sort(key=_ioc_priority, reverse=True)
    pivot_iocs = all_candidates[:MAX_PIVOTS]

    if len(pivot_iocs) < MAX_PIVOTS:
        # Fall back to IPs to make up the shortfall so exactly MAX_PIVOTS
        # get scanned whenever enough candidates exist across all buckets.
        ips.sort(key=_ioc_priority, reverse=True)
        needed = MAX_PIVOTS - len(pivot_iocs)
        pivot_iocs.extend(ips[:needed])

    return pivot_iocs, sources_map, relation_map


def _get_domain_network_info(domain):
    """Resolve a domain to its current IP via VT's own DNS records, then
    get that IP's country/ASN/detection stats. Avoids WHOIS entirely —
    uses only VT lookups (likely a cache hit for the domain itself, since
    it's probably already been fetched earlier in the same scan)."""
    from .vt import vt_check
    vt_domain = vt_check(domain, "domain", skip_rescan=True)
    if not vt_domain:
        return {}

    info = {
        "registrar":        vt_domain.get("registrar"),
        "creation_date":    vt_domain.get("creation_date"),
        "expiration_date":  vt_domain.get("expiration_date"),
        "last_update_date": vt_domain.get("last_update_date"),
        "domain_vt_tags":   vt_domain.get("tags", []),
        "domain_last_scan": vt_domain.get("last_scan_date"),
    }

    resolved_ip = None
    for rec in vt_domain.get("dns_records", []):
        if rec.startswith("A:"):
            try:
                resolved_ip = rec.split(":", 1)[1].split("(")[0].strip()
            except Exception:
                pass
            break

    if not resolved_ip:
        return info

    info["resolved_ip"] = resolved_ip

    vt_ip = vt_check(resolved_ip, "ip", skip_rescan=True)
    if vt_ip:
        info["country"] = vt_ip.get("country")
        info["asn"] = vt_ip.get("asn")
        info["resolved_ip_malicious"] = vt_ip.get("malicious", 0)
        info["resolved_ip_suspicious"] = vt_ip.get("suspicious", 0)
        info["resolved_ip_tags"] = vt_ip.get("tags", [])

    return info


def _get_ip_network_info(ip):
    """Country/ASN/detection stats for an IP, via VT (likely a cache hit if
    this IP was already looked up earlier in the same scan)."""
    from .vt import vt_check
    vt_r = vt_check(ip, "ip", skip_rescan=True)
    if not vt_r:
        return {}
    return {
        "country": vt_r.get("country"),
        "asn": vt_r.get("asn"),
        "malicious": vt_r.get("malicious", 0),
        "suspicious": vt_r.get("suspicious", 0),
        "vt_tags": vt_r.get("tags", []),
    }


def _get_hash_network_info(file_hash):
    """Detection stats for a file hash, via VT (likely a cache hit if this
    hash was already looked up earlier in the same scan) plus Hybrid
    Analysis sandbox details."""
    from .vt import vt_check
    from .hybrid import hybrid_check
    vt_r     = vt_check(file_hash, "hash", skip_rescan=True)
    hybrid_r = hybrid_check(file_hash, "hash")

    details = {}
    if vt_r:
        details.update({
            "malicious": vt_r.get("malicious", 0),
            "suspicious": vt_r.get("suspicious", 0),
            "harmless": vt_r.get("harmless", 0),
            "vt_tags": vt_r.get("tags", []),
        })
    if hybrid_r:
        details["hybrid_threat_score"] = hybrid_r.get("threat_score")
        details["hybrid_verdict"]      = hybrid_r.get("verdict")
        details["hybrid_family"]       = hybrid_r.get("family")
        details["hybrid_first_seen"]   = hybrid_r.get("first_seen")
        details["hybrid_size"]         = hybrid_r.get("size")
        details["hybrid_av_detect"]    = hybrid_r.get("av_detect")
    return details


def _is_subdomain(domain):
    # Heuristic: 2 labels (example.com) = domain, 3+ = subdomain.
    # Known limitation: misclassifies multi-part TLDs (example.co.uk
    # would incorrectly count as subdomain). Acceptable tradeoff for
    # now — flag this if it causes visible misclassification.
    return domain.strip('.').count('.') >= 2


def select_and_detail_extras(sources_map, pivot_iocs, config, relation_map=None):
    """Bucket remaining (non-deep-scanned) candidates by type, cap each
    bucket at 3, and fetch a lightweight detail lookup for each."""
    relation_map = relation_map or {}

    scanned_set = set(pivot_iocs)
    buckets = {"ip": [], "domain": [], "subdomain": [], "hash": []}

    for ioc in sources_map:
        if ioc in scanned_set:
            continue
        t = _detect_pivot_type(ioc)
        if t == "domain":
            t = "subdomain" if _is_subdomain(ioc) else "domain"
        if t in buckets:
            buckets[t].append(ioc)

    # Reuse the same priority sort already used in extract_pivot_iocs
    _SOURCE_PRIORITY = {"ThreatFox": 3, "VirusTotal": 2, "OTX": 1}
    def _priority(ioc):
        srcs = sources_map.get(ioc, [])
        return max((_SOURCE_PRIORITY.get(s, 0) for s in srcs), default=0)

    extras = {}
    for bucket_type, candidates in buckets.items():
        candidates.sort(key=_priority, reverse=True)
        for ioc in candidates[:3]:
            details = {}
            try:
                if bucket_type == "ip":
                    details = _get_ip_network_info(ioc)
                elif bucket_type == "hash":
                    details = _get_hash_network_info(ioc)
                elif bucket_type in ("domain", "subdomain"):
                    details = _get_domain_network_info(ioc)
            except Exception as e:
                details = {"error": str(e)}
            extras[ioc] = {
                "type": bucket_type,
                "sources": sources_map.get(ioc, []),
                "relation": relation_map.get(ioc, []),
                "details": details,
            }
    return extras


def _scan_single_pivot(ioc, config, original_norm, user_id=LOCAL_USER_ID):
    from .vt import vt_check
    from .otx import otx_check
    from .scoring import combined_verdict

    if ioc.strip().lower() == original_norm:
        return (ioc, None, 0, None)

    ioc_type = _detect_pivot_type(ioc)
    if ioc_type is None:
        return (ioc, None, 0, None)

    # A full scan is a strict superset of a pivot scan — if this IOC already
    # has one on record (scoped to the same user running the parent scan),
    # reuse its verdict/score instead of running the lighter pivot check.
    # No freshness check: whatever's on record wins regardless of age.
    existing = get_last_result(ioc, user_id=user_id)
    if existing and existing.get("verdict") is not None:
        return (ioc, existing["verdict"], existing.get("score") or 0, existing)

    vt_r = otx_r = None

    if ioc_type == "hash":
        vt_r  = vt_check(ioc, "hash", skip_rescan=True, light=True)
        otx_r = otx_check(ioc, "hash", skip_passive_dns=True)

    elif ioc_type == "domain":
        vt_r  = vt_check(ioc, "domain", skip_rescan=True, light=True)
        otx_r = otx_check(ioc, "domain", skip_passive_dns=True)

    elif ioc_type == "url":
        host  = _extract_host(ioc)
        vt_r  = vt_check(host, "domain", skip_rescan=True, light=True) if host else None
        otx_r = otx_check(host, "domain", skip_passive_dns=True) if host else None

    elif ioc_type == "ip":
        vt_r  = vt_check(ioc, "ip", skip_rescan=True, light=True)
        otx_r = otx_check(ioc, "ip", skip_passive_dns=True)

    result = combined_verdict(
        vt=vt_r, otx=otx_r, abuse=None, shodan=None,
        greynoise=None, hybrid=None,
        threatfox=None, urlhaus=None, urlscan=None,
        config=config,
        pivot_result=None,
    )

    return (ioc, result["final_verdict"], result.get("score", 0), None)


def _print_source_summaries(ind_type, vt, otx, abuse, shodan, whois, censys, greynoise, urlhaus, threatfox, urlscan, hybrid, spamhaus_drop, config):
    if vt:
        print(f"\n  [VirusTotal]")
        print(f"  Malicious  : {vt['malicious']}")
        print(f"  Suspicious : {vt['suspicious']}")
        print(f"  Harmless   : {vt['harmless']}")
        print(f"  Undetected : {vt['undetected']}")

        if ind_type == "ip":
            print(f"  Country    : {vt['country']}")
            print(f"  ASN        : {vt['asn']}")

        if len(vt["tags"]) > 0:
            print(f"  Tags       : {', '.join(vt['tags'][:5])}")

        if vt["last_scan_date"]:
            scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
            print(f"  Last Scan  : {scan_date.strftime('%Y-%m-%d %H:%M')}")

        if vt["dns_records"]:
            print(f"\n  Last DNS Records:")
            for rec in vt["dns_records"]:
                print(f"    {rec}")

        if len(vt["malicious_vendors"]) > 0:
            print(f"\n  Top Malicious Detections:")

            def _vendor_tier(v):
                canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                if canonical in config["tier1"]:
                    return 1
                elif canonical in config["tier2"]:
                    return 2
                return 3

            for v in sorted(vt["malicious_vendors"], key=_vendor_tier):
                canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                if canonical in config["tier1"]:
                    tier_label = "(Tier 1)"
                elif canonical in config["tier2"]:
                    tier_label = "(Tier 2)"
                else:
                    tier_label = "(Tier 3)"
                print(f"    {v['vendor']:<20} {v['name']:<30} {tier_label}")

        comments  = vt.get("comments", [])
        relations = vt.get("relations", {})
        has_relations = any(items for items in relations.values()) if relations else False

        if not comments and not has_relations:
            print(f"\n  No community activity or relations found.")
        else:
            print(f"\n  ── Community comments ──")
            if comments:
                for c in comments[:5]:
                    snippet = c["text"][:120]
                    print(f"  [{c['date']}] @{c['author']} — {snippet} [+{c['votes_positive']}/-{c['votes_negative']}]")
                if len(comments) > 5:
                    print(f"  ({len(comments) - 5} more not shown)")
            else:
                print("  (none)")

            print(f"\n  ── Relations ──")
            if has_relations:
                for rel_name, items in relations.items():
                    if not items:
                        continue
                    label = rel_name.replace("_", " ").title()
                    if rel_name == "resolutions":
                        ids = [(i.get("hostname") or i.get("ip") or "") for i in items]
                        print(f"  {label}: {', '.join(ids)}")
                    else:
                        ids = [i.get("id", "") for i in items]
                        mal = sum(i.get("malicious", 0) for i in items)
                        print(f"  {label}: {', '.join(ids)}  (malicious: {mal})")
            else:
                print("  (none)")

    if otx:
        print(f"\n  [AlienVault OTX]")

        if ind_type == "ip":
            print(f"  Country    : {otx['country']}")
            print(f"  ASN        : {otx['asn']}")
            print(f"  Reputation : {otx['reputation']}")

        ind_desc  = otx.get("indicator_description")
        ind_title = otx.get("indicator_title")
        rep_score = otx.get("reputation_threat_score")
        rep_type  = otx.get("reputation_threat_type")

        if ind_desc or rep_score is not None:
            print(f"\n  ── OTX Indicator Summary ──")
            if ind_title:
                print(f"  Title: {ind_title}")
            if ind_desc:
                print(f"  Description: {ind_desc[:300]}")
            if ZeroDivisionError is not None:
                print(f"  OTX Threat Score: {rep_score}/100  ({rep_type})")

        print(f"  Pulses     : {otx['pulse_count']} threat reports")

        pulse_details = otx.get("pulse_details", [])

        for i, p in enumerate(pulse_details, 1):
            print(f"\n  Pulse #{i}: {p['name']}")

            if p["adversary"] != "":
                print(f"    Threat Actor  : {p['adversary']}")

            if len(p["tags"]) > 0:
                print(f"    Tags          : {', '.join(p['tags'][:5])}")

            if p["ref"] != "":
                print(f"    Reference     : {p['ref']}")

        pdns = otx.get("passive_dns", [])
        if pdns:
            print(f"\n  Passive DNS ({len(pdns)} record(s), showing first 5):")
            for r in pdns[:5]:
                first = r["first"][:10] if r["first"] else "?"
                last  = r["last"][:10]  if r["last"]  else "?"
                print(f"    [{r['record_type']:<5}] {r['hostname'] or r['address']:<40}  first: {first}  last: {last}")

        print(f"\n  ── Pulse descriptions ──")
        pulses_detail = otx.get("pulses_detail", [])
        useful_pulses = [
            p for p in pulses_detail
            if p.get("description") or p.get("malware_families") or p.get("attack_ids")
        ]
        if not useful_pulses:
            print(f"  No pulse descriptions or ATT&CK mappings available.")
        else:
            for p in useful_pulses[:3]:
                modified   = p.get("modified") or ""
                name       = p.get("name", "Unnamed")
                author     = p.get("author_name") or ""
                desc_full  = (p.get("description") or "").strip()
                desc       = desc_full[:200]
                families   = p.get("malware_families") or []
                attack_ids = p.get("attack_ids") or []
                refs       = p.get("references") or []

                author_str = f" (by @{author})" if author else ""
                print(f"  [{modified}] {name}{author_str}")
                if desc:
                    ellipsis = "..." if len(desc_full) > 200 else ""
                    print(f"    Description: {desc}{ellipsis}")
                if families:
                    print(f"    Malware: {', '.join(families)}")
                if attack_ids:
                    print(f"    ATT&CK: {', '.join(attack_ids)}")
                if refs:
                    print(f"    References: {refs[0]}")
                print(f"  ---")

            remaining = len(useful_pulses) - 3
            if remaining > 0:
                print(f"  {remaining} more pulses not shown")

    if abuse:
        print(f"\n  [AbuseIPDB]")
        print(f"  Abuse Score    : {abuse['abuse_score']}%")
        print(f"  Total Reports  : {abuse['total_reports']}  ({abuse['distinct_users']} distinct users)")
        print(f"  ISP            : {abuse['isp']}")
        print(f"  Tor Exit Node  : {'Yes' if abuse['is_tor'] else 'No'}")
        if abuse['last_reported']:
            print(f"  Last Reported  : {abuse['last_reported'][:10]}")

        if abuse['top_categories']:
            print(f"\n  Top Attack Types:")
            for name, count in abuse['top_categories'][:5]:
                print(f"    {name:<25} {count} report(s)")

        if abuse['reports']:
            print(f"\n  Recent Reports:")
            _firewall_words  = {'ttl', 'ufw', 'tos', 'packet', 'port'}
            _threat_keywords = {'malware', 'phishing', 'ransomware', 'trojan', 'botnet', 'actor'}
            for r in abuse['reports']:
                date = r['reported_at'][:10] if r['reported_at'] else '?'
                cats = ', '.join(r['categories']) if r['categories'] else 'None'
                print(f"    [{date}] {cats}")
                comment = (r['comment'] or '').strip()
                if comment:
                    lower = comment.lower()
                    is_firewall = any(w in lower for w in _firewall_words)
                    has_domain  = '.' in comment and not comment.replace('.', '').replace(':', '').replace('/', '').replace(' ', '').isdigit()
                    has_threat  = any(k in lower for k in _threat_keywords)
                    if not is_firewall and (has_domain or has_threat):
                        print(f"             {comment[:80]}")

    if shodan:
        print(f"\n  [Shodan]")
        print(f"  Org          : {shodan['org']}")
        print(f"  ISP          : {shodan['isp']}")
        print(f"  ASN          : {shodan['asn']}")
        print(f"  OS           : {shodan['os'] or 'Unknown'}")
        print(f"  Last scan    : {shodan['last_update'][:10] if shodan['last_update'] else 'Unknown'}")

        if shodan['hostnames']:
            print(f"  Hostnames    : {', '.join(shodan['hostnames'][:3])}")
        else:
            print(f"  Hostnames    : None")

        if shodan['ports']:
            print(f"  Open ports   : {', '.join(str(p) for p in shodan['ports'])}")

        if shodan['tags']:
            print(f"  Tags         : {', '.join(shodan['tags'])}")

        if shodan['vulns']:
            print(f"\n  CVEs ({len(shodan['vulns'])} found):")
            for cve in shodan['vulns'][:5]:
                print(f"    {cve}")

        if shodan['services']:
            print(f"\n  Services:")
            for svc in shodan['services']:
                product   = svc['product'] or 'Unknown'
                version   = svc['version'] or ''
                label     = f"{product} {version}".strip()
                port      = svc['port']      if svc['port']      is not None else '?'
                transport = svc['transport'] if svc['transport'] is not None else '?'
                print(f"    Port {port:<6} {transport:<4} {label}")

    if censys:
        print(f"\n  [Censys]")
        print(f"  Org          : {censys.get('org') or 'Unknown'}")
        print(f"  ASN          : {censys.get('asn') or 'Unknown'}")
        print(f"  Country      : {censys.get('country') or 'Unknown'}")
        print(f"  Last scan    : {censys['last_update'][:10] if censys.get('last_update') else 'Unknown'}")

        if censys.get('ports'):
            print(f"  Open ports   : {', '.join(str(p) for p in censys['ports'])}")

        if censys.get('labels'):
            print(f"  Labels       : {', '.join(censys['labels'])}")

        if censys.get('vulns'):
            print(f"\n  CVEs ({len(censys['vulns'])} found):")
            for cve in censys['vulns'][:5]:
                print(f"    {cve}")

        if censys.get('services'):
            print(f"\n  Services:")
            for svc in censys['services']:
                product   = svc.get('product') or 'Unknown'
                version   = svc.get('version') or ''
                label     = f"{product} {version}".strip()
                port      = svc.get('port')      if svc.get('port')      is not None else '?'
                transport = svc.get('transport') if svc.get('transport') is not None else '?'
                print(f"    Port {port:<6} {transport:<4} {label}")

    if whois:
        print(f"\n  [WHOIS]")
        print(f"  Domain         : {whois.get('domain') or 'N/A'}")
        print(f"  Registrar      : {whois.get('registrar') or 'N/A'}")
        creation = whois.get('creation_date')
        print(f"  Creation date  : {creation[:10] if creation else 'N/A'}")
        age_days = whois.get('domain_age_days')
        print(f"  Domain age     : {age_days} days" if age_days is not None else "  Domain age     : unknown")
        expiry = whois.get('expiration_date')
        print(f"  Expiration     : {expiry[:10] if expiry else 'N/A'}")
        print(f"  Privacy masked : {'Yes' if whois.get('privacy_masked') else 'No'}")
        print(f"  Country        : {whois.get('country') or 'N/A'}")
        ns = whois.get('name_servers', [])
        print(f"  Name servers   : {', '.join(ns[:3]) if ns else 'N/A'}")

    if greynoise:
        print(f"\n  [GreyNoise]")
        print(f"  Classification : {greynoise.get('classification', 'unknown')}")
        print(f"  Noise          : {'Yes' if greynoise.get('noise') else 'No'}")
        if greynoise.get('actor'):
            print(f"  Actor          : {greynoise['actor']}")
        if greynoise.get('cve'):
            print(f"  CVEs           : {greynoise['cve']}")

    if urlhaus:
        print(f"\n  [URLhaus]")
        print(f"  URL count      : {urlhaus.get('url_count', 0)}")
        if urlhaus.get('threat'):
            print(f"  Threat type    : {urlhaus['threat']}")
        if urlhaus.get('first_seen'):
            print(f"  First seen     : {urlhaus['first_seen'][:10]}")
        urls = urlhaus.get('urls', [])
        if urls:
            print(f"\n  Recent URLs:")
            for u in urls[:3]:
                print(f"    [{u.get('url_status', '?')}] {u.get('url', '')[:70]}")

    if threatfox:
        print(f"\n  [ThreatFox]")
        print(f"  IOC count      : {threatfox.get('ioc_count', 0)}")
        if threatfox.get('threat_type'):
            print(f"  Threat type    : {threatfox['threat_type']}")
        if threatfox.get('malware'):
            print(f"  Malware family : {threatfox['malware']}")
        if threatfox.get('confidence_level') is not None:
            print(f"  Confidence     : {threatfox['confidence_level']}%")
        if threatfox.get('first_seen'):
            print(f"  First seen     : {threatfox['first_seen'][:10]}")
        iocs = threatfox.get('iocs', [])
        if iocs:
            print(f"\n  IOCs:")
            for ioc in iocs[:3]:
                print(f"    [{ioc.get('ioc_type', '?')}] {ioc.get('ioc', '')[:70]}")

    if urlscan:
        print(f"\n  [URLScan]")
        print(f"  Malicious      : {'Yes' if urlscan.get('malicious') else 'No'}")
        if urlscan.get('categories'):
            print(f"  Categories     : {', '.join(urlscan['categories'][:5])}")
        if urlscan.get('page_title'):
            print(f"  Page title     : {urlscan['page_title'][:60]}")
        if urlscan.get('server'):
            print(f"  Server         : {urlscan['server']}")
        if urlscan.get("domains"):
            print(f"  Hosted domains : {', '.join(urlscan['domains'][:5])}")
        if urlscan.get('ip'):
            print(f"  Resolved IP    : {urlscan['ip']}")

    if hybrid:
        print(f"\n  [Hybrid Analysis]")
        print(f"  Threat score   : {hybrid.get('threat_score', 'N/A')}")
        print(f"  Verdict        : {hybrid.get('verdict', 'unknown')}")
        if hybrid.get('type'):
            print(f"  File type      : {hybrid['type']}")
        if hybrid.get('family'):
            print(f"  Families       : {', '.join(hybrid['family'])}")

    if spamhaus_drop is not None:
        print(f"\n  [Spamhaus DROP]")
        if spamhaus_drop.get('listed'):
            print(f"  Listed         : Yes")
            print(f"  ASN name       : {spamhaus_drop.get('asname') or 'N/A'}")
            print(f"  Country        : {spamhaus_drop.get('cc') or 'N/A'}")
            print(f"  Domain         : {spamhaus_drop.get('domain') or 'N/A'}")
            print(f"  RIR            : {spamhaus_drop.get('rir') or 'N/A'}")
        else:
            print(f"  Listed         : No")


def generate_pivot_detail_log(ioc, pivot_result, config):
    """Full per-source investigation report for one pivot IOC, as text."""
    from .vt import vt_check
    from .otx import otx_check
    from .hybrid import hybrid_check
    from .threatfox import threatfox_check
    from .urlhaus import urlhaus_check
    from .urlscan import urlscan_check
    from .scoring import combined_verdict

    captured   = StringIO()
    old_stdout = sys.stdout
    old_silent = cache.SILENT
    with _pivot_log_lock:
        sys.stdout   = captured
        cache.SILENT = True
        try:
            print(f"  Verdict  : {VERDICT_DISPLAY.get(pivot_result['pivot_verdicts'].get(ioc))}")
            print(f"  Score    : {pivot_result['pivot_scores'].get(ioc, '?')}")
            print(f"  Found via: {', '.join(pivot_result['sources_map'].get(ioc, []))}")

            ioc_type = _detect_pivot_type(ioc)

            vt_r = otx_r = hybrid_r = threatfox_r = urlhaus_r = urlscan_r = abuse_r = greynoise_r = shodan_r = None
            whois_r = None
            if ioc_type == "hash":
                vt_r        = vt_check(ioc, "hash")
                hybrid_r    = hybrid_check(ioc, "hash")
                threatfox_r = threatfox_check(ioc, "hash")
                otx_r       = otx_check(ioc, "hash")
            elif ioc_type == "domain":
                vt_r        = vt_check(ioc, "domain")
                otx_r       = otx_check(ioc, "domain")
                threatfox_r = threatfox_check(ioc, "domain")
                urlhaus_r   = urlhaus_check(ioc, "domain")
                urlscan_r   = urlscan_check(ioc, "domain")
            elif ioc_type == "url":
                host        = _extract_host(ioc)
                vt_r        = vt_check(host, "domain") if host else None
                threatfox_r = threatfox_check(ioc, "url")
                urlhaus_r   = urlhaus_check(host, "domain") if host else None
                urlscan_r   = urlscan_check(ioc, "domain")
            elif ioc_type == "ip":
                from .abuseipdb import abuseipdb_check
                from .greynoise import greynoise_check
                from .shodan import shodan_check as shodan_check_fn
                vt_r        = vt_check(ioc, "ip")
                otx_r       = otx_check(ioc, "ip")
                abuse_r     = abuseipdb_check(ioc, "ip")
                greynoise_r = greynoise_check(ioc, "ip")
                shodan_r    = shodan_check_fn(ioc, "ip")

            result = combined_verdict(
                vt=vt_r, otx=otx_r, abuse=abuse_r, shodan=shodan_r,
                greynoise=greynoise_r, hybrid=hybrid_r,
                threatfox=threatfox_r, urlhaus=urlhaus_r, urlscan=urlscan_r,
                config=config,
                pivot_result=None,
            )

            _print_source_summaries(ioc_type, vt_r, otx_r, abuse_r, shodan_r, whois_r, None, greynoise_r, urlhaus_r, threatfox_r, urlscan_r, hybrid_r, None, config)

            print(f"\n  Per Source:")
            for name, s in result["per_source"].items():
                print(f"    {name:<12}: {s['findings_label']}  (evidence: {s['evidence_count']})")

            print(f"\n  Score Breakdown:")
            for line in result["breakdown"]:
                print(f"    {line}")

            print(f"\n  Active sources : {', '.join(result['active_sources'])}")
            print(f"  No data from   : {', '.join(result['inactive_sources'])}")
        finally:
            sys.stdout   = old_stdout
            cache.SILENT = old_silent
    return captured.getvalue()


def _full_scan_summary_log(ioc, entry):
    """Text block shown in place of a pivot-scan log for an IOC that already
    had a full scan on record — makes clear this is a reused full-scan
    result, not output from a pivot scan that just ran."""
    lines = [
        f"  [Full scan on record] Skipped pivot scan — a full scan for this IOC",
        f"  already exists and supersedes it. Showing that stored result:",
        f"",
        f"  Scanned at : {entry.get('timestamp', 'unknown')}",
        f"  Verdict    : {VERDICT_DISPLAY.get(entry.get('verdict'), entry.get('verdict'))}",
        f"  Score      : {entry.get('score', '?')}",
    ]
    if entry.get("recommendation"):
        lines.append(f"  Recommendation: {entry['recommendation']}")
    return "\n".join(lines)


def run_pivot_scan(pivot_iocs, sources_map, config, original_indicator, relation_map=None, user_id=LOCAL_USER_ID):
    """Scan each pivot IOC one level deep using type-appropriate sources.

    Uses the existing cache — already-scanned IOCs cost nothing. Any pivot
    IOC that already has a full scan on record (for user_id) reuses that
    result instead — a full scan is a strict superset of what a pivot scan
    would produce, so re-running the lighter check would be redundant.
    Passes pivot_result=None to combined_verdict to prevent recursion.
    """
    relation_map = relation_map or {}
    _EMPTY = {
        "pivot_iocs":        [],
        "malicious_pivots":  [],
        "suspicious_pivots": [],
        "pivot_verdicts":    {},
        "pivot_scores":      {},
        "breakdown":         [],
        "pivot_detail":      [],
        "sources_map":       {},
        "pivot_attempted":   [],
        "pivot_log_by_ioc":  {},
        "pivot_log":         "",
        "pivot_extras":      {},
        "pivot_whois":       {},
        "relation_map":      relation_map,
        "pivot_from_full_scan": {},
    }

    if not pivot_iocs:
        return _EMPTY

    original_norm = original_indicator.strip().lower()

    captured   = StringIO()
    old_stdout = sys.stdout
    with _pivot_log_lock:
        sys.stdout = captured
        try:
            print(f"\n  [Pivot] Scanning {len(pivot_iocs)} pivot IOC(s)...")

            malicious_pivots  = []
            suspicious_pivots = []
            pivot_verdicts    = {}
            scores_map        = {}
            full_scan_entries = {}  # ioc -> full history entry, for IOCs that skipped the pivot scan

            _MALICIOUS = {"medium_risk", "high"}
            _SUSPICIOUS = {"suspicious", "low_risk"}

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(_scan_single_pivot, ioc, config, original_norm, user_id): ioc
                    for ioc in pivot_iocs
                }
                try:
                    completed = as_completed(futures, timeout=45)
                    for future in completed:
                        try:
                            ioc, verdict, score, full_entry = future.result(timeout=10)
                        except Exception as e:
                            ioc = futures[future]
                            print(f"  [Pivot] {ioc[:55]} → {type(e).__name__}: {e} — skipping")
                            continue
                        if verdict is None:
                            continue
                        pivot_verdicts[ioc] = verdict
                        scores_map[ioc] = score
                        if full_entry is not None:
                            full_scan_entries[ioc] = full_entry
                        if verdict in _MALICIOUS:
                            malicious_pivots.append(ioc)
                        elif verdict in _SUSPICIOUS:
                            suspicious_pivots.append(ioc)
                except TimeoutError:
                    print(f"  [Pivot] Overall 45s timeout reached with {len(pivot_verdicts)}/{len(pivot_iocs)} "
                          f"pivot(s) resolved so far — remaining pivot(s) abandoned")
                    for future, ioc in futures.items():
                        if not future.done():
                            print(f"  [Pivot] {ioc[:55]} → skipped (still in flight at timeout)")
                            future.cancel()

            summary_lines = []
            if malicious_pivots:
                summary_lines.append(f"Malicious pivots: {len(malicious_pivots)}")
            if suspicious_pivots:
                summary_lines.append(f"Suspicious pivots: {len(suspicious_pivots)}")
            if not malicious_pivots and not suspicious_pivots:
                summary_lines.append(f"Pivot IOCs {len(pivot_verdicts)} scanned → +0 (all clean or no data)")

            detail_lines = []
            if pivot_verdicts:
                detail_lines.append(f"Pivot scan: {len(pivot_verdicts)} IOC(s) checked")
                for ioc, v in pivot_verdicts.items():
                    src_label = ", ".join(sources_map.get(ioc, ["unknown"]))
                    verdict_display = VERDICT_DISPLAY.get(v, v)
                    pivot_score = scores_map.get(ioc, 0)
                    if ioc in full_scan_entries:
                        origin = f"full scan on record ({(full_scan_entries[ioc].get('timestamp') or '')[:10]})"
                    else:
                        origin = f"via {src_label}"
                    detail_lines.append(f"  {ioc:<64} → {verdict_display} (score: {pivot_score})  ({origin})")
        finally:
            sys.stdout = old_stdout

    full_log = captured.getvalue()

    result_so_far = {
        "pivot_verdicts": pivot_verdicts,
        "pivot_scores":   {ioc: scores_map.get(ioc, 0) for ioc in pivot_verdicts},
        "sources_map":    sources_map,
    }

    pivot_log_by_ioc = {}
    pivot_whois      = {}
    for ioc in pivot_iocs:
        if ioc in full_scan_entries:
            pivot_log_by_ioc[ioc] = _full_scan_summary_log(ioc, full_scan_entries[ioc])
            continue
        if ioc in pivot_verdicts:
            pivot_log_by_ioc[ioc] = generate_pivot_detail_log(ioc, result_so_far, config)
            ioc_type = _detect_pivot_type(ioc)
            try:
                if ioc_type == "domain":
                    pivot_whois[ioc] = _get_domain_network_info(ioc)
                elif ioc_type == "url":
                    host = _extract_host(ioc)
                    if host:
                        pivot_whois[ioc] = _get_domain_network_info(host)
                elif ioc_type == "ip":
                    pivot_whois[ioc] = _get_ip_network_info(ioc)
                elif ioc_type == "hash":
                    pivot_whois[ioc] = _get_hash_network_info(ioc)
            except Exception as e:
                pivot_whois[ioc] = {"error": str(e)}
            continue
        needles = [ioc]
        if _detect_pivot_type(ioc) == "url":
            host = _extract_host(ioc)
            if host:
                needles.append(host)
        matching = [ln for ln in full_log.splitlines() if any(n in ln for n in needles)]
        pivot_log_by_ioc[ioc] = "\n".join(matching)

    return {
        "pivot_iocs":        list(pivot_verdicts.keys()),
        "malicious_pivots":  malicious_pivots,
        "suspicious_pivots": suspicious_pivots,
        "pivot_verdicts":    pivot_verdicts,
        "pivot_scores":      {ioc: scores_map.get(ioc, 0) for ioc in pivot_verdicts},
        "breakdown":         summary_lines,
        "pivot_detail":      detail_lines,
        "sources_map":       sources_map,
        "pivot_attempted":   pivot_iocs,
        "pivot_log_by_ioc":  pivot_log_by_ioc,
        "pivot_log":         full_log,
        "pivot_extras":      select_and_detail_extras(sources_map, pivot_iocs, config, relation_map),
        "pivot_whois":       pivot_whois,
        "relation_map":      relation_map,
        "pivot_from_full_scan": {ioc: entry.get("timestamp") for ioc, entry in full_scan_entries.items()},
    }