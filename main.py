import datetime

from detect import detect_type
from sources.vt import vt_check
from sources.otx import otx_check
from sources.shodan import shodan_check
from sources.abuseipdb import abuseipdb_check
from sources.whois import whois_check
from sources.censys import censys_check
from sources.greynoise import greynoise_check
from sources.urlhaus import urlhaus_check
from sources.urlscan import urlscan_check
from sources.hybrid import hybrid_check
from sources.scoring import combined_verdict, load_config, resolve_vendor, VERDICT_DISPLAY
from cache import clear_cache, clear_indicator_cache
from output import save_results, print_history, get_history_entry, get_history_count, clear_history, clear_indicator, get_last_result, compare_results


config = load_config("config.json")
VERBOSE = False


def display_report(indicator, ind_type, vt, otx, abuse, shodan=None, whois=None, censys=None,
                   greynoise=None, urlhaus=None, urlscan=None, hybrid=None):

    verdict_result = combined_verdict(vt, otx, abuse, shodan, whois=whois, censys=censys,
                                      greynoise=greynoise, urlhaus=urlhaus,
                                      urlscan=urlscan, hybrid=hybrid, config=config)

    if not VERBOSE:
        print(f"\n{'='*45}")
        print(f"  Threat Report: {indicator}")
        print(f"{'='*45}")

        # VirusTotal summary line
        if vt:
            malicious = vt['malicious']
            harmless  = vt['harmless']
            if malicious == 0:
                tier_summary = "clean"
            else:
                tier1_hits = tier2_hits = 0
                for v in vt.get("malicious_vendors", []):
                    canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                    if canonical in config["tier1"]:
                        tier1_hits += 1
                    elif canonical in config["tier2"]:
                        tier2_hits += 1
                if tier1_hits > 0:
                    tier_summary = "includes Tier 1"
                elif tier2_hits > 0:
                    tier_summary = "includes Tier 2"
                else:
                    tier_summary = "Tier 3 only"
            print(f"\n  [VirusTotal]    {malicious} malicious / {harmless} harmless — {tier_summary}")
        else:
            print(f"\n  [VirusTotal]    no data")

        # OTX summary line
        if otx:
            pulse_count   = otx['pulse_count']
            pulse_details = otx.get("pulse_details", [])
            adversary     = next((p["adversary"] for p in pulse_details if p.get("adversary")), None)
            family        = next((p["families"][0] for p in pulse_details if p.get("families")), None)
            if adversary:
                top_signal = f"APT: {adversary}"
            elif family:
                top_signal = f"family: {family}"
            elif pulse_count > 0:
                top_signal = f"{pulse_count} pulses"
            else:
                top_signal = "no data"
            print(f"  [OTX]           {pulse_count} pulses — {top_signal}")
        else:
            print(f"  [OTX]           no data")

        # AbuseIPDB summary line
        if not abuse or (abuse.get('total_reports', 0) == 0 and
                         abuse.get('distinct_users', 0) == 0 and
                         not abuse.get('is_tor', False)):
            abuse_summary = "no data"
        else:
            abuse_summary = f"{abuse['total_reports']} reports, {abuse['distinct_users']} users"
        print(f"  [AbuseIPDB]     {abuse_summary}")

        # Shodan summary line
        if shodan:
            org = shodan.get('org') or 'Unknown'
            ports     = shodan.get('ports', [])
            ports_str = ', '.join(str(p) for p in ports) if ports else "no suspicious findings"
            print(f"  [Shodan]        {org} — {ports_str}")
        else:
            print(f"  [Shodan]        no data")

        # Censys summary line
        if censys:
            c_org = censys.get('org') or 'Unknown'
            c_cve_count = len(censys.get('vulns', []))
            cve_str = f"{c_cve_count} CVE(s)" if c_cve_count > 0 else "no CVEs"
            print(f"  [Censys]        {c_org} — {cve_str}")
        else:
            print(f"  [Censys]        no data")

        # WHOIS summary line
        if whois:
            age_days  = whois.get('domain_age_days')
            age_str   = f"{age_days} days old" if age_days is not None else "unknown age"
            registrar = (whois.get('registrar') or 'unknown registrar')[:35]
            print(f"  [WHOIS]         {whois.get('domain', indicator)} — {age_str}, {registrar}")
        else:
            print(f"  [WHOIS]         no data")

        if greynoise:
            classification = greynoise.get('classification', 'unknown')
            noise = greynoise.get('noise', False)
            if noise:
                print(f"  [GreyNoise]     🌐 Internet background noise ({classification})")
            else:
                print(f"  [GreyNoise]     {classification}")
        else:
            print(f"  [GreyNoise]     no data")

        if urlhaus:
            url_count = urlhaus.get('url_count', 0)
            threat = urlhaus.get('threat') or 'unknown threat'
            print(f"  [URLhaus]       {url_count} malicious URL(s) — {threat}")
        else:
            print(f"  [URLhaus]       no data")

        if urlscan:
            malicious = urlscan.get('malicious', False)
            flag = '⚠️  malicious' if malicious else 'clean'
            print(f"  [URLScan]       {flag}")
        else:
            print(f"  [URLScan]       no data")

        if hybrid:
            threat_score = hybrid.get('threat_score', 0)
            verdict = hybrid.get('verdict', 'unknown')
            print(f"  [Hybrid]        threat score {threat_score} — {verdict}")
        else:
            print(f"  [Hybrid]        no data")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Triggered by   : {', '.join(verdict_result['triggered_by'])}")
        _whois_ctx = verdict_result.get('whois_context', {})
        if _whois_ctx.get('has_data'):
            print(f"  Supporting     : WHOIS (+{_whois_ctx['score_modifier']} domain context)")
        _corr = verdict_result.get('shodan_censys_corroboration', {})
        _corr_total = _corr.get('total_bonus', 0)
        if _corr_total > 0:
            _parts = []
            if _corr.get('corroborated_ports'):
                _parts.append(f"{len(_corr['corroborated_ports'])} port(s)")
            if _corr.get('corroborated_cves'):
                _parts.append(f"{len(_corr['corroborated_cves'])} CVE(s)")
            if _corr.get('corroborated_products'):
                _parts.append(f"{len(_corr['corroborated_products'])} product(s)")
            if _corr.get('corroborated_banners'):
                _parts.append(f"{len(_corr['corroborated_banners'])} banner(s)")
            if _corr.get('cert_match'):
                _parts.append("TLS cert")
            if _corr.get('service_overlap_bonus', 0) > 0:
                _parts.append(f"service overlap ({_corr.get('service_overlap_pct', 0)}%)")
            if _corr.get('recency_bonus', 0) > 0:
                _parts.append("both recent")
            print(f"  Corroboration  : {', '.join(_parts)} confirmed across Shodan+Censys (+{_corr_total})")
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"{'='*45}\n")

    else:
        # Verbose: full source detail + score breakdown
        print(f"\n{'='*45}")
        print(f"  Threat Report: {indicator}")
        print(f"{'='*45}")

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

        if otx:
            print(f"\n  [AlienVault OTX]")

            if ind_type == "ip":
                print(f"  Country    : {otx['country']}")
                print(f"  ASN        : {otx['asn']}")
                print(f"  Reputation : {otx['reputation']}")

            print(f"  Pulses     : {otx['pulse_count']} threat reports")

            pulse_details = otx.get("pulse_details", [])

            for i, p in enumerate(pulse_details, 1):
                print(f"\n  Pulse #{i}: {p['name']}")

                if p["adversary"] != "":
                    print(f"    Threat Actor  : {p['adversary']}")

                if len(p["families"]) > 0:
                    print(f"    Malware Family: {', '.join(p['families'])}")

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
                    product = svc['product'] or 'Unknown'
                    version = svc['version'] or ''
                    label   = f"{product} {version}".strip()
                    print(f"    Port {svc['port']:<6} {svc['transport']:<4} {label}")

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
                    product = svc.get('product') or 'Unknown'
                    version = svc.get('version') or ''
                    label   = f"{product} {version}".strip()
                    print(f"    Port {svc['port']:<6} {svc['transport']:<4} {label}")

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

        print(f"\n  Per Source:")
        for name, s in verdict_result['per_source'].items():
            print(f"    {name:<12}: {s['verdict_display']}  (evidence: {s['evidence_count']})")

        print(f"\n  Score Breakdown:")
        for line in verdict_result["breakdown"]:
            print(f"    {line}")
        print(f"  {'─'*40}")

        print(f"\n  Contribution   :")
        for name, pct in verdict_result['contribution'].items():
            print(f"    {name:<12}: {pct}")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}  (score: {verdict_result['score']})")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"  Triggered      : {', '.join(verdict_result['triggered_by'])}")
        _whois_ctx = verdict_result.get('whois_context', {})
        if _whois_ctx.get('has_data'):
            print(f"  Supporting     : WHOIS (+{_whois_ctx['score_modifier']} domain context)")
        _corr = verdict_result.get('shodan_censys_corroboration', {})
        _corr_total = _corr.get('total_bonus', 0)
        if _corr_total > 0:
            print(f"\n  [Corroboration] Shodan + Censys (+{_corr_total} total, cap 4)")
            if _corr.get('corroborated_ports'):
                print(f"  Ports    : {', '.join(_corr['corroborated_ports'])} (+{_corr['port_bonus']})")
            if _corr.get('corroborated_cves'):
                print(f"  CVEs     : {', '.join(_corr['corroborated_cves'])} (+{_corr['cve_bonus']})")
            if _corr.get('corroborated_products'):
                print(f"  Products : {', '.join(_corr['corroborated_products'])} (+{_corr['product_bonus']})")
            if _corr.get('corroborated_banners'):
                print(f"  Banners  : {', '.join(_corr['corroborated_banners'])} (+{_corr['banner_bonus']})")
            if _corr.get('cert_match'):
                print(f"  TLS cert : fingerprint match across both sources (+{_corr['cert_bonus']})")
            if _corr.get('service_overlap_bonus', 0) > 0:
                print(f"  Overlap  : {_corr.get('service_overlap_pct', 0)}% non-common port overlap (+{_corr['service_overlap_bonus']})")
            if _corr.get('recency_bonus', 0) > 0:
                print(f"  Recency  : both scanned within 7 days (+{_corr['recency_bonus']})")
        print(f"  Active sources : {', '.join(verdict_result['active_sources'])}")
        if verdict_result['inactive_sources']:
            print(f"  No data from   : {', '.join(verdict_result['inactive_sources'])}")
        print(f"{'='*45}\n")

    return verdict_result


def _print_changes(changes, since_ts):
    if not changes:
        print(f"  ✓  No changes since last scan ({since_ts})\n")
        return
    print(f"\n  ⚠️  Changes since last scan ({since_ts}):")
    if "verdict" in changes:
        old_v = VERDICT_DISPLAY.get(changes["verdict"]["from"], changes["verdict"]["from"] or "no data")
        new_v = VERDICT_DISPLAY.get(changes["verdict"]["to"],   changes["verdict"]["to"]   or "no data")
        print(f"    Verdict  : {old_v} → {new_v}")
    if "score" in changes:
        print(f"    Score    : {changes['score']['from']} → {changes['score']['to']}")
    if "sources" in changes:
        for src, chg in changes["sources"].items():
            old_v = VERDICT_DISPLAY.get(chg["from"], chg["from"] or "no data")
            new_v = VERDICT_DISPLAY.get(chg["to"],   chg["to"]   or "no data")
            print(f"    {src:<12}: {old_v} → {new_v}")
    print()


def check_indicator(indicator, previous=None):

    ind_type = detect_type(indicator)

    if ind_type is None:
        print("Invalid indicator. Enter a valid IPv4, domain, or hash.")
        return

    old_entry = previous if previous is not None else get_last_result(indicator)

    vt     = vt_check(indicator, ind_type)
    otx    = otx_check(indicator, ind_type)
    abuse  = abuseipdb_check(indicator, ind_type)
    shodan = shodan_check(indicator, ind_type)
    whois  = whois_check(indicator, ind_type)
    censys = censys_check(indicator, ind_type)
    greynoise = greynoise_check(indicator, ind_type)
    urlhaus   = urlhaus_check(indicator, ind_type)
    urlscan   = urlscan_check(indicator, ind_type)
    hybrid    = hybrid_check(indicator, ind_type)

    verdict_result = display_report(indicator, ind_type, vt, otx, abuse, shodan, whois, censys,
                                    greynoise=greynoise, urlhaus=urlhaus,
                                    urlscan=urlscan, hybrid=hybrid)
    save_results(indicator, vt, otx, abuse, shodan, verdict_result["final_verdict"], whois,
                 score=verdict_result["score"], per_source=verdict_result["per_source"],
                 censys_result=censys, greynoise_result=greynoise, urlhaus_result=urlhaus,
                 urlscan_result=urlscan, hybrid_result=hybrid)

    if old_entry is not None:
        new_cmp = {
            "verdict":    verdict_result["final_verdict"],
            "score":      verdict_result["score"],
            "per_source": verdict_result["per_source"],
        }
        _print_changes(compare_results(old_entry, new_cmp), old_entry["timestamp"])


# Main loop

print("╔══════════════════════════════════════════════╗")
print("║         IOC Investigation Tool               ║")
print("╠══════════════════════════════════════════════╣")
print("║  Enter an IP, domain, or file hash           ║")
print("║  Type 'help' for available commands          ║")
print("╚══════════════════════════════════════════════╝")

while True:
    indicator = input("\n> ").strip()

    if indicator.lower() in ("exit", "quit", "q"):
        break

    if indicator.lower() == "help":
        print(f"""
  Commands
  ────────────────────────────────────────
  history              List past lookups
  history <n>          Replay lookup #n
  history clear        Delete all history

  verbose              Show full breakdown
  brief                Show summary only

  reset cache          Clear cached API results
  rescan <indicator>   Delete one IOC from history and cache, then rescan it
  exit                 Quit
  ────────────────────────────────────────
        """)
        continue

    if indicator.lower() == "verbose":
        VERBOSE = True
        print("  Verbose mode on — full breakdown will be shown.")
        continue

    if indicator.lower() == "brief":
        VERBOSE = False
        print("  Brief mode on — summary only.")
        continue

    parts = indicator.split()
    if parts and parts[0].lower() == "history":
        if len(parts) == 1:
            print_history()
        elif len(parts) == 2 and parts[1].lower() == "clear":
            confirm = input("  Clear all history? Type 'yes' to confirm: ").strip().lower()
            if confirm == "yes":
                clear_history()
                print("  History cleared.")
            else:
                print("  Cancelled.")
        elif len(parts) == 2 and parts[1].isdigit():
            n     = int(parts[1])
            entry = get_history_entry(n)
            if entry is None:
                total = get_history_count()
                print(f"  Entry #{n} not found. History has {total} entries.")
            else:
                ind_type = detect_type(entry["indicator"])
                print(f"  (Cached result from {entry['timestamp']})")
                display_report(entry["indicator"], ind_type, entry["vt"], entry["otx"], entry["abuse"],
                               entry["shodan"], entry.get("whois"), entry.get("censys"),
                               greynoise=entry.get("greynoise"), urlhaus=entry.get("urlhaus"),
                               urlscan=entry.get("urlscan"), hybrid=entry.get("hybrid"))
        else:
            print("  Usage: history  or  history <number>  or  history clear")
        continue

    if parts and " ".join(parts[:2]).lower() == "reset cache":
        confirm = input("  Clear all cached API results? Type 'yes' to confirm: ").strip().lower()
        if confirm == "yes":
            clear_cache()
            print("  API cache cleared.")
        else:
            print("  Cancelled.")
        continue

    if parts and parts[0].lower() == "rescan":
        if len(parts) < 2:
            print("  Usage: rescan <ip / domain / hash>")
            continue
        target = parts[1].strip()
        if detect_type(target) is None:
            print(f"  Invalid indicator: {target}")
            continue
        confirm = input(f"  Delete {target} from history and cache and rescan? Type 'yes' to confirm: ").strip().lower()
        if confirm != "yes":
            print("  Cancelled.")
            continue
        old_entry       = get_last_result(target)
        cache_deleted   = clear_indicator_cache(target)
        history_deleted = clear_indicator(target)
        print(f"  Cleared {cache_deleted} cache entries and {history_deleted} history entries for {target}")
        print(f"  Rescanning {target}...")
        check_indicator(target, previous=old_entry)
        continue

    check_indicator(indicator)
