from dotenv import load_dotenv
load_dotenv()

import datetime
from concurrent.futures import ThreadPoolExecutor

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
from sources.spamhaus import spamhaus_asn_check
from sources.threatfox import threatfox_check
from sources.google_intel import query_google_intel
from sources.scoring import combined_verdict, load_config, resolve_vendor, VERDICT_DISPLAY
from sources.pivot import extract_pivot_iocs, run_pivot_scan, _detect_pivot_type
import cache
from cache import clear_cache, clear_indicator_cache
from output import save_results, print_history, get_history_entry, get_history_count, clear_history, clear_indicator, get_last_result, compare_results
import os as _os

config = load_config(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "config.json"))
VERBOSE = False


def display_report(indicator, ind_type, vt, otx, abuse, shodan=None, whois=None, censys=None,
                   greynoise=None, urlhaus=None, urlscan=None, hybrid=None, spamhaus_drop=None,
                   threatfox=None, google_intel=None, pivot_result=None, show_breakdown_only=False):

    verdict_result = combined_verdict(vt, otx, abuse, shodan, whois=whois, censys=censys,
                                      greynoise=greynoise, urlhaus=urlhaus,
                                      urlscan=urlscan, hybrid=hybrid,
                                      spamhaus_drop=spamhaus_drop, threatfox=threatfox,
                                      google_intel=google_intel, config=config,
                                      pivot_result=pivot_result)

    if show_breakdown_only:
        if pivot_result and pivot_result.get("pivot_iocs"):
            print(f"\n  [Pivot IOCs]")
            print(f"  Scanned        : {len(pivot_result['pivot_iocs'])}")
            mal = pivot_result.get("malicious_pivots", [])
            sus = pivot_result.get("suspicious_pivots", [])
            sm  = pivot_result.get("sources_map", {})
            if mal:
                mal_labeled = [f"{i} (via {', '.join(sm.get(i, ['unknown']))})" for i in mal]
                print(f"  Malicious      : {', '.join(mal_labeled)}")
            if sus:
                sus_labeled = [f"{i} (via {', '.join(sm.get(i, ['unknown']))})" for i in sus]
                print(f"  Suspicious     : {', '.join(sus_labeled)}")
            clean = [i for i in pivot_result["pivot_iocs"] if i not in mal and i not in sus]
            if clean:
                print(f"  Clean/no data  : {', '.join(clean)}")
        print(f"\n  Score Breakdown:")
        for line in verdict_result["breakdown"]:
            print(f"    {line}")
        print(f"  {'─'*40}\n")
        return verdict_result

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
            total_engines = (
                vt.get("malicious", 0) + vt.get("suspicious", 0) +
                vt.get("harmless", 0) + vt.get("undetected", 0)
            )
            ratio_str = f"  ({vt['malicious']}/{total_engines} = {vt['malicious']/total_engines:.0%})" if total_engines > 0 and malicious > 0 else ""
            print(f"\n  [VirusTotal]    {malicious} malicious / {harmless} harmless — {tier_summary}{ratio_str}")
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

        if threatfox:
            ioc_count   = threatfox.get('ioc_count', 0)
            malware     = threatfox.get('malware')
            threat_type = threatfox.get('threat_type')
            print(f"  [ThreatFox]     {ioc_count} IOC(s) — {malware or threat_type or 'unknown'}")
        else:
            print(f"  [ThreatFox]     no data")

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

        if spamhaus_drop and spamhaus_drop.get('listed'):
            asname = spamhaus_drop.get('asname') or ''
            cc     = spamhaus_drop.get('cc') or ''
            print(f"  [Spamhaus DROP] listed — {asname} ({cc})")
        elif spamhaus_drop is not None:
            print(f"  [Spamhaus DROP] not listed")

        if google_intel:
            n_fam = len(google_intel.get('malware_families') or [])
            n_atk = len(google_intel.get('attack_ids') or [])
            n_url = len(google_intel.get('urls_fetched') or [])
            gi_parts = []
            if n_fam:
                gi_parts.append(f"{n_fam} malware family/families")
            if n_atk:
                gi_parts.append(f"{n_atk} ATT&CK technique(s)")
            if gi_parts:
                print(f"  [Google Intel]  {n_url} source(s) — {', '.join(gi_parts)}")
            else:
                print(f"  [Google Intel]  {n_url} source(s) — no signals found")
        else:
            print(f"  [Google Intel]  no data")

        if pivot_result and pivot_result.get("pivot_iocs"):
            n_total = len(pivot_result["pivot_iocs"])
            n_mal   = len(pivot_result.get("malicious_pivots", []))
            n_sus   = len(pivot_result.get("suspicious_pivots", []))
            parts   = []
            if n_mal:
                parts.append(f"{n_mal} malicious")
            if n_sus:
                parts.append(f"{n_sus} suspicious")
            if not parts:
                parts.append("all clean")
            print(f"  [Pivot]         {n_total} IOC(s) checked — {', '.join(parts)}")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Triggered by   : {', '.join(verdict_result['triggered_by'])}")
        pivot_bonus = verdict_result.get("pivot_bonus", 0)
        if verdict_result.get("pivot_influenced"):
            print(f"  Pivot         : influenced verdict (pivot bonus: +{pivot_bonus})")
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

        _print_source_summaries(ind_type, vt, otx, abuse, shodan, whois, censys, greynoise, urlhaus, threatfox, urlscan, hybrid, spamhaus_drop)

        if google_intel:
            print(f"\n  [Google Intel]")
            urls_fetched = google_intel.get('urls_fetched') or []
            print(f"  Sources fetched: {len(urls_fetched)}")
            if google_intel.get('search_method'):
                print(f"  Search method  : {google_intel['search_method']}")
            families = google_intel.get('malware_families') or []
            if families:
                print(f"  Malware families: {', '.join(families)}")
            attack_ids = google_intel.get('attack_ids') or []
            if attack_ids:
                print(f"  ATT&CK techs   : {', '.join(attack_ids)}")
            co_iocs = google_intel.get('co_iocs') or {}
            co_ips     = co_iocs.get('ips') or []
            co_domains = co_iocs.get('domains') or []
            co_hashes  = co_iocs.get('hashes') or []
            if co_ips:
                print(f"  Co-mentioned IPs     : {', '.join(co_ips[:10])}")
            if co_domains:
                print(f"  Co-mentioned domains : {', '.join(co_domains[:10])}")
            if co_hashes:
                print(f"  Co-mentioned hashes  : {', '.join(co_hashes[:5])}")

        if pivot_result and pivot_result.get("pivot_iocs"):
            print(f"\n  [Pivot IOCs]")
            print(f"  Scanned        : {len(pivot_result['pivot_iocs'])}")
            mal = pivot_result.get("malicious_pivots", [])
            sus = pivot_result.get("suspicious_pivots", [])
            sm  = pivot_result.get("sources_map", {})
            if mal:
                mal_labeled = [f"{i} (via {', '.join(sm.get(i, ['unknown']))})" for i in mal]
                print(f"  Malicious      : {', '.join(mal_labeled)}")
            if sus:
                sus_labeled = [f"{i} (via {', '.join(sm.get(i, ['unknown']))})" for i in sus]
                print(f"  Suspicious     : {', '.join(sus_labeled)}")
            clean = [i for i in pivot_result["pivot_iocs"] if i not in mal and i not in sus]
            if clean:
                print(f"  Clean/no data  : {', '.join(clean)}")

        print(f"\n  Per Source:")
        for name, s in verdict_result['per_source'].items():
            print(f"    {name:<12}: {s['verdict_display']}  (evidence: {s['evidence_count']})")

        print(f"\n  Score Breakdown:")
        for line in verdict_result["breakdown"]:
            print(f"    {line}")
        print(f"  {'─'*40}")

        print(f"\n  Contribution   :")
        for name, pct in verdict_result['contribution'].items():
            print(f"    {name:<14}: {pct}")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}  (score: {verdict_result['score']})")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"  Triggered      : {', '.join(verdict_result['triggered_by'])}")
        pivot_bonus = verdict_result.get("pivot_bonus", 0)
        if verdict_result.get("pivot_influenced"):
            print(f"  Pivot         : influenced verdict (pivot bonus: +{pivot_bonus})")
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


def _print_source_summaries(ind_type, vt, otx, abuse, shodan, whois, censys, greynoise, urlhaus, threatfox, urlscan, hybrid, spamhaus_drop):
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


def _print_pivot_details(pivot_result, config):
    all_iocs = pivot_result.get("malicious_pivots", []) + pivot_result.get("suspicious_pivots", [])
    cache.SILENT = True
    for ioc in all_iocs:
        print(f"\n  {'─'*55}")
        print(f"  Pivot IOC: {ioc}")
        print(f"  Verdict  : {VERDICT_DISPLAY.get(pivot_result['pivot_verdicts'][ioc])}")
        print(f"  Score    : {pivot_result['pivot_scores'].get(ioc, '?')}")
        print(f"  Found via: {', '.join(pivot_result['sources_map'].get(ioc, []))}")
        print(f"  {'─'*55}")

        ioc_type = _detect_pivot_type(ioc)

        vt_r = otx_r = hybrid_r = threatfox_r = urlhaus_r = urlscan_r = abuse_r = greynoise_r = shodan_r = None
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
            from sources.pivot import _extract_host
            host        = _extract_host(ioc)
            vt_r        = vt_check(host, "domain") if host else None
            threatfox_r = threatfox_check(ioc, "url")
            urlhaus_r   = urlhaus_check(host, "domain") if host else None
            urlscan_r   = urlscan_check(ioc, "domain")
        elif ioc_type == "ip":
            from sources.abuseipdb import abuseipdb_check
            from sources.greynoise import greynoise_check
            from sources.shodan import shodan_check as shodan_check_fn
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

        _print_source_summaries(ioc_type, vt_r, otx_r, abuse_r, shodan_r, None, None, greynoise_r, urlhaus_r, threatfox_r, urlscan_r, hybrid_r, None)

        print(f"\n  Per Source:")
        for name, s in result["per_source"].items():
            print(f"    {name:<12}: {s['verdict_display']}  (evidence: {s['evidence_count']})")

        print(f"\n  Score Breakdown:")
        for line in result["breakdown"]:
            print(f"    {line}")

        print(f"\n  Active sources : {', '.join(result['active_sources'])}")
        print(f"  No data from   : {', '.join(result['inactive_sources'])}")
    cache.SILENT = False


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
    global VERBOSE

    ind_type = detect_type(indicator)

    if ind_type is None:
        print("Invalid indicator. Enter a valid IPv4, domain, or hash.")
        return

    old_entry = previous if previous is not None else get_last_result(indicator)

    source_calls = {
        "vt":           lambda: vt_check(indicator, ind_type),
        "otx":          lambda: otx_check(indicator, ind_type),
        "abuse":        lambda: abuseipdb_check(indicator, ind_type),
        "shodan":       lambda: shodan_check(indicator, ind_type),
        "whois":        lambda: whois_check(indicator, ind_type),
        "censys":       lambda: censys_check(indicator, ind_type),
        "greynoise":    lambda: greynoise_check(indicator, ind_type),
        "urlhaus":      lambda: urlhaus_check(indicator, ind_type),
        "threatfox":    lambda: threatfox_check(indicator, ind_type),
        "urlscan":      lambda: urlscan_check(indicator, ind_type),
        "hybrid":       lambda: hybrid_check(indicator, ind_type),
        "google_intel": lambda: query_google_intel(indicator, ind_type, config=config),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {name: executor.submit(fn) for name, fn in source_calls.items()}
        for name, future in futures.items():
            try:
                results[name] = future.result()
            except Exception as e:
                print(f"  [{name}] Error: {e}")
                results[name] = None

    vt           = results["vt"]
    otx          = results["otx"]
    abuse        = results["abuse"]
    shodan       = results["shodan"]
    whois        = results["whois"]
    censys       = results["censys"]
    greynoise    = results["greynoise"]
    urlhaus      = results["urlhaus"]
    threatfox    = results["threatfox"]
    urlscan      = results["urlscan"]
    hybrid       = results["hybrid"]
    google_intel = results["google_intel"]

    _asn = (
        (shodan.get("asn") if isinstance(shodan, dict) else None) or
        (censys.get("asn") if isinstance(censys, dict) else None) or
        (vt.get("asn")     if isinstance(vt, dict)     else None)
    )
    spamhaus_drop = spamhaus_asn_check(_asn) if _asn else None

    sources_results = {
        "vt":          vt,
        "otx":         otx,
        "google_intel": google_intel,
        "threatfox":   threatfox,
        "urlhaus":     urlhaus,
        "urlscan":     urlscan,
        "censys":      censys,
        "shodan":      shodan,
    }
    pivot_iocs, sources_map = extract_pivot_iocs(sources_results, indicator)
    pivot_result = run_pivot_scan(pivot_iocs, sources_map, config, indicator)

    verdict_result = display_report(indicator, ind_type, vt, otx, abuse, shodan, whois, censys,
                                    greynoise=greynoise, urlhaus=urlhaus,
                                    urlscan=urlscan, hybrid=hybrid, spamhaus_drop=spamhaus_drop,
                                    threatfox=threatfox, google_intel=google_intel,
                                    pivot_result=pivot_result)
    save_results(indicator, vt, otx, abuse, shodan, verdict_result["final_verdict"], whois,
                 score=verdict_result["score"], per_source=verdict_result["per_source"],
                 censys_result=censys, greynoise_result=greynoise, urlhaus_result=urlhaus,
                 urlscan_result=urlscan, hybrid_result=hybrid,
                 spamhaus_drop_result=spamhaus_drop, threatfox_result=threatfox,
                 google_intel_result=google_intel, pivot_result=pivot_result)

    if old_entry is not None:
        new_cmp = {
            "verdict":    verdict_result["final_verdict"],
            "score":      verdict_result["score"],
            "per_source": verdict_result["per_source"],
        }
        _print_changes(compare_results(old_entry, new_cmp), old_entry["timestamp"])

    if not VERBOSE:
        see_verbose = input("  Show full breakdown? [y/N]: ").strip().lower()
        if see_verbose == "y":
            VERBOSE = True
            display_report(indicator, ind_type, vt, otx, abuse, shodan, whois, censys,
                           greynoise=greynoise, urlhaus=urlhaus, urlscan=urlscan,
                           hybrid=hybrid, spamhaus_drop=spamhaus_drop, threatfox=threatfox,
                           google_intel=google_intel, pivot_result=pivot_result)
            VERBOSE = False

    if pivot_result and (
        pivot_result.get("malicious_pivots") or
        pivot_result.get("suspicious_pivots")
    ):
        see_pivot = input("  Show pivot details? [y/N]: ").strip().lower()
        if see_pivot == "y":
            _print_pivot_details(pivot_result, config)


# Main loop

if __name__ == "__main__":
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
                confirm = input("  Clear all history? [y/N]: ").strip().lower()
                if confirm == "y":
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
                                   urlscan=entry.get("urlscan"), hybrid=entry.get("hybrid"),
                                   spamhaus_drop=entry.get("spamhaus_drop"),
                                   threatfox=entry.get("threatfox"),
                                   google_intel=entry.get("google_intel"),
                                   pivot_result=entry.get("pivot_result"))
            else:
                print("  Usage: history  or  history <number>  or  history clear")
            continue

        if parts and " ".join(parts[:2]).lower() == "reset cache":
            confirm = input("  Clear all cached API results? [y/N]: ").strip().lower()
            if confirm == "y":
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
            confirm = input(f"  Delete {target} from history and cache and rescan? [y/N]: ").strip().lower()
            if confirm != "y":
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

