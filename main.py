from dotenv import load_dotenv
load_dotenv()

from concurrent.futures import ThreadPoolExecutor

# Self-heals a fresh/empty ioc_cache.db — must run before ANY `sources.*`
# import below, since sources/scoring.py loads config at its own import time
# (module-level `NOISE_TAGS = load_config()[...]`). See web/app.py for the
# same fix and a fuller explanation.
from sources.app_config import ensure_seeded
ensure_seeded()

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
from sources.pivot import extract_pivot_iocs, run_pivot_scan, _print_source_summaries, generate_pivot_detail_log
import cache
from cache import clear_cache, clear_indicator_cache
from output import save_results, print_history, get_history_entry, get_history_count, clear_history, clear_indicator, get_last_result, compare_results

config = load_config()
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
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"{'='*45}\n")

    else:
        # Verbose: full source detail + score breakdown
        print(f"\n{'='*45}")
        print(f"  Threat Report: {indicator}")
        print(f"{'='*45}")

        _print_source_summaries(ind_type, vt, otx, abuse, shodan, whois, censys, greynoise, urlhaus, threatfox, urlscan, hybrid, spamhaus_drop, config)

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
            print(f"    {name:<12}: {s['findings_label']}  (evidence: {s['evidence_count']})")

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
        print(f"  Active sources : {', '.join(verdict_result['active_sources'])}")
        if verdict_result['inactive_sources']:
            print(f"  No data from   : {', '.join(verdict_result['inactive_sources'])}")
        print(f"{'='*45}\n")

    return verdict_result


def _print_pivot_details(pivot_result, config):
    all_iocs = pivot_result.get("malicious_pivots", []) + pivot_result.get("suspicious_pivots", [])
    cache.SILENT = True
    for ioc in all_iocs:
        print(f"\n  {'─'*55}")
        print(f"  Pivot IOC: {ioc}")
        print(generate_pivot_detail_log(ioc, pivot_result, config))
        print(f"  {'─'*55}")
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
            old_v = chg["from"] or "No Findings"
            new_v = chg["to"]   or "No Findings"
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
    pivot_iocs, sources_map, relation_map = extract_pivot_iocs(sources_results, indicator)
    # user_id=None matches save_results' default below — the CLI has no
    # per-user accounts, so full-scan lookups here aren't scoped to one.
    pivot_result = run_pivot_scan(pivot_iocs, sources_map, config, indicator, relation_map, user_id=None)

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
                 google_intel_result=google_intel, pivot_result=pivot_result,
                 breakdown=verdict_result["breakdown"],
                 recommendation=verdict_result["recommendation"],
                 consensus_ratio=verdict_result["consensus_ratio"],
                 triggered_by=verdict_result["triggered_by"],
                 active_sources=verdict_result["active_sources"],
                 inactive_sources=verdict_result["inactive_sources"],
                 contribution=verdict_result["contribution"])

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

