import datetime
import json

def load_config(path="config.json"):
    with open(path) as f:
        config = json.load(f)

    scoring   = config["_meta"]["scoring"]
    aliases   = config.get("vt_engine_name_aliases", {})
    tier1_raw = config["tier1"]["vendors"]
    tier2_raw = config["tier2"]["vendors"]

    # Build alias lookup: vt_engine_name (lower) → canonical name (lower)
    alias_lookup = {}
    for canonical, vt_names in aliases.items():
        if isinstance(vt_names, list):
            for vt_name in vt_names:
                alias_lookup[vt_name.lower()] = canonical.lower()

    tier1 = set(v.lower() for v in tier1_raw)
    tier2 = set(v.lower() for v in tier2_raw)

    # Flatten nested tag_weights into a single {tag: weight} dict
    raw_tags    = config.get("tag_weights", {})
    tag_cap     = raw_tags.get("tag_cap", 5)
    tag_weights = {}
    for group, entries in raw_tags.items():
        if group.startswith("_") or group == "tag_cap":
            continue
        if isinstance(entries, dict):
            for tag, weight in entries.items():
                if not tag.startswith("_"):
                    tag_weights[tag.lower()] = weight
                    
    suspicious_ports    = config.get("suspicious_ports", {})
    suspicious_products = config.get("suspicious_products", {})
    shodan_tags         = config.get("shodan_tags", {})
    trusted_asns        = config.get("trusted_asns", {})
    vt_file_tags        = config.get("vt_file_tags", {})

    return {
        "tier1":        tier1,
        "tier2":        tier2,
        "alias_lookup": alias_lookup,
        "scoring":      scoring,
        "tag_weights":  tag_weights,
        "tag_cap":      tag_cap,
        "default_mode": config.get("default_verdict_mode", "worst_case"),
        "apt_actors":   {a.lower() for a in config.get("apt_actors", [])},
        "suspicious_ports":    suspicious_ports,
        "suspicious_products": suspicious_products,
        "shodan_tags":         shodan_tags,
        "trusted_asns":        trusted_asns,
        "source_reliability":  config.get("source_reliability", {}),
        "vt_file_tags":        vt_file_tags,
    }


def resolve_vendor(raw_name, alias_lookup):
    return alias_lookup.get(raw_name.lower(), raw_name.lower())

# Used to pick the strongest confidence/verdict when comparing across sources
CONFIDENCE_ORDER = {None: 0, "low": 1, "medium": 2, "high": 3}

VERDICT_ORDER = {None: 0, "no_data": 0, "clean": 1, "suspicious": 2, "low_risk": 3, "medium_risk": 4, "high": 5}

VERDICT_DISPLAY = {
    "high":        "🔴 High risk",
    "medium_risk": "🟠 Medium risk",
    "low_risk":    "🟡 Low risk",
    "suspicious":  "⚠️  Suspicious",
    "clean":       "✅ Clean",
    "no_data":     "ℹ️  No data",
}

RECOMMENDATIONS = {
    "high":        "Escalate immediately",
    "medium_risk": "Investigate",
    "elevated":    "Review",
    "suspicious":  "Monitor",
    "clean":       "No action required",
    "no_data":     "No data available",
}

# OTX pulse tags that indicate automated scanner/honeypot noise, not real threat intel
NOISE_TAGS = {
    "honeypot", "tpot", "sensor-tagged", "scanner", "portscan", "scanners",
    "cowrie", "suricata", "dionaea", "kippo", "glastopf", "conpot", "mailoney",
}

def score_to_verdict(score):
    # Thresholds: <=0=clean, 1-2=suspicious, 3-4=low, 5-7=medium, 8+=high
    if score <= 0:
        return "clean"
    elif score <= 2:
        return "suspicious"
    elif score <= 4:
        return "low_risk"
    elif score <= 7:
        return "medium_risk"
    else:
        return "high"


def score_vt(vt, config):
    """Score VirusTotal data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Raw malicious count  — how many engines flagged it
      2. Harmless deduction   — counterbalances noise when most engines agree it's clean
      3. Suspicious count     — engines that hedged rather than flagged outright
      4. Vendor tier hits     — weighted by engine reputation (tier1 > tier2 > tier3)
      5. Tags                 — VT behavioral tags (e.g. 'miner', 'trojan') from config weights
      6. Recency              — recent scans with hits are more actionable than old ones
    """

    if not vt:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score        = 0
    breakdown    = []
    tier1        = config["tier1"]
    tier2        = config["tier2"]
    alias_lookup = config["alias_lookup"]
    scoring      = config["scoring"]

    malicious  = vt.get("malicious", 0)
    harmless   = vt.get("harmless", 0)
    undetected = vt.get("undetected", 0)

    if malicious >= 10:
        score += 3
        breakdown.append(f"Malicious count {malicious:<5} → +3")
    elif malicious >= 4:
        score += 2
        breakdown.append(f"Malicious count {malicious:<5} → +2")
    elif malicious >= 1:
        score += 1
        breakdown.append(f"Malicious count {malicious:<5} → +1")
    else:
        breakdown.append(f"Malicious count {malicious:<5} → +0")

    if harmless >= 50 and malicious <= 1:
        breakdown.append(f"Harmless majority {harmless:<4}  → +0  (overwhelmingly clean)")
    elif harmless >= 30 and malicious <= 2:
        breakdown.append(f"Harmless majority {harmless:<4}  → +0  (mostly clean)")

    suspicious = vt.get("suspicious", 0)

    if suspicious >= 3:
        score += 1
        breakdown.append(f"Suspicious count {suspicious:<4} → +1")
    else:
        breakdown.append(f"Suspicious count {suspicious:<4} → +0")

    tier1_hits = tier2_hits = tier3_hits = 0

    # Classify each flagging vendor by tier after resolving any VT engine name aliases
    for v in vt.get("malicious_vendors", []):
        canonical = resolve_vendor(v["vendor"], alias_lookup)
        if canonical in tier1:
            tier1_hits += 1
        elif canonical in tier2:
            tier2_hits += 1
        else:
            tier3_hits += 1

    # Per-tier points are capped independently so a flood of low-tier hits can't dominate
    tier1_points = min(tier1_hits * scoring["tier1_points"], scoring["tier1_cap"])
    tier2_points = min(tier2_hits * scoring["tier2_points"], scoring["tier2_cap"])
    tier3_points = min(tier3_hits * scoring["tier3_points"], scoring["tier3_cap"])

    score += tier1_points + tier2_points + tier3_points

    if tier1_hits > 0:
        breakdown.append(f"Tier 1 vendors   {tier1_hits:<5} → +{tier1_points}  (cap {scoring['tier1_cap']})")
    if tier2_hits > 0:
        breakdown.append(f"Tier 2 vendors   {tier2_hits:<5} → +{tier2_points}  (cap {scoring['tier2_cap']})")
    if tier3_hits > 0:
        breakdown.append(f"Tier 3 vendors   {tier3_hits:<5} → +{tier3_points}  (cap {scoring['tier3_cap']})")

    tag_score  = 0
    found_tags = []

    for tag in vt.get("tags", []):
        weight = config["tag_weights"].get(tag.lower(), 0)
        if weight == 0:
            weight = config.get("vt_file_tags", {}).get(tag.lower(), 0)
        if weight > 0:
            tag_score += weight
            found_tags.append(tag)

    tag_score = min(tag_score, config["tag_cap"])
    score += tag_score

    if found_tags:
        breakdown.append(f"Tags {', '.join(found_tags):<20} → +{tag_score}  (cap {config['tag_cap']})")
    else:
        breakdown.append(f"Tags none                    → +0")

    # Recency only applies when there are active malicious detections — an old clean scan
    # shouldn't penalize an IP, and a brand-new scan of a clean IP isn't worth boosting.
    if vt.get("last_scan_date") and malicious > 0:
        now       = datetime.datetime.now()
        scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
        days_ago  = (now - scan_date).days

        if days_ago <= 7:
            score += 2
            breakdown.append(f"Last scanned {days_ago} days ago       → +2")
        elif days_ago <= 30:
            score += 1
            breakdown.append(f"Last scanned {days_ago} days ago       → +1")
        elif days_ago > 180:
            breakdown.append(f"Last scanned {days_ago} days ago       → +0  (old, not penalized)")
        else:
            breakdown.append(f"Last scanned {days_ago} days ago       → +0")
    else:
        if vt.get("last_scan_date"):
            breakdown.append(f"Recency skipped — no malicious detections")

    # Only assign a real verdict if there's something to judge; avoids false "clean" on empty responses
    has_data = (
        malicious > 0 or
        suspicious > 0 or
        len(found_tags) > 0 or
        harmless > 0 or
        undetected > 0
    )

    if tier1_hits >= 2:
        confidence = "high"
    elif tier1_hits >= 1 or tier2_hits >= 2:
        confidence = "medium"
    elif malicious >= 15:
        confidence = "high"
    elif malicious >= 10:
        confidence = "medium"
    elif malicious >= 1:
        confidence = "low"
    elif harmless >= 10:
        confidence = "high"
    elif harmless >= 1:
        confidence = "medium"
    else:
        confidence = None

    score = min(score, 15)

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": malicious,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_otx(otx, config=None):
    """Score AlienVault OTX data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Pulse count      — how widely tracked the IP is across OTX feeds
      2. Reputation       — OTX community reputation score (negative = flagged)
      3. Recent pulses    — pulses mentioning 2025/2026 indicate current activity
      4. Pulse tags       — weighted tags on individual pulses (noise tags excluded)
      5. Adversary        — named APT/adversary attribution is high-signal
      6. Malware families — named family in a pulse stands on its own
      7. Passive DNS      — recent passive DNS activity corroborates the threat
    """

    if not otx:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []

    pulse_count   = otx.get("pulse_count", 0)
    pulse_details = otx.get("pulse_details", [])
    reputation    = otx.get("reputation", 0)

    if reputation < 0:
        score += 1
        breakdown.append(f"OTX reputation {reputation:<5} → +1  (negative)")
    else:
        breakdown.append(f"OTX reputation {reputation:<5} → +0")

    # Single pass over pulse_details: noise filter, recency, tag scoring, adversary, families
    pulse_tag_score    = 0
    pulse_tag_contrib  = {}
    adversary_score    = 0
    apt_hit            = False
    family_score       = 0
    recent_pulse_found = False
    non_noise_count    = 0

    for p in pulse_details:
        p_tags = {t.lower() for t in p.get("tags", [])}

        # Skip pulses whose tags are entirely noise (honeypots, honeypot sensors, etc.)
        if p_tags and p_tags.issubset(NOISE_TAGS):
            continue

        non_noise_count += 1

        # OTX doesn't expose a reliable created_at field via the indicator API,
        # so we look for the year in the pulse name as a cheap recency heuristic.
        if "2026" in p.get("name", "") or "2025" in p.get("name", ""):
            recent_pulse_found = True

        # Pulse tag scoring
        if config:
            for tag in p_tags - NOISE_TAGS:
                w = config["tag_weights"].get(tag, 0)
                if w > 0:
                    pulse_tag_score += w
                    pulse_tag_contrib[tag] = pulse_tag_contrib.get(tag, 0) + w

        # Adversary attribution
        adversary = p.get("adversary", "")
        if adversary:
            apt_actors = config.get("apt_actors", set()) if config else set()
            if adversary.lower() in apt_actors:
                adversary_score = min(adversary_score + 4, 4)
                apt_hit = True
            else:
                adversary_score = min(adversary_score + 2, 4)

        # Malware family
        if p.get("families", []):
            family_score = min(family_score + 2, 4)

    # Gate pulse count score on quality: if we have details and all are noise, score 0.
    # When no pulse_details are available fall back to the raw count (can't judge quality).
    qualifying_count = non_noise_count if pulse_details else pulse_count
    if qualifying_count >= 20:
        score += 1
        breakdown.append(f"OTX pulses {pulse_count:<8} → +1  (widely tracked, {qualifying_count} quality)")
    else:
        if pulse_count > 0 and pulse_details and qualifying_count == 0:
            breakdown.append(f"OTX pulses {pulse_count:<8} → +0  (all noise-tagged)")
        else:
            breakdown.append(f"OTX pulses {pulse_count:<8} → +0")

    if recent_pulse_found:
        score += 1
        breakdown.append(f"Recent pulse (2025/2026)     → +1")
    else:
        breakdown.append(f"Recent pulse (2025/2026)     → +0")

    pulse_tag_score = min(pulse_tag_score, 5)
    if pulse_tag_contrib:
        score += pulse_tag_score
        for tag, w in sorted(pulse_tag_contrib.items(), key=lambda x: -x[1]):
            breakdown.append(f"  Pulse tag [{tag}] → +{w}")
        breakdown.append(f"Pulse tags (capped)          → +{pulse_tag_score}  (cap 5)")
    else:
        breakdown.append(f"Pulse tags                   → +0")

    if adversary_score > 0:
        score += adversary_score
        label = "APT actor" if apt_hit else "adversary"
        breakdown.append(f"Adversary attribution ({label}) → +{adversary_score}  (cap 4)")
    else:
        breakdown.append(f"Adversary attribution        → +0")

    if family_score > 0:
        score += family_score
        breakdown.append(f"Malware families             → +{family_score}  (cap 4)")
    else:
        breakdown.append(f"Malware families             → +0")

    pdns        = otx.get("passive_dns", [])
    latest_pdns = None

    for r in pdns:
        last_str = r.get("last", "")
        if not last_str:
            continue
        try:
            last_dt = datetime.datetime.fromisoformat(last_str.replace("Z", ""))
            if latest_pdns is None or last_dt > latest_pdns:
                latest_pdns = last_dt
        except ValueError:
            pass

    if latest_pdns:
        days_since = (datetime.datetime.now() - latest_pdns).days
        if days_since <= 30:
            score += 1
            breakdown.append(f"Passive DNS last seen {days_since} days ago → +1")
        else:
            breakdown.append(f"Passive DNS last seen {days_since} days ago → +0")
    else:
        breakdown.append(f"Passive DNS last seen unknown  → +0")

    score = min(score, 15)

    # reputation is 0 for unknown IPs, negative means OTX community flagged it
    has_data = pulse_count > 0 or reputation < 0

    if adversary_score > 0 or family_score > 0:
        confidence = "high"
    elif pulse_tag_score > 0:
        confidence = "medium"
    elif pulse_count > 0:
        confidence = "low"
    else:
        confidence = None

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": pulse_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_abuse(abuse):
    """Score AbuseIPDB data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Distinct reporters — independent sources corroborate the abuse
      2. Recency            — recent reports are more actionable
      3. Tor exit node      — anonymization proxy adds baseline risk

    AbuseIPDB's confidence score is shown informally but not used for
    scoring — it is often stale or miscalibrated for shared infrastructure.
    """

    if not abuse:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score          = 0
    breakdown      = []
    abuse_score    = abuse.get("abuse_score", 0)
    distinct_users = abuse.get("distinct_users", 0)
    is_tor         = abuse.get("is_tor", False)
    last_reported  = abuse.get("last_reported")

    # Show the AbuseIPDB confidence score informally but do not use
    # it for scoring — it is often stale or miscalibrated for shared
    # infrastructure. Score from raw report data instead.
    breakdown.append(f"AbuseIPDB confidence {abuse_score}%       → informational only")

    if distinct_users >= 50:
        score += 3
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +3  (widely reported)")
    elif distinct_users >= 20:
        score += 2
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +2")
    elif distinct_users >= 5:
        score += 1
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +1")
    elif distinct_users >= 2:
        score += 0
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +0  (too few reporters)")
    else:
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +0")

    if last_reported:
        try:
            last_dt  = datetime.datetime.fromisoformat(last_reported[:19])
            days_ago = (datetime.datetime.now() - last_dt).days
            if days_ago <= 7:
                score += 2
                breakdown.append(f"Last reported {days_ago} days ago       → +2  (very recent)")
            elif days_ago <= 30:
                score += 1
                breakdown.append(f"Last reported {days_ago} days ago       → +1  (recent)")
            elif days_ago <= 90:
                breakdown.append(f"Last reported {days_ago} days ago       → +0")
            else:
                breakdown.append(f"Last reported {days_ago} days ago       → +0  (old)")
        except (ValueError, TypeError):
            breakdown.append(f"Last reported date unknown  → +0")
    else:
        breakdown.append(f"Last reported unknown        → +0")

    if is_tor:
        score += 1
        breakdown.append(f"Tor exit node               → +1")
    else:
        breakdown.append(f"Tor exit node               → +0")

    has_data = distinct_users > 0 or is_tor

    if distinct_users >= 20:
        confidence = "high"
    elif distinct_users >= 5:
        confidence = "medium"
    elif distinct_users >= 2:
        confidence = "low"
    else:
        confidence = None

    score = min(score, 15)
    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": distinct_users,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }

def score_shodan(shodan, config=None):
    """Score Shodan data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. CVEs          — known vulnerabilities matched against running services
      2. Ports         — suspicious ports associated with malware and C2 (skipped for trusted ASNs)
      3. Products      — offensive tools identified in banners
      4. Shodan tags   — Shodan's own classification labels (weight >= 3 only for trusted ASNs)
      5. No hostname   — anonymous infrastructure with no reverse DNS (skipped for trusted ASNs)

    Trusted ASNs (Cloudflare, Google, etc.) skip port and hostname scoring because shared
    infrastructure legitimately exposes many ports. A non-clean verdict additionally requires
    at least one CVE, suspicious product, or high-weight tag (weight >= 3) — open ports and
    a missing hostname alone can never push the verdict above clean.
    """

    if not shodan:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []

    suspicious_ports    = config.get("suspicious_ports", {})    if config else {}
    suspicious_products = config.get("suspicious_products", {}) if config else {}
    shodan_tag_weights  = config.get("shodan_tags", {})         if config else {}
    trusted_asns        = config.get("trusted_asns", {})        if config else {}

    asn = (shodan.get("asn") or "").strip().upper()
    is_trusted_asn = asn in trusted_asns

    if is_trusted_asn:
        breakdown.append(f"Trusted ASN {asn} ({trusted_asns[asn]}) → port/hostname scoring skipped")

    vulns      = shodan.get("vulns", [])
    vuln_count = len(vulns)

    if vuln_count >= 5:
        score += 3
        breakdown.append(f"CVEs found       {vuln_count:<5} → +3  (critically exposed)")
    elif vuln_count >= 3:
        score += 2
        breakdown.append(f"CVEs found       {vuln_count:<5} → +2  (multiple vulnerabilities)")
    elif vuln_count >= 1:
        score += 1
        breakdown.append(f"CVEs found       {vuln_count:<5} → +1  (vulnerable)")
    else:
        breakdown.append(f"CVEs found       {vuln_count:<5} → +0")

    if vulns:
        breakdown.append(f"  CVEs: {', '.join(vulns[:5])}")

    port_score    = 0
    flagged_ports = []

    if not is_trusted_asn:
        for port in shodan.get("ports", []):
            port_str = str(port)
            if port_str in suspicious_ports:
                weight = suspicious_ports[port_str]["weight"]
                reason = suspicious_ports[port_str]["reason"]
                port_score += weight
                flagged_ports.append(f"{port} ({reason})")

        port_score = min(port_score, 4)
        score += port_score

        if flagged_ports:
            breakdown.append(f"Suspicious ports {len(flagged_ports):<4} → +{port_score}  (cap 4)")
            for p in flagged_ports:
                breakdown.append(f"  Port {p}")
        else:
            breakdown.append(f"Suspicious ports none → +0")
    else:
        breakdown.append(f"Suspicious ports (skipped — trusted ASN) → +0")

    product_score    = 0
    flagged_products = []

    for service in shodan.get("services", []):
        product = service.get("product", "").lower()
        if not product:
            continue
        for known_product, details in suspicious_products.items():
            if known_product in product:
                product_score += details["weight"]
                flagged_products.append(f"{service['product']} on port {service['port']} ({details['reason']})")

    product_score = min(product_score, 6)
    score += product_score

    if flagged_products:
        breakdown.append(f"Suspicious products {len(flagged_products):<3} → +{product_score}  (cap 6)")
        for p in flagged_products:
            breakdown.append(f"  {p}")
    else:
        breakdown.append(f"Suspicious products none  → +0")

    tag_score           = 0
    flagged_tags        = []
    has_high_weight_tag = False

    for tag in shodan.get("tags", []):
        tag_lower = tag.lower()
        if tag_lower in shodan_tag_weights:
            weight = shodan_tag_weights[tag_lower]["weight"]
            reason = shodan_tag_weights[tag_lower]["reason"]
            if weight >= 3:
                has_high_weight_tag = True
            if is_trusted_asn and weight < 3:
                continue
            tag_score += weight
            flagged_tags.append(f"{tag} ({reason})")

    tag_score = min(tag_score, 5)
    score += tag_score

    if flagged_tags:
        breakdown.append(f"Shodan tags      {len(flagged_tags):<4} → +{tag_score}  (cap 5)")
        for t in flagged_tags:
            breakdown.append(f"  Tag: {t}")
    else:
        breakdown.append(f"Shodan tags      none → +0")

    if not is_trusted_asn:
        hostnames = shodan.get("hostnames", [])
        if not hostnames:
            score += 1
            breakdown.append(f"No hostname                  → +1  (anonymous infrastructure)")
        else:
            breakdown.append(f"Hostname: {hostnames[0]:<20} → +0")
    else:
        breakdown.append(f"Hostname check (skipped — trusted ASN) → +0")

    has_data = (
        len(vulns) > 0 or
        len(flagged_ports) > 0 or
        len(flagged_products) > 0 or
        len(flagged_tags) > 0 or
        len(shodan.get("ports", [])) > 0
    )

    if len(vulns) >= 3 or len(flagged_products) > 0:
        confidence = "high"
    elif len(vulns) >= 1 or len(flagged_ports) > 0 or len(flagged_tags) > 0:
        confidence = "medium"
    elif has_data:
        confidence = "low"
    else:
        confidence = None

    score = min(score, 15)

    # Minimum evidence threshold: open ports and missing hostname alone cannot raise the verdict
    meets_min_threshold = vuln_count > 0 or product_score > 0 or has_high_weight_tag

    if has_data and meets_min_threshold:
        verdict = score_to_verdict(score)
    elif has_data:
        verdict = "clean"
    else:
        verdict = "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": len(vulns) + len(flagged_ports) + len(flagged_products),
        "has_data":       has_data,
        "breakdown":      breakdown,
    }
    
    
def combined_verdict(vt=None, otx=None, abuse=None,shodan=None, mode=None, config=None):
    """Combine per-source scores into a single final verdict.

    Three aggregation modes (set via config or overridden per-call):
      worst_case  — takes the highest verdict across all active sources; most conservative
      average     — averages raw scores then maps to a verdict; balances all sources equally
      weighted    — blends verdicts using fixed source weights (VT 50%, OTX 30%, Abuse 20%),
                    normalizing to the active subset so missing sources don't dilute the result

    Confidence is derived from corroboration (how many sources agree on the final verdict)
    rather than from any individual source, because cross-source agreement is a stronger
    signal than a single high-confidence hit.
    """

    if config is None:
        config = load_config()

    if mode is None:
        mode = config.get("default_mode", "worst_case")

    vt_result    = score_vt(vt, config)
    otx_result   = score_otx(otx, config=config)
    abuse_result = score_abuse(abuse)
    shodan_result = score_shodan(shodan, config=config)
    sources = {
        "VirusTotal": vt_result,
        "OTX":        otx_result,
        "AbuseIPDB":  abuse_result,
        "Shodan":     shodan_result,
    }

    # Only include sources that returned real data so no-data sources don't drag the verdict down
    active = {name: r for name, r in sources.items() if r["has_data"]}

    if not active:
        return {
            "final_verdict":         "no_data",
            "final_verdict_display": VERDICT_DISPLAY["no_data"],
            "confidence":            None,
            "triggered_by":          [],
            "mode":                  mode,
            "score":                 0,
            "corroboration_count":   0,
            "consensus_ratio":       "Weak (0/0)",
            "recommendation":        RECOMMENDATIONS["no_data"],
            "per_source": {
                name: {
                    "verdict":         r["verdict"],
                    "verdict_display": VERDICT_DISPLAY.get(r["verdict"], r["verdict"]),
                    "confidence":      r["confidence"],
                    "score":           r["score"],
                    "evidence_count":  r["evidence_count"],
                    "has_data":        r["has_data"],
                }
                for name, r in sources.items()
            },
            "breakdown": [],
        }

    reliability = config.get("source_reliability", {})

    if mode == "worst_case":
        final_score = max(
            r["score"] * reliability.get(name, 1.0)
            for name, r in active.items()
        )
        final_verdict = score_to_verdict(final_score)

    elif mode == "average":
        final_score = sum(
            r["score"] * reliability.get(name, 1.0)
            for name, r in active.items()
        ) / len(active)
        final_verdict = score_to_verdict(final_score)

    elif mode == "weighted":
        base_weights = {"VirusTotal": 0.4, "OTX": 0.25, "AbuseIPDB": 0.15, "Shodan": 0.2}
        active_weights     = {name: base_weights.get(name, 0.1) for name in active}
        total_weight       = sum(active_weights.values())
        normalized_weights = {name: w / total_weight for name, w in active_weights.items()}
        final_score = sum(
            r["score"] * reliability.get(name, 1.0) * normalized_weights[name]
            for name, r in active.items()
        )
        final_verdict = score_to_verdict(final_score)

    else:
        final_score = max(
            r["score"] * reliability.get(name, 1.0)
            for name, r in active.items()
        )
        final_verdict = score_to_verdict(final_score)

    # Cap verdict at medium_risk for trusted CDN/cloud ASNs — shared infrastructure
    # legitimately looks suspicious on port and hostname signals alone.
    shodan_asn = ""
    if shodan and isinstance(shodan, dict):
        shodan_asn = (shodan.get("asn") or "").strip().upper()
    if shodan_asn in config.get("trusted_asns", {}):
        if VERDICT_ORDER.get(final_verdict, 0) > VERDICT_ORDER["medium_risk"]:
            final_verdict = "medium_risk"

    for name, r in active.items():
        if r["verdict"] == "high" and r["confidence"] in ("high", "medium"):
            if VERDICT_ORDER.get(final_verdict, 0) < VERDICT_ORDER["medium_risk"]:
                final_verdict = "medium_risk"
                break

    otx_breakdown = sources["OTX"]["breakdown"]
    has_apt = any("APT actor" in line for line in otx_breakdown)
    if has_apt:
        if VERDICT_ORDER.get(final_verdict, 0) < VERDICT_ORDER["high"]:
            final_verdict = "high"

    triggered_by        = [
        name for name, r in active.items()
        if VERDICT_ORDER.get(r["verdict"], 0) >= VERDICT_ORDER.get(final_verdict, 0) - 1
    ]
    corroboration_count = len(triggered_by)
    active_count        = len(active)

    # Source confidence: strongest confidence among individual sources
    single_source_confidences = [r["confidence"] for r in active.values() if r["confidence"]]
    if single_source_confidences:
        source_confidence = max(single_source_confidences, key=lambda c: CONFIDENCE_ORDER[c])
    else:
        source_confidence = "low"

    # System confidence: derived from cross-source corroboration count
    if active_count >= 3 and corroboration_count >= 3:
        system_confidence = "high"
    elif active_count >= 2 and corroboration_count >= 2:
        system_confidence = "medium"
    else:
        system_confidence = "low"

    # Blended confidence: resolves contradictions between a single high-signal source
    # and weak cross-source consensus so the display doesn't mislead analysts.
    if system_confidence == "low" and corroboration_count == 1:
        blended_confidence = "low"
    elif source_confidence == "high" and system_confidence == "medium":
        blended_confidence = "medium"
    elif source_confidence == "high" and system_confidence == "high":
        blended_confidence = "high"
    else:
        blended_confidence = min(
            source_confidence or "low", system_confidence,
            key=lambda c: CONFIDENCE_ORDER.get(c, 1),
        )

    ratio_str    = f"{corroboration_count}/{active_count}"
    if active_count == 1:
        consensus_ratio = f"Single-source ({ratio_str})"
    elif corroboration_count == active_count:
        consensus_ratio = f"Strong ({ratio_str})"
    elif corroboration_count >= 2:
        consensus_ratio = f"Moderate ({ratio_str})"
    else:
        consensus_ratio = f"Weak ({ratio_str})"

    full_breakdown = []
    for name, r in sources.items():
        if r["breakdown"]:
            full_breakdown.append(f"── {name} ──")
            full_breakdown.extend(r["breakdown"])

    raw_total     = sum(r["score"] for r in active.values())
    display_score = round(raw_total / len(active), 1) if active else 0
    contribution  = {}
    for name, r in sources.items():
        if not r["has_data"]:
            contribution[name] = "no data"
        elif raw_total <= 0:
            contribution[name] = "0%"
        else:
            pct = round(max(r["score"], 0) / raw_total * 100)
            contribution[name] = f"{pct}%"

    return {
        "final_verdict":         final_verdict,
        "final_verdict_display": VERDICT_DISPLAY.get(final_verdict, final_verdict),
        "confidence":            source_confidence,
        "system_confidence":     system_confidence,
        "blended_confidence":    blended_confidence,
        "triggered_by":          triggered_by,
        "mode":                  mode,
        "score":                 display_score,
        "corroboration_count":   corroboration_count,
        "consensus_ratio":       consensus_ratio,
        "recommendation":        RECOMMENDATIONS.get(final_verdict, "Review"),
        "active_sources":        list(active.keys()),
        "inactive_sources":      [name for name, r in sources.items() if not r["has_data"]],
        "contribution":          contribution,
        "per_source": {
            name: {
                "verdict":         r["verdict"],
                "verdict_display": VERDICT_DISPLAY.get(r["verdict"], r["verdict"]),
                "confidence":      r["confidence"],
                "score":           r["score"],
                "evidence_count":  r["evidence_count"],
                "has_data":        r["has_data"],
            }
            for name, r in sources.items()
        },
        "breakdown": full_breakdown,
    }
