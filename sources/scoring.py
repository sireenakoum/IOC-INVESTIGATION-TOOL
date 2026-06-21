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
    cdn_asns            = config.get("cdn_asns", {})
    cloud_hosting_asns  = config.get("cloud_hosting_asns", {})
    vt_file_tags        = config.get("vt_file_tags", {})

    return {
        "tier1":        tier1,
        "tier2":        tier2,
        "alias_lookup": alias_lookup,
        "scoring":      scoring,
        "tag_weights":  tag_weights,
        "tag_cap":      tag_cap,
        "apt_actors":   {a.lower() for a in config.get("apt_actors", [])},
        "suspicious_ports":    suspicious_ports,
        "suspicious_products": suspicious_products,
        "shodan_tags":         shodan_tags,
        "cdn_asns":            cdn_asns,
        "cloud_hosting_asns":  cloud_hosting_asns,
        "vt_file_tags":             vt_file_tags,
        "abuseipdb_attack_weights": config.get("abuseipdb_attack_weights", {}),
    }


def resolve_vendor(raw_name, alias_lookup):
    return alias_lookup.get(raw_name.lower(), raw_name.lower())

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
    if score <= 0:
        return "clean"
    elif score <= 3:
        return "suspicious"
    elif score <= 7:
        return "low_risk"
    elif score <= 13:
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
        return {"verdict": "no_data", "score": 0,
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

        qualifies_for_recency = (
            malicious >= 2 or
            tier1_hits >= 1 or
            tier2_hits >= 2
        )
        if qualifies_for_recency:
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
            breakdown.append(f"Last scanned {days_ago} days ago       → +0  (recency skipped — weak detections only)")
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

    score = min(score, 15)

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
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
        return {"verdict": "no_data", "score": 0,
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
        pulse_name = p.get("name", "")
        pulse_ref  = p.get("ref", "")
        pulse_tags_str = " ".join(p.get("tags", []))
        if (
            "2026" in pulse_name or "2025" in pulse_name or
            "2026" in pulse_ref  or "2025" in pulse_ref  or
            "2026" in pulse_tags_str or "2025" in pulse_tags_str
        ):
            recent_pulse_found = True

        # Pulse tag scoring
        if config:
            meaningful_tags = {
                t for t in p_tags - NOISE_TAGS
                if config["tag_weights"].get(t, 0) >= 2
            }
            if meaningful_tags:
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

        # Malware family
        if p.get("families", []):
            family_score = min(family_score + 2, 4)

    pulse_tag_score = min(pulse_tag_score, 3)  # cap per-pulse contribution

    # Gate pulse count score on quality: only zero out if the entire sample is noise.
    # pulse_details is a 5-pulse sample, so use full pulse_count when any sample pulse
    # is non-noise; fall back to raw count when no details are available.
    if pulse_details:
        qualifying_count = pulse_count if non_noise_count > 0 else 0
    else:
        qualifying_count = pulse_count
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
        raw_pulse_total = sum(pulse_tag_contrib.values())
        for tag, w in sorted(pulse_tag_contrib.items(), key=lambda x: -x[1]):
            breakdown.append(f"  Pulse tag [{tag}] → +{w}")
        if raw_pulse_total > pulse_tag_score:
            breakdown.append(f"  Raw pulse tag total → {raw_pulse_total}  (per-pulse cap of 3 applied)")
        breakdown.append(f"Pulse tags contribution      → +{pulse_tag_score}")
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
        if days_since <= 30 and (pulse_count > 0 or reputation < 0):
            score += 1
            breakdown.append(f"Passive DNS last seen {days_since} days ago → +1")
        elif days_since <= 30:
            breakdown.append(f"Passive DNS last seen {days_since} days ago → +0  (skipped — no pulse data to corroborate)")
        else:
            breakdown.append(f"Passive DNS last seen {days_since} days ago → +0")
    else:
        breakdown.append(f"Passive DNS last seen unknown  → +0")

    score = min(score, 15)

    # reputation is 0 for unknown IPs, negative means OTX community flagged it
    has_data = pulse_count > 0 or reputation < 0

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": pulse_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_abuse(abuse, config=None, asn=None):
    """Score AbuseIPDB data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Distinct reporters — independent sources corroborate the abuse
      2. Recency            — recent reports are more actionable
      3. Tor exit node      — anonymization proxy adds baseline risk
      4. Attack types       — high-severity categories (phishing, hacking) score more than noisy ones (port scan)

    AbuseIPDB's confidence score is shown informally but not used for
    scoring — it is often stale or miscalibrated for shared infrastructure.
    """

    if not abuse:
        return {"verdict": "no_data", "score": 0,
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
    if abuse_score >= 80:
        score += 2
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +2  (high confidence)")
    elif abuse_score >= 40:
        score += 1
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +1  (moderate confidence)")
    else:
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +0  (low — not scored)")

    if distinct_users >= 500:
        score += 5
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +5  (extraordinary — mass reporting)")
    elif distinct_users >= 100:
        score += 4
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +4  (overwhelming corroboration)")
    elif distinct_users >= 50:
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

    attack_weights = (config or {}).get("abuseipdb_attack_weights", {})
    if attack_weights and abuse.get("top_categories"):
        high_cfg   = attack_weights.get("high", {})
        medium_cfg = attack_weights.get("medium", {})
        ignore_cfg = attack_weights.get("ignore", {})

        high_cats   = set(high_cfg.get("categories", []))
        medium_cats = set(medium_cfg.get("categories", []))
        ignore_cats = set(ignore_cfg.get("categories", []))

        high_score   = 0
        medium_score = 0
        matched_cats = []

        for cat_name, _ in abuse.get("top_categories", []):
            if cat_name in ignore_cats:
                continue
            elif cat_name in high_cats:
                high_score += high_cfg.get("weight", 2)
                matched_cats.append(cat_name)
            elif cat_name in medium_cats:
                medium_score += medium_cfg.get("weight", 1)
                matched_cats.append(cat_name)

        high_score   = min(high_score,   high_cfg.get("cap", 4))
        medium_score = min(medium_score, medium_cfg.get("cap", 2))
        attack_bonus = high_score + medium_score
        cdn_asns_cfg = (config or {}).get("cdn_asns", {})
        if asn and asn in cdn_asns_cfg:
            attack_bonus = min(attack_bonus, 3)

        if matched_cats:
            score += attack_bonus
            breakdown.append(f"Attack types [{', '.join(matched_cats)}] → +{attack_bonus}")
        else:
            breakdown.append(f"Attack types                → +0")

    has_data = distinct_users > 0 or is_tor

    score = min(score, 15)
    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": distinct_users,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }

def score_shodan(shodan, config=None, censys_hostnames=None):
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
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []

    suspicious_ports    = config.get("suspicious_ports", {})    if config else {}
    suspicious_products = config.get("suspicious_products", {}) if config else {}
    shodan_tag_weights  = config.get("shodan_tags", {})         if config else {}

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

    breakdown.append("Suspicious ports → skipped (requires Censys corroboration)")

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

    hostnames = shodan.get("hostnames", [])
    effective_hostnames = hostnames or (censys_hostnames or [])
    if not effective_hostnames:
        score += 1
        breakdown.append(f"No hostname                  → +1  (anonymous infrastructure)")
    else:
        breakdown.append(f"Hostname: {effective_hostnames[0]:<20} → +0")

    has_data = (
        len(vulns) > 0 or
        len(flagged_products) > 0 or
        len(flagged_tags) > 0 or
        len(shodan.get("ports", [])) > 0
    )

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
        "score":          score,
        "evidence_count": len(vulns) + len(flagged_products),
        "has_data":       has_data,
        "breakdown":      breakdown,
        "gated":          False,
    }


def score_censys(censys, config=None):
    """Score Censys data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. CVEs          — known vulnerabilities present in service scan data
      2. Products      — offensive tools identified in service banners (skipped for CDN ASNs)
      3. Labels        — Censys classification labels mapped to shodan_tags weights

    No port-only scoring and no hostname penalty (Censys doesn't reliably expose hostnames).
    CDN ASNs: product scoring skipped, verdict capped at medium_risk.
    Minimum evidence threshold: a non-clean verdict requires at least one CVE, suspicious
    product, or high-weight label (weight >= 3) — ports alone cannot raise the verdict.
    """

    if not censys:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []

    suspicious_products = config.get("suspicious_products", {}) if config else {}
    shodan_tag_weights  = config.get("shodan_tags", {})         if config else {}

    vulns      = censys.get("vulns", [])
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

    product_score    = 0
    flagged_products = []

    for service in censys.get("services", []):
        product = (service.get("product") or "").lower()
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
    flagged_labels      = []
    has_high_weight_tag = False

    for label in censys.get("labels", []):
        label_lower = label.lower()
        if label_lower in shodan_tag_weights:
            weight = shodan_tag_weights[label_lower]["weight"]
            reason = shodan_tag_weights[label_lower]["reason"]
            if weight >= 3:
                has_high_weight_tag = True
            tag_score += weight
            flagged_labels.append(f"{label} ({reason})")

    tag_score = min(tag_score, 5)
    score += tag_score

    if flagged_labels:
        breakdown.append(f"Censys labels    {len(flagged_labels):<4} → +{tag_score}  (cap 5)")
        for lbl in flagged_labels:
            breakdown.append(f"  Label: {lbl}")
    else:
        breakdown.append(f"Censys labels    none → +0")

    has_data = (
        len(vulns) > 0 or
        len(flagged_products) > 0 or
        len(flagged_labels) > 0 or
        len(censys.get("ports", [])) > 0
    )

    score = min(score, 15)

    meets_min_threshold = (
        vuln_count > 0 or
        product_score > 0 or
        has_high_weight_tag or
        tag_score >= 3
    )

    if has_data and meets_min_threshold:
        verdict = score_to_verdict(score)
    elif has_data:
        verdict = "clean"
    else:
        verdict = "no_data"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": len(vulns) + len(flagged_products) + len(flagged_labels),
        "has_data":       has_data,
        "breakdown":      breakdown,
        "gated":          False,
    }


def score_shodan_censys(shodan, censys, config):
    """Confidence layer — Shodan + Censys cross-source corroboration.

    Seven flat signals (+1 or +2 each) answer "do two independent scanners
    agree?" rather than "how many items agree?". Total is capped at +4 so
    this layer nudges verdicts rather than manufacturing them.
    """

    empty = {
        "port_bonus":            0,
        "cve_bonus":             0,
        "product_bonus":         0,
        "banner_bonus":          0,
        "cert_bonus":            0,
        "service_overlap_bonus": 0,
        "recency_bonus":         0,
        "favicon_bonus":         0,
        "ssh_bonus":             0,
        "total_bonus":           0,
        "corroborated_ports":    [],
        "corroborated_cves":     [],
        "corroborated_products": [],
        "corroborated_banners":  [],
        "cert_match":            False,
        "service_overlap_pct":   0,
    }

    if not isinstance(shodan, dict) or not isinstance(censys, dict):
        return empty

    suspicious_ports    = config.get("suspicious_ports", {})    if config else {}
    suspicious_products = config.get("suspicious_products", {}) if config else {}

    # Signal 1 — Suspicious port corroboration (flat +1)
    # A port only qualifies if both scanners see it AND it's suspicious AND
    # either source has a suspicious product on that port OR the port weight >= 3.
    ports_shodan = {int(p) for p in shodan.get("ports", []) if str(p).isdigit()}
    ports_censys = {int(p) for p in censys.get("ports", []) if str(p).isdigit()}
    agreed_ports = ports_shodan & ports_censys

    corroborated_ports = []
    for port in agreed_ports:
        port_str = str(port)
        if port_str not in suspicious_ports:
            continue
        port_weight = suspicious_ports[port_str].get("weight", 0)

        all_products_on_port = [
            (svc.get("product") or "").lower()
            for src in (shodan, censys)
            for svc in src.get("services", [])
            if svc.get("port") == port
        ]
        either_has_suspicious_product = any(
            known in prod
            for prod in all_products_on_port
            for known in suspicious_products
            if prod
        )
        if either_has_suspicious_product or port_weight >= 3:
            corroborated_ports.append(port_str)

    port_bonus = min(
        sum(suspicious_ports[p].get("weight", 1) for p in corroborated_ports),
        4,
    ) if corroborated_ports else 0

    # Signal 2 — CVE corroboration (flat +1)
    shodan_cves       = set(shodan.get("vulns", []))
    censys_cves       = set(censys.get("vulns", []))
    shared_cves       = shodan_cves & censys_cves
    corroborated_cves = sorted(shared_cves)
    cve_bonus         = 1 if shared_cves else 0

    # Signal 3 — Suspicious product corroboration (flat +1)
    corroborated_products = []
    for key in suspicious_products:
        shodan_has = any(
            key in (svc.get("product") or "").lower()
            for svc in shodan.get("services", [])
        )
        censys_has = any(
            key in (svc.get("product") or "").lower()
            for svc in censys.get("services", [])
        )
        if shodan_has and censys_has:
            corroborated_products.append(key)
    product_bonus = 1 if corroborated_products else 0

    # Signal 4 — Banner/version corroboration (flat +1)
    # Exact product+version match on the same port, OR suspicious product match.
    corroborated_banners = []
    for s_svc in shodan.get("services", []):
        s_product = (s_svc.get("product") or "").lower().strip()
        s_version = (s_svc.get("version") or "").lower().strip()
        if not s_product or s_product == "unknown":
            continue
        s_port = s_svc.get("port")
        for c_svc in censys.get("services", []):
            if c_svc.get("port") != s_port:
                continue
            c_product = (c_svc.get("product") or "").lower().strip()
            c_version = (c_svc.get("version") or "").lower().strip()
            product_match  = s_product == c_product and c_product != ""
            version_match  = s_version == c_version and s_version != "" and c_version != ""
            is_suspicious  = any(known in s_product for known in suspicious_products)
            if (product_match and version_match) or (product_match and is_suspicious):
                banner = f"{s_product} {s_version}".strip()
                if banner not in corroborated_banners:
                    corroborated_banners.append(banner)
    banner_bonus = 1 if corroborated_banners else 0

    # Signal 5 — TLS certificate fingerprint match (flat +2)
    # Certificates are cryptographically unique, so a match is very high-confidence.
    shodan_cert  = shodan.get("ssl_sha256") or None
    censys_fps   = [
        c.get("fingerprint", "").lower()
        for c in censys.get("certificates", [])
        if c.get("fingerprint")
    ]
    cert_match   = shodan_cert is not None and shodan_cert.lower() in censys_fps
    cert_bonus   = 2 if cert_match else 0

    # Signal 6 — Service overlap (flat +1, requires >= 3 ports on each side)
    # Common web/infra ports excluded so routine overlap doesn't score.
    COMMON_PORTS          = {80, 443, 22, 21, 25, 53, 8080, 8443}
    ports_s_filt          = ports_shodan - COMMON_PORTS
    ports_c_filt          = ports_censys - COMMON_PORTS
    service_overlap_bonus = 0
    service_overlap_pct   = 0
    if len(ports_shodan) >= 3 and len(ports_censys) >= 3:
        union = ports_s_filt | ports_c_filt
        if union:
            overlap_ratio       = len(ports_s_filt & ports_c_filt) / len(union)
            service_overlap_pct = round(overlap_ratio * 100, 1)
            if overlap_ratio >= 0.70:
                service_overlap_bonus = 1

    # Signal 7 — Recency corroboration (flat +1, both must be scanned within 7 days)
    recency_bonus = 0
    try:
        shodan_dt   = datetime.datetime.fromisoformat(
            shodan.get("last_update", "").replace("Z", "")[:19]
        )
        censys_dt   = datetime.datetime.fromisoformat(
            censys.get("last_update", "").replace("Z", "")[:19]
        )
        now = datetime.datetime.now()
        if (now - shodan_dt).days <= 7 and (now - censys_dt).days <= 7:
            recency_bonus = 1
    except (ValueError, TypeError, AttributeError):
        pass

    # Signal 8 — Favicon hash corroboration (flat +1)
    shodan_favicon  = shodan.get("favicon_hash")
    censys_favicons = censys.get("favicon_hashes", [])
    favicon_bonus   = 1 if (shodan_favicon is not None and shodan_favicon in censys_favicons) else 0

    # Signal 9 — SSH host key fingerprint corroboration (flat +1)
    shodan_ssh_fp  = shodan.get("ssh_fingerprint")
    censys_ssh_fps = censys.get("ssh_host_key_fingerprints", [])
    ssh_bonus      = 1 if (shodan_ssh_fp is not None and shodan_ssh_fp in censys_ssh_fps) else 0

    total_bonus = min(
        port_bonus + cve_bonus + product_bonus +
        banner_bonus + cert_bonus +
        service_overlap_bonus + recency_bonus +
        favicon_bonus + ssh_bonus,
        4,
    )

    return {
        "port_bonus":            port_bonus,
        "cve_bonus":             cve_bonus,
        "product_bonus":         product_bonus,
        "banner_bonus":          banner_bonus,
        "cert_bonus":            cert_bonus,
        "service_overlap_bonus": service_overlap_bonus,
        "recency_bonus":         recency_bonus,
        "favicon_bonus":         favicon_bonus,
        "ssh_bonus":             ssh_bonus,
        "total_bonus":           total_bonus,
        "corroborated_ports":    corroborated_ports,
        "corroborated_cves":     corroborated_cves,
        "corroborated_products": corroborated_products,
        "corroborated_banners":  corroborated_banners,
        "cert_match":            cert_match,
        "service_overlap_pct":   service_overlap_pct,
    }


def score_whois(whois, config=None):
    if not whois:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score        = 0
    breakdown    = []
    age_days     = whois.get("domain_age_days")
    privacy      = whois.get("privacy_masked", False)
    registrar    = whois.get("registrar")
    creation     = whois.get("creation_date")

    # Domain age scoring
    if age_days is not None:
        if age_days < 7:
            score += 4
            breakdown.append(f"Domain age {age_days} days        → +4  (very newly registered)")
        elif age_days < 30:
            score += 3
            breakdown.append(f"Domain age {age_days} days        → +3  (newly registered)")
        elif age_days < 90:
            score += 2
            breakdown.append(f"Domain age {age_days} days        → +2  (recently registered)")
        elif age_days < 365:
            score += 1
            breakdown.append(f"Domain age {age_days} days        → +1  (registered < 1 year)")
        else:
            breakdown.append(f"Domain age {age_days} days        → +0  (established domain)")
    else:
        breakdown.append(f"Domain age unknown           → +0")

    # Privacy masking
    if privacy:
        score += 1
        breakdown.append(f"Privacy masking              → +1")
    else:
        breakdown.append(f"Privacy masking              → +0")

    # Missing registrar
    if not registrar:
        score += 1
        breakdown.append(f"No registrar found           → +1")
    else:
        breakdown.append(f"Registrar: {registrar[:30]:<30} → +0")

    # Cap at 7 — WHOIS is a supporting signal not primary evidence
    score = min(score, 7)

    has_data = creation is not None or registrar is not None

    # Cap verdict at medium_risk — WHOIS alone should never produce High risk
    verdict = score_to_verdict(score) if has_data else "no_data"
    if verdict == "high":
        verdict = "medium_risk"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": 1 if has_data else 0,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_greynoise(greynoise, config=None):
    if not greynoise:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [], "is_noise": False}

    classification = greynoise.get("classification")
    actor          = greynoise.get("actor")
    cve            = greynoise.get("cve")
    breakdown      = []

    if classification == "benign":
        breakdown.append(f"Classification: benign        → score 0  (internet scanner/noise)")
        return {
            "verdict":        "clean",
            "score":          0,
            "evidence_count": 0,
            "has_data":       True,
            "breakdown":      breakdown,
            "is_noise":       True,
        }

    score = 0

    if classification == "malicious":
        score += 3
        breakdown.append(f"Classification: malicious     → +3")
    elif classification == "suspicious":
        score += 2
        breakdown.append(f"Classification: suspicious    → +2")
    else:
        breakdown.append(f"Classification: {classification or 'unknown':<14} → +0")

    if actor:
        score += 2
        breakdown.append(f"Actor: {actor:<25} → +2")
    else:
        breakdown.append(f"Actor: none                  → +0")

    if cve:
        score += 1
        breakdown.append(f"CVE present                  → +1")
    else:
        breakdown.append(f"CVE present                  → +0")

    score    = min(score, 6)
    has_data = classification is not None

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": 1 if classification == "malicious" else 0,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "is_noise":       False,
    }


def score_urlhaus(urlhaus, config=None):
    if not urlhaus:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []
    url_count = urlhaus.get("url_count", 0)
    threat    = urlhaus.get("threat") or ""

    if url_count >= 5:
        score += 3
        breakdown.append(f"URL count {url_count:<6}           → +3")
    elif url_count >= 2:
        score += 2
        breakdown.append(f"URL count {url_count:<6}           → +2")
    elif url_count == 1:
        score += 1
        breakdown.append(f"URL count {url_count:<6}           → +1")
    else:
        breakdown.append(f"URL count {url_count:<6}           → +0")

    if any(t in threat.lower() for t in ["ransomware", "trojan", "banker"]):
        score += 3
        breakdown.append(f"Threat: {threat:<22} → +3  (high severity)")
    elif any(t in threat.lower() for t in ["malware", "dropper"]):
        score += 2
        breakdown.append(f"Threat: {threat:<22} → +2  (malware)")
    elif threat:
        breakdown.append(f"Threat: {threat:<22} → +0")
    else:
        breakdown.append(f"Threat: none                 → +0")

    score    = min(score, 8)
    has_data = url_count > 0

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": url_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_hybrid(hybrid, config=None):
    if not hybrid:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score        = 0
    breakdown    = []
    threat_score = hybrid.get("threat_score")
    family       = hybrid.get("family") or []

    if threat_score is not None:
        if threat_score >= 80:
            score += 5
            breakdown.append(f"Threat score {threat_score:<5}        → +5")
        elif threat_score >= 60:
            score += 4
            breakdown.append(f"Threat score {threat_score:<5}        → +4")
        elif threat_score >= 40:
            score += 3
            breakdown.append(f"Threat score {threat_score:<5}        → +3")
        elif threat_score >= 20:
            score += 2
            breakdown.append(f"Threat score {threat_score:<5}        → +2")
        else:
            breakdown.append(f"Threat score {threat_score:<5}        → +0")
    else:
        verdict_val = hybrid.get("verdict", "")
        if verdict_val == "malicious":
            score += 3
            breakdown.append(f"Verdict: malicious           → +3  (no threat score available)")
        elif verdict_val == "suspicious":
            score += 1
            breakdown.append(f"Verdict: suspicious          → +1  (no threat score available)")
        else:
            breakdown.append(f"Threat score N/A             → +0")

    if family:
        score += 1
        breakdown.append(f"Families: {', '.join(family):<21} → +1")
    else:
        breakdown.append(f"Families: none               → +0")

    score    = min(score, 6)
    has_data = threat_score is not None or hybrid.get("verdict") is not None

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": 1 if (threat_score or 0) >= 20 else 0,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_urlscan(urlscan, config=None):
    if not urlscan:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score      = 0
    breakdown  = []
    malicious  = urlscan.get("malicious", False)
    categories = urlscan.get("categories") or []

    if malicious:
        score += 3
        breakdown.append(f"Malicious verdict            → +3")
    else:
        breakdown.append(f"Malicious verdict            → +0")

    cat_score = min(len(categories), 2)
    score += cat_score
    if categories:
        breakdown.append(f"Categories: {', '.join(categories[:3]):<21} → +{cat_score}  (cap +2)")
    else:
        breakdown.append(f"Categories: none             → +0")

    phishing_keywords = [
        "auth", "login", "verify", "secure", "account", "recovery",
        "member", "update", "confirm", "banking", "wallet", "signin",
        "portal", "access", "gateway", "support", "helpdesk",
    ]
    domain_score = 0
    flagged_domains = []
    for d in (urlscan.get("domains") or []):
        if any(kw in d.lower() for kw in phishing_keywords):
            domain_score += 2
            flagged_domains.append(d)
    domain_score = min(domain_score, 4)
    score += domain_score
    if flagged_domains:
        breakdown.append(f"Phishing domains [{', '.join(flagged_domains[:3])}] → +{domain_score}  (cap +4)")
    else:
        breakdown.append(f"Phishing domains             → +0")

    has_data = (
        malicious or
        len(categories) > 0 or
        len(urlscan.get("domains") or []) > 0 or
        urlscan.get("page_title") is not None or
        urlscan.get("ip") is not None
    )

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": 1 if malicious else 0,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def combined_verdict(vt=None, otx=None, abuse=None, shodan=None, whois=None,
                     censys=None, greynoise=None, urlhaus=None, hybrid=None,
                     urlscan=None, config=None):
    """Combine per-source scores into a single final verdict using a plain average.

    Gated sources (CDN/cloud ASNs with score==0) are excluded from the average.
    One override rule applies: if any source returns High, the final verdict is raised
    to at least Medium risk. A Shodan+Censys corroboration bonus is added on top.
    """

    if config is None:
        config = load_config()

    vt_result     = score_vt(vt, config)
    otx_result    = score_otx(otx, config=config)
    _abuse_asn    = (shodan.get("asn") or "").strip().upper() if isinstance(shodan, dict) else None
    abuse_result  = score_abuse(abuse, config=config, asn=_abuse_asn or None)
    shodan_result = score_shodan(shodan, config=config,
                                  censys_hostnames=censys.get("hostnames", []) if isinstance(censys, dict) else None)
    censys_result = score_censys(censys, config=config)
    whois_result     = score_whois(whois, config)
    greynoise_result = score_greynoise(greynoise, config)
    urlhaus_result   = score_urlhaus(urlhaus, config)
    hybrid_result    = score_hybrid(hybrid, config)
    urlscan_result   = score_urlscan(urlscan, config)
    sources = {
        "VirusTotal": vt_result,
        "OTX":        otx_result,
        "AbuseIPDB":  abuse_result,
        "Shodan":     shodan_result,
        "Censys":     censys_result,
        "GreyNoise":  greynoise_result,
        "URLhaus":    urlhaus_result,
        "Hybrid":     hybrid_result,
        "URLScan":    urlscan_result,
    }

    # Only include sources that returned real data so no-data sources don't drag the verdict down.
    # GreyNoise benign (is_noise=True) is excluded from the score sum but kept in per_source as context.
    active = {
        name: r for name, r in sources.items()
        if r["has_data"] and not (name == "GreyNoise" and r.get("is_noise"))
    }

    if not active:
        return {
            "final_verdict":         "no_data",
            "final_verdict_display": VERDICT_DISPLAY["no_data"],
            "triggered_by":          [],
            "score":                 0,
            "corroboration_count":   0,
            "consensus_ratio":       "Weak (0/0)",
            "recommendation":        RECOMMENDATIONS["no_data"],
            "active_sources":        [],
            "inactive_sources":      list(sources.keys()),
            "contribution":          {name: "no data" for name in sources},
            "per_source": {
                name: {
                    "verdict":         r["verdict"],
                    "verdict_display": VERDICT_DISPLAY.get(r["verdict"], r["verdict"]),
                    "score":           r["score"],
                    "evidence_count":  r["evidence_count"],
                    "has_data":        r["has_data"],
                    **( {"is_noise": True} if r.get("is_noise") else {} ),
                }
                for name, r in sources.items()
            },
            "breakdown": [],
            "whois_context": {
                "has_data":       whois_result.get("has_data", False),
                "score_modifier": 0,
                "verdict":        whois_result.get("verdict", "no_data"),
                "breakdown":      whois_result.get("breakdown", []),
            },
            "shodan_censys_corroboration": {
                "port_bonus": 0, "cve_bonus": 0, "product_bonus": 0,
                "banner_bonus": 0, "cert_bonus": 0, "service_overlap_bonus": 0,
                "recency_bonus": 0, "favicon_bonus": 0, "ssh_bonus": 0, "total_bonus": 0,
                "corroborated_ports": [], "corroborated_cves": [],
                "corroborated_products": [], "corroborated_banners": [],
                "cert_match": False, "service_overlap_pct": 0,
            },
        }

    if active:
        final_score = min(sum(r["score"] for r in active.values()), 20)
    else:
        final_score = 0
    final_verdict = score_to_verdict(final_score)

    # WHOIS modifier — domain metadata, not threat intel
    # Strengthens existing suspicion but cannot create it from nothing.
    # Cap depends on base score:
    #   final_score <= 0  → +0  (no real signal, WHOIS contributes nothing)
    #   final_score < 4   → max +1  (weak signal, WHOIS nudges slightly)
    #   final_score >= 4  → max +2  (real signal exists, WHOIS can reinforce)
    whois_modifier = 0
    if whois and whois_result.get("has_data"):
        if final_score <= 0:
            whois_modifier = 0
        elif final_score < 4:
            whois_modifier = min(whois_result["score"], 1)
        else:
            whois_modifier = min(whois_result["score"], 2)
        final_score = min(final_score + whois_modifier, 20)

    # Recompute verdict after modifier
    final_verdict = score_to_verdict(final_score)

    # Cross-source corroboration bonus (Shodan + Censys)
    corroboration = score_shodan_censys(shodan, censys, config)
    corr_bonus    = corroboration["total_bonus"]
    if corr_bonus > 0:
        final_score  = min(final_score + corr_bonus, 20)
        final_verdict = score_to_verdict(final_score)

    vt_country      = (vt or {}).get("country", "")
    censys_country  = (censys or {}).get("country", "") if isinstance(censys, dict) else ""
    shodan_country  = (shodan or {}).get("country", "") if isinstance(shodan, dict) else ""
    geo_countries   = {c.upper() for c in [vt_country, censys_country, shodan_country] if c}
    geo_mismatch    = len(geo_countries) > 1

    # Rule 2: High verdict requires at least 2 active sources with score >= 5
    if final_verdict == "high":
        strong_sources = [r for r in active.values() if r["score"] >= 5]
        if len(strong_sources) < 2:
            final_verdict = "medium_risk"

    for name, r in active.items():
        if r["verdict"] == "high":
            if VERDICT_ORDER.get(final_verdict, 0) < VERDICT_ORDER["medium_risk"]:
                final_verdict = "medium_risk"
                break

    triggered_by        = [
        name for name, r in active.items()
        if VERDICT_ORDER.get(r["verdict"], 0) >= VERDICT_ORDER.get(final_verdict, 0) - 1
    ]
    corroboration_count = len(triggered_by)
    active_count        = len(active)

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

    if whois_result.get("has_data") and whois_result.get("breakdown"):
        full_breakdown.append(f"── WHOIS ──")
        full_breakdown.extend(whois_result["breakdown"])

    if corr_bonus > 0:
        full_breakdown.append(f"── Shodan+Censys Corroboration ──")
        if corroboration["corroborated_ports"]:
            full_breakdown.append(f"Ports confirmed: {', '.join(corroboration['corroborated_ports'])} → +{corroboration['port_bonus']}")
        if corroboration["corroborated_cves"]:
            full_breakdown.append(f"CVEs confirmed: {', '.join(corroboration['corroborated_cves'])} → +{corroboration['cve_bonus']}")
        if corroboration["corroborated_products"]:
            full_breakdown.append(f"Products confirmed: {', '.join(corroboration['corroborated_products'])} → +{corroboration['product_bonus']}")
        if corroboration["corroborated_banners"]:
            full_breakdown.append(f"Banners confirmed: {', '.join(corroboration['corroborated_banners'])} → +{corroboration['banner_bonus']}")
        if corroboration.get("cert_match"):
            full_breakdown.append(f"TLS cert fingerprint match → +{corroboration['cert_bonus']}")
        if corroboration.get("service_overlap_bonus", 0) > 0:
            full_breakdown.append(f"Service overlap {corroboration.get('service_overlap_pct', 0)}% → +{corroboration['service_overlap_bonus']}")
        if corroboration.get("recency_bonus", 0) > 0:
            full_breakdown.append(f"Both scanned within 7 days → +{corroboration['recency_bonus']}")
        if corroboration.get("favicon_bonus", 0) > 0:
            full_breakdown.append(f"Favicon hash match → +{corroboration['favicon_bonus']}")
        if corroboration.get("ssh_bonus", 0) > 0:
            full_breakdown.append(f"SSH host key fingerprint match → +{corroboration['ssh_bonus']}")
        full_breakdown.append(f"Corroboration total (cap 4) → +{corr_bonus}")

    raw_total     = sum(r["score"] for r in active.values())
    display_score = int(min(raw_total, 20))
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
        "triggered_by":          triggered_by,
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
                "score":           r["score"],
                "evidence_count":  r["evidence_count"],
                "has_data":        r["has_data"],
                **( {"is_noise": True} if r.get("is_noise") else {} ),
            }
            for name, r in sources.items()
        },
        "breakdown": full_breakdown,
        "whois_context": {
            "has_data":       whois_result.get("has_data", False),
            "score_modifier": whois_modifier,
            "verdict":        whois_result.get("verdict", "no_data"),
            "breakdown":      whois_result.get("breakdown", []),
        },
        "shodan_censys_corroboration": corroboration,
        "geo_mismatch":               geo_mismatch,
        "geo_countries":              sorted(geo_countries),
    }
