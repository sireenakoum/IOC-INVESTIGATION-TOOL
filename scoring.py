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
 
    return {
        "tier1":        tier1,
        "tier2":        tier2,
        "alias_lookup": alias_lookup,
        "scoring":      scoring,
        "tag_weights":  tag_weights,
        "tag_cap":      tag_cap,
    }
 
 
def resolve_vendor(raw_name, alias_lookup):
    return alias_lookup.get(raw_name.lower(), raw_name.lower())

# Combined verdict
def combined_verdict(vt, otx, abuse=None, config=None):

    if config is None:
        config = load_config()
        
    score        = 0
    breakdown    = []
    vt_malicious = 0  # tracked across blocks to gate OTX pulse scoring

    # VirusTotal signals

    if vt:

        # Malicious count
        malicious    = vt.get("malicious", 0)
        vt_malicious = malicious

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

        # Suspicious count
        suspicious = vt.get("suspicious", 0)

        if suspicious >= 3:
            score += 1
            breakdown.append(f"Suspicious count {suspicious:<4} → +1")
        else:
            breakdown.append(f"Suspicious count {suspicious:<4} → +0")

        # Vendor reliability 
        trusted_hits   = 0
        untrusted_hits = 0
        tier1_hits = 0
        tier2_hits = 0
        tier3_hits = 0

        for v in vt.get("malicious_vendors", []):
            canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
            if canonical in config["tier1"]:
                tier1_hits += 1
            elif canonical in config["tier2"]:
                tier2_hits += 1
            else:
                tier3_hits += 1

        scoring      = config["scoring"]
        tier1_points = min(tier1_hits * scoring["tier1_points"], scoring["tier1_cap"])
        tier2_points = min(tier2_hits * scoring["tier2_points"], scoring["tier2_cap"])
        tier3_points = min(tier3_hits * scoring["tier3_points"], scoring["tier3_cap"])

        score += tier1_points + tier2_points + tier3_points

        if tier1_hits > 0:
            breakdown.append(f"Tier 1 vendors   {tier1_hits:<5} → +{tier1_points}  (capped at {scoring['tier1_cap']})")
        if tier2_hits > 0:
            breakdown.append(f"Tier 2 vendors   {tier2_hits:<5} → +{tier2_points}  (capped at {scoring['tier2_cap']})")
        if tier3_hits > 0:
            breakdown.append(f"Tier 3 vendors   {tier3_hits:<5} → +{tier3_points}  (capped at {scoring['tier3_cap']})")

        # Bad tags

        tag_points  = 0
        found_tags  = []

        for tag in vt.get("tags", []):
            weight = config["tag_weights"].get(tag.lower(), 0)
            if weight > 0:
                tag_points += weight
                found_tags.append(tag)

        tag_score = min(tag_points, config["tag_cap"])
        score += tag_score

        if len(found_tags) > 0:
            breakdown.append(f"Bad tags {', '.join(found_tags):<15} → +{tag_score}  (capped at 3)")
        else:
            breakdown.append(f"Bad tags none          → +0")

        # Recency — only counts if malicious detections exist
        if vt.get("last_scan_date") and malicious > 0:

            now       = datetime.datetime.now()
            scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
            days_ago  = (now - scan_date).days

            if days_ago <= 7:
                score += 2
                breakdown.append(f"Last scanned {days_ago} days ago      → +2  (recent malicious activity)")
            elif days_ago <= 30:
                score += 1
                breakdown.append(f"Last scanned {days_ago} days ago      → +1  (recent)")
            elif days_ago > 180:
                score -= 1
                breakdown.append(f"Last scanned {days_ago} days ago      → -1  (old)")
            else:
                breakdown.append(f"Last scanned {days_ago} days ago      → +0")
        else:
            if vt.get("last_scan_date"):
                breakdown.append(f"Recency skipped — no malicious detections → +0")

    # OTX signals

    if otx:

        # Pulse count — only scored if VT has at least one malicious detection
        pulse_count = otx.get("pulse_count", 0)

        if vt_malicious >= 1:
            if pulse_count >= 10:
                score += 2
                breakdown.append(f"OTX pulses {pulse_count:<8}      → +2  (widely tracked)")
            elif pulse_count >= 1:
                score += 1
                breakdown.append(f"OTX pulses {pulse_count:<8}      → +1")
            else:
                breakdown.append(f"OTX pulses {pulse_count:<8}      → +0")
        else:
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +0  (skipped — no VT malicious detections)")

        # OTX reputation (independent of VT — not gated)
        reputation = otx.get("reputation", 0)

        if reputation < 0:
            score += 1
            breakdown.append(f"OTX reputation {reputation:<5}    → +1  (negative)")
        else:
            breakdown.append(f"OTX reputation {reputation:<5}    → +0")

        # Pulse recency — only scored if VT has at least one malicious detection
        pulse_details      = otx.get("pulse_details", [])
        recent_pulse_found = False

        for p in pulse_details:
            pulse_name = p.get("name", "")
            if "2026" in pulse_name or "2025" in pulse_name:
                recent_pulse_found = True

        if vt_malicious >= 1:
            if recent_pulse_found:
                score += 1
                breakdown.append(f"Recent pulse (2025/2026)        → +1")
            else:
                breakdown.append(f"Recent pulse (2025/2026)        → +0")
        else:
            breakdown.append(f"Recent pulse (2025/2026)        → +0  (skipped — no VT malicious detections)")

        # Passive DNS recency — only scored if VT has at least one malicious detection
        pdns = otx.get("passive_dns", [])
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

        if vt_malicious >= 1:
            if latest_pdns:
                days_since = (datetime.datetime.now() - latest_pdns).days
                if days_since <= 30:
                    score += 1
                    breakdown.append(f"Passive DNS last seen {days_since} days ago  → +1  (active infrastructure)")
                else:
                    breakdown.append(f"Passive DNS last seen {days_since} days ago  → +0")
            else:
                breakdown.append(f"Passive DNS last seen unknown   → +0")
        else:
            breakdown.append(f"Passive DNS last seen N/A       → +0  (skipped — no VT malicious detections)")

    # AbuseIPDB signals

    if abuse:

        abuse_score    = abuse.get("abuse_score", 0)
        distinct_users = abuse.get("distinct_users", 0)
        is_tor         = abuse.get("is_tor", False)

        if abuse_score >= 80:
            score += 3
            breakdown.append(f"AbuseIPDB score  {abuse_score:<5}    → +3  (high confidence)")
        elif abuse_score >= 40:
            score += 2
            breakdown.append(f"AbuseIPDB score  {abuse_score:<5}    → +2  (moderate)")
        elif abuse_score >= 10:
            score += 1
            breakdown.append(f"AbuseIPDB score  {abuse_score:<5}    → +1  (low risk)")
        else:
            breakdown.append(f"AbuseIPDB score  {abuse_score:<5}    → +0")

        if distinct_users >= 50:
            score += 2
            breakdown.append(f"Distinct reporters {distinct_users:<3}      → +2  (widely reported)")
        elif distinct_users >= 10:
            score += 1
            breakdown.append(f"Distinct reporters {distinct_users:<3}      → +1")
        else:
            breakdown.append(f"Distinct reporters {distinct_users:<3}      → +0")

        if is_tor:
            score += 1
            breakdown.append(f"Tor exit node                   → +1")
        else:
            breakdown.append(f"Tor exit node                   → +0")

    # Final verdict

    if score == 0:
        label = "✅ Clean"
    elif score <= 2:
        label = "⚠️  Suspicious"
    elif score <= 4:
        label = "🟡 Low risk"
    elif score <= 7:
        label = "🟠 Medium risk"
    else:
        label = "🔴 High risk"

    return {
        "verdict":   label,
        "score":     score,
        "breakdown": breakdown
    }
