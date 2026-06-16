import datetime

# Combined verdict

def combined_verdict(vt, otx, abuse=None):

    score     = 0
    breakdown = []

    # VirusTotal signals

    if vt:

        # Malicious count
        malicious = vt.get("malicious", 0)

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
        trusted_vendors = [
            "Kaspersky", "CrowdStrike", "Sophos", "BitDefender",
            "ESET", "Palo Alto Networks", "Microsoft", "Symantec"
        ]

        trusted_hits   = 0
        untrusted_hits = 0

        for v in vt.get("malicious_vendors", []):
            if v["vendor"] in trusted_vendors:
                trusted_hits += 1
            else:
                untrusted_hits += 1

        trusted_points   = min(trusted_hits * 2, 4)
        untrusted_points = min(untrusted_hits * 1, 2)

        score += trusted_points
        score += untrusted_points

        if trusted_hits > 0:
            breakdown.append(f"Trusted vendors  {trusted_hits:<5} → +{trusted_points}  (capped at 4)")
        if untrusted_hits > 0:
            breakdown.append(f"Untrusted vendors {untrusted_hits:<4} → +{untrusted_points}  (capped at 2)")

        # Bad tags
        bad_tags = [
            "tor", "self-signed", "malware", "c2", "ransomware",
            "botnet", "phishing", "scanner", "brute-force", "proxy"
        ]

        tag_points  = 0
        found_tags  = []

        for tag in vt.get("tags", []):
            if tag in bad_tags:
                tag_points += 1
                found_tags.append(tag)

        tag_score = min(tag_points, 3)
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

        # Pulse count
        pulse_count = otx.get("pulse_count", 0)

        if pulse_count >= 10:
            score += 2
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +2  (widely tracked)")
        elif pulse_count >= 1:
            score += 1
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +1")
        else:
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +0")

        # OTX reputation
        reputation = otx.get("reputation", 0)

        if reputation < 0:
            score += 1
            breakdown.append(f"OTX reputation {reputation:<5}    → +1  (negative)")
        else:
            breakdown.append(f"OTX reputation {reputation:<5}    → +0")

        # Pulse recency
        pulse_details      = otx.get("pulse_details", [])
        recent_pulse_found = False

        for p in pulse_details:
            pulse_name = p.get("name", "")
            if "2026" in pulse_name or "2025" in pulse_name:
                recent_pulse_found = True

        if recent_pulse_found:
            score += 1
            breakdown.append(f"Recent pulse (2025/2026)        → +1")
        else:
            breakdown.append(f"Recent pulse (2025/2026)        → +0")

        # Passive DNS recency
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

        if latest_pdns:
            days_since = (datetime.datetime.now() - latest_pdns).days
            if days_since <= 30:
                score += 1
                breakdown.append(f"Passive DNS last seen {days_since} days ago  → +1  (active infrastructure)")
            else:
                breakdown.append(f"Passive DNS last seen {days_since} days ago  → +0")
        else:
            breakdown.append(f"Passive DNS last seen unknown   → +0")

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
