import datetime
import re

from .enrichment import get_known_entities
from .app_config import load_config as _load_raw_config

def humanize_recency(dt, now=None):
    now = now or datetime.datetime.now()
    seconds = (now - dt).total_seconds()
    if seconds < 3600:
        mins = max(1, int(seconds // 60))
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = int(seconds // 86400)
    if days < 14:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return f"on {dt.strftime('%Y-%m-%d')}"

def load_config():
    """Build the processed config dict consumed by score_vt/score_otx/etc.

    Sources the raw nested config from the DB-backed app_config store (see
    sources/app_config.py) — config.json/config.seed.json is no longer read
    at runtime, only used as the one-time import source. This function keeps
    doing the same transformation it always did (lowercased tier1/tier2/
    noise_tags sets, alias_lookup, flattened tag_weights): downstream
    consumers expect that processed shape, not the raw one app_config.
    load_config() returns.
    """
    config = _load_raw_config()

    try:
        scoring   = config["_meta"]["scoring"]
        aliases   = config.get("vt_engine_name_aliases", {})
        tier1_raw = config["tier1"]["vendors"]
        tier2_raw = config["tier2"]["vendors"]
    except KeyError as e:
        raise RuntimeError(f"app_config DB is missing required key: {e.args[0]!r} — run scripts/import_config_to_db.py") from e

    # Build alias lookup: vt_engine_name (lower) → canonical name (lower)
    alias_lookup = {}
    for canonical, vt_names in aliases.items():
        if isinstance(vt_names, list):
            for vt_name in vt_names:
                alias_lookup[vt_name.lower()] = canonical.lower()

    tier1 = set(v.lower() for v in tier1_raw)
    tier2 = set(v.lower() for v in tier2_raw)
    noise_tags = {t.lower() for t in config.get("noise_tags", [])}

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
        "noise_tags":   noise_tags,
        "alias_lookup": alias_lookup,
        "scoring":      scoring,
        "tag_weights":  tag_weights,
        "tag_cap":      tag_cap,
        "suspicious_ports":    suspicious_ports,
        "suspicious_products": suspicious_products,
        "shodan_tags":         shodan_tags,
        "cdn_asns":            cdn_asns,
        "cloud_hosting_asns":  cloud_hosting_asns,
        "vt_file_tags":             vt_file_tags,
        "abuseipdb_attack_weights": config.get("abuseipdb_attack_weights", {}),
        "vt_relations":         config.get("vt_relations", {}),
        "vt_comments":          config.get("vt_comments", {}),
        "vt_ratio_bonus":       config.get("vt_ratio_bonus", {}),
        "otx_malware_families": config.get("otx_malware_families", {}),
        "otx_attack_ids":       config.get("otx_attack_ids", {}),
        "otx_reputation":       config.get("otx_reputation", {}),
        "google_intel":         config.get("google_intel", {}),
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

# OTX pulse tags that indicate automated scanner/honeypot noise, not real threat intel.
# Sourced from the DB-backed config's "noise_tags" (single shared definition — otx.py
# imports this same constant instead of keeping its own hardcoded copy). Used as the
# default here so score_otx() still works when called without an explicit config.
NOISE_TAGS = load_config()["noise_tags"]

def score_to_verdict(score):
    # Normalize to int to match display_score = int(min(raw_total, 20)).
    # VT tier3_points (0.5 per hit) can produce float sums; without this,
    # 13.5 would map to "high" while the displayed score shows 13.
    score = int(score)
    if score <= 0:
        return "clean"
    elif score <= 3:
        return "suspicious"
    elif score <= 7:
        return "low_risk"
    elif score <= 11:
        return "medium_risk"
    else:
        return "high"


# Malicious/suspicious terms used to scan VT community-comment text (score_vt).
# Compiled with word boundaries — naive substring matching on short terms like
# "rat", "apt", "c2", "worm" produces false positives (e.g. "rat" inside
# "operator", "apt" inside "adaptation") — same bug class already fixed once
# in the enrichment matching, so it's built the same way here from the start.
MALICIOUS_COMMENT_KEYWORDS = [
    "malware", "trojan", "ransomware", "botnet", "backdoor",
    "c2", "c&c", "command and control", "ddos", "exploit",
    "phishing", "worm", "spyware", "rootkit", "keylogger",
    "dropper", "cryptominer", "exfiltration", "malicious",
    "compromised", "infected", "apt", "rat",
]
SUSPICIOUS_COMMENT_KEYWORDS = [
    "suspicious", "scam", "spam", "fraud", "abuse", "blacklisted",
    "flagged", "sketchy",
]

_MALICIOUS_COMMENT_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(kw) for kw in MALICIOUS_COMMENT_KEYWORDS) + r")\b",
    re.IGNORECASE,
)
_SUSPICIOUS_COMMENT_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(kw) for kw in SUSPICIOUS_COMMENT_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def evidence_count_to_findings_label(count):
    """Buckets raw evidence_count into a volume label, independent of
    risk scoring. First-pass thresholds — may need per-source tuning
    later once real distributions are visible across many scans, since
    evidence_count's natural range varies a lot by source (VT's
    malicious count can run much higher than OTX's _count)."""
    if count <= 0:
        return "No Findings"
    elif count <= 2:
        return "Low Risk Findings"
    elif count <= 9:
        return "Medium Risk Findings"
    else:
        return "High Risk Findings"


def evidence_count_to_findings_tier(count):
    """Returns the raw tier key ('none'/'low'/'medium'/'high') so the
    frontend can map it to a color independent of the risk verdict."""
    if count <= 0:
        return "none"
    elif count <= 2:
        return "low"
    elif count <= 9:
        return "medium"
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
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

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
        tier1_hits >= 1 or
        tier2_hits >= 2 or
        malicious >= 4
)
        if vt.get("rescan_timed_out"):
            breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +0  (rescan still processing — recency not scored)")
        elif vt.get("self_rescanned"):
            breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +0  (rescanned via this tool just now — not a meaningful recency signal)")
        elif qualifies_for_recency:
            if days_ago <= 7:
                score += 2
                breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +2")
            elif days_ago <= 30:
                score += 1
                breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +1")
            elif days_ago > 180:
                breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +0  (old, not penalized)")
            else:
                breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +0")
        else:
            breakdown.append(f"Last scanned {humanize_recency(scan_date)}       → +0  (recency skipped — weak detections only)")
    else:
        if vt.get("last_scan_date"):
            breakdown.append(f"Recency skipped — no malicious detections")

    # Relations scoring — communicating and downloaded files with malicious detections
    relations = vt.get("relations") or {}
    comm_mal = 0
    dl_mal   = 0
    if relations:
        rel_cfg  = config.get("vt_relations", {})
        comm_mal = sum(1 for f in (relations.get("communicating_files") or []) if f.get("malicious", 0) > 0)
        dl_mal   = sum(1 for f in (relations.get("downloaded_files") or []) if f.get("malicious", 0) > 0)

        comm_score = (rel_cfg.get("communicating_malicious_2+", 2) if comm_mal >= 2
                      else rel_cfg.get("communicating_malicious_1", 1) if comm_mal == 1
                      else 0)
        dl_score   = (rel_cfg.get("downloaded_malicious_2+", 2) if dl_mal >= 2
                      else rel_cfg.get("downloaded_malicious_1", 1) if dl_mal == 1
                      else 0)

        relations_score = min(comm_score + dl_score, rel_cfg.get("combined_cap", 3))
        score += relations_score

        if comm_mal > 0:
            breakdown.append(f"Communicating files: {comm_mal} malicious → +{comm_score}")
        if dl_mal > 0:
            breakdown.append(f"Downloaded files: {dl_mal} malicious → +{dl_score}")
        else:
            breakdown.append(f"Downloaded files: 0 malicious → +0")

    # Community vote scoring — net positive votes signal community consensus on maliciousness
    comments = vt.get("comments") or []
    vote_modifier = 0
    if comments:
        comm_cfg  = config.get("vt_comments", {})
        total_net = sum(c.get("votes_positive", 0) - c.get("votes_negative", 0) for c in comments)

        high_min = comm_cfg.get("net_votes_high_min", 5)
        mid_min  = comm_cfg.get("net_votes_mid_min", 2)
        neg_max  = comm_cfg.get("net_votes_neg_max", -2)

        if total_net >= high_min:
            vote_modifier = comm_cfg.get("net_votes_high", 2)
            breakdown.append(f"Community comments: {len(comments)} found, net +{total_net} → +{vote_modifier}")
        elif total_net >= mid_min:
            vote_modifier = comm_cfg.get("net_votes_mid", 1)
            breakdown.append(f"Community comments: {len(comments)} found, net +{total_net} → +{vote_modifier}")
        elif total_net <= neg_max:
            vote_modifier = comm_cfg.get("net_votes_negative", -1)
            breakdown.append(f"Community comments: {len(comments)} found, net {total_net} → {vote_modifier}")
        else:
            vote_modifier = 0
            breakdown.append(f"Community comments: {len(comments)} found, net {total_net:+d} → +0  (neutral)")

        score = max(score + vote_modifier, 0)
    else:
        breakdown.append(f"Community comments: none                    → +0")

    # Comment text keyword scan — analyst comments often name the threat directly
    # ("this is a Cobalt Strike C2", "known ransomware dropper"). Vote totals alone
    # miss this; scan the actual comment text for malicious/suspicious terminology.
    # Uses word-boundary regex (not substring containment) — short terms like "rat"
    # or "apt" would otherwise false-positive inside words like "operator"/"adaptation".
    comment_score      = 0
    matched_malicious  = set()
    matched_suspicious = set()

    for c in comments:
        text = c.get("text", "")
        matched_malicious  |= {m.lower() for m in _MALICIOUS_COMMENT_RE.findall(text)}
        matched_suspicious |= {m.lower() for m in _SUSPICIOUS_COMMENT_RE.findall(text)}

    if matched_malicious:
        comment_score = 3
        breakdown.append(f"Comment keywords [{', '.join(sorted(matched_malicious))[:40]}] → +{comment_score}  (threat terminology)")
    elif matched_suspicious:
        comment_score = 1
        breakdown.append(f"Comment keywords [{', '.join(sorted(matched_suspicious))[:40]}] → +{comment_score}  (suspicious terminology)")
    elif comments:
        breakdown.append(f"Comment keywords none                → +0")

    comment_score = min(comment_score, 3)
    score += comment_score

    # Detection ratio bonus — consensus across all engines
    total_engines = (
        vt.get("malicious", 0) +
        vt.get("suspicious", 0) +
        vt.get("harmless", 0) +
        vt.get("undetected", 0)
    )
    if total_engines > 0 and vt.get("malicious", 0) > 0:
        ratio = vt["malicious"] / total_engines
        ratio_cfg = (config or {}).get("vt_ratio_bonus", {})
        if ratio >= ratio_cfg.get("threshold_high", 0.70):
            ratio_bonus = ratio_cfg.get("bonus_high", 3)
        elif ratio >= ratio_cfg.get("threshold_mid", 0.50):
            ratio_bonus = ratio_cfg.get("bonus_mid", 2)
        elif ratio >= ratio_cfg.get("threshold_low", 0.30):
            ratio_bonus = ratio_cfg.get("bonus_low", 1)
        else:
            ratio_bonus = 0
        ratio_cap = ratio_cfg.get("cap", 3)
        ratio_bonus = min(ratio_bonus, ratio_cap)
    else:
        ratio_bonus = 0
        ratio = 0.0

    count_maxed = malicious >= 10  # already scored +3 from count

    if ratio_bonus > 0 and not count_maxed:
        score += ratio_bonus
        breakdown.append(
            f"Detection ratio {ratio:.0%} ({vt['malicious']}/{total_engines}) → +{ratio_bonus}"
        )
    elif ratio_bonus > 0 and count_maxed:
        breakdown.append(
            f"Detection ratio {ratio:.0%} ({vt['malicious']}/{total_engines}) → +0  (count already maxed at +3)"
        )
    else:
        if total_engines > 0 and vt.get("malicious", 0) > 0:
            breakdown.append(
                f"Detection ratio {ratio:.0%} ({vt['malicious']}/{total_engines}) → +0  (below threshold)"
            )

    # Mirror every signal that can independently move the score above 0, not just
    # raw detection counts — otherwise a source can score non-clean while its own
    # findings_label still reads "No Findings" (e.g. tags/comments flagged it but
    # no engine marked it malicious).
    suspicious_evidence = suspicious if suspicious >= 3 else 0
    tag_evidence         = len(found_tags)
    vote_evidence        = 1 if vote_modifier > 0 else 0
    keyword_evidence     = len(matched_malicious) + len(matched_suspicious)

    evidence_count = (
        malicious + comm_mal + dl_mal +
        suspicious_evidence + tag_evidence + vote_evidence + keyword_evidence
    )

    # Only assign a real verdict if there's something to judge; avoids false "clean" on empty
    # responses. Built from evidence_count plus harmless/undetected (a 100%-clean scan is still
    # "data", just not "evidence") so has_data can't disagree with evidence_count/findings_label.
    has_data = evidence_count > 0 or harmless > 0 or undetected > 0

    score = min(score, 18)

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
    }


def score_otx(otx, config=None):
    """Score AlienVault OTX data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Reputation       — OTX community reputation score (negative = flagged)
      2. Recent pulses    — pulses mentioning 2025/2026 indicate current activity
      3. Pulse tags       — weighted tags on individual pulses (noise tags excluded)
      4. Adversary        — named APT/adversary attribution is high-signal
      5. Malware families — named family in a pulse stands on its own
      6. Passive DNS      — recent passive DNS activity corroborates the threat
    """

    if not otx:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    score     = 0
    breakdown = []

    pulse_count   = otx.get("pulse_count", 0)
    pulse_details = otx.get("pulse_details", [])
    reputation    = otx.get("reputation", 0)
    noise_tags    = config.get("noise_tags", NOISE_TAGS) if config else NOISE_TAGS

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
    recent_pulse_found = False
    non_noise_count    = 0
    known_apt_actors   = get_known_entities("apt_actor")

    for p in pulse_details:
        p_tags = {t.lower() for t in p.get("tags", [])}

        # Skip pulses whose tags are entirely noise (honeypots, honeypot sensors, etc.)
        if p_tags and p_tags.issubset(noise_tags):
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
            for tag in p_tags - noise_tags:
                w = config["tag_weights"].get(tag, 0)
                if w >= 2:
                    pulse_tag_score += w
                    pulse_tag_contrib[tag] = pulse_tag_contrib.get(tag, 0) + w

        # Adversary attribution — matched against the self-enriching known_entities DB
        # (live-learned from OTX/ThreatFox + MITRE ATT&CK bulk import), not config.json.
        adversary = p.get("adversary", "")
        if adversary:
            if adversary.lower() in known_apt_actors:
                adversary_score = min(adversary_score + 4, 4)
                apt_hit = True

    pulse_tag_score = min(pulse_tag_score, 3)  # cap per-pulse contribution

    # Pre-check pulses_detail for qualitative content (malware family / ATT&CK technique)
    # so pure pulse volume can't reach the top score tiers on its own — see gating below.
    _pulses_detail_pre = otx.get("pulses_detail") or []
    has_malware_family = any((entry.get("malware_families") or []) for entry in _pulses_detail_pre)
    has_attack_id = any(
        (entry.get("attack_ids") or entry.get("attack_id") or []) for entry in _pulses_detail_pre
    )
    has_qualitative_signal = (
        bool(pulse_tag_contrib) or adversary_score > 0 or has_malware_family or has_attack_id
    )

    # Gate pulse count score on quality. otx.py exposes non_noise_count — the accurate
    # count of non-noise pulses from the full pulse list, not just the 5-pulse sample.
    # Use it when available; fall back to raw pulse_count only when no pulse details
    # were fetched at all.
    reported_non_noise = otx.get("non_noise_count")
    if reported_non_noise is not None:
        qualifying_count = reported_non_noise
    elif pulse_details:
        qualifying_count = pulse_count if non_noise_count > 0 else 0
    else:
        qualifying_count = pulse_count

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
            breakdown.append(f"Passive DNS last seen {humanize_recency(latest_pdns)} → +1")
        elif days_since <= 30:
            breakdown.append(f"Passive DNS last seen {humanize_recency(latest_pdns)} → +0  (skipped — no pulse data to corroborate)")
        else:
            breakdown.append(f"Passive DNS last seen {humanize_recency(latest_pdns)} → +0")
    else:
        breakdown.append(f"Passive DNS last seen unknown  → +0")

    # Malware families and ATT&CK techniques from full pulse detail (deduplicated)
    pulses_detail = otx.get("pulses_detail") or []
    if pulses_detail and config:
        fam_cfg = config.get("otx_malware_families", {})

        seen_fams       = set()
        unique_families = []
        for entry in pulses_detail:
            for raw_fam in (entry.get("malware_families") or []):
                if isinstance(raw_fam, dict):
                    fam = raw_fam.get("display_name") or raw_fam.get("family") or ""
                else:
                    fam = str(raw_fam).strip() if raw_fam else ""
                if fam and fam not in seen_fams:
                    unique_families.append(fam)
                    seen_fams.add(fam)

        n_fams = len(unique_families)
        if n_fams >= 4:
            fam_score = fam_cfg.get("four_plus", 3)
        elif n_fams >= 2:
            fam_score = fam_cfg.get("two_three", 2)
        elif n_fams == 1:
            fam_score = fam_cfg.get("one", 1)
        else:
            fam_score = 0

        fam_score = min(fam_score, fam_cfg.get("cap", 3))
        if fam_score > 0:
            score += fam_score
            breakdown.append(f"Malware families confirmed: {', '.join(unique_families)} → +{fam_score}")

        atk_cfg      = config.get("otx_attack_ids", {})
        high_impact  = {t.upper() for t in (atk_cfg.get("HIGH_IMPACT_TECHNIQUES") or [])}
        seen_attacks = set()
        unique_attacks = []
        for entry in pulses_detail:
            for raw_aid in (entry.get("attack_ids") or entry.get("attack_id") or []):
                if isinstance(raw_aid, dict):
                    aid = raw_aid.get("id") or raw_aid.get("display_name") or ""
                else:
                    aid = str(raw_aid).strip() if raw_aid else ""
                if aid and aid not in seen_attacks:
                    unique_attacks.append(aid)
                    seen_attacks.add(aid)

        n_atk = len(unique_attacks)
        if n_atk >= 5:
            atk_score = atk_cfg.get("five_plus", 3)
        elif n_atk >= 2:
            atk_score = atk_cfg.get("two_four", 2)
        elif n_atk == 1:
            atk_score = atk_cfg.get("one", 1)
        else:
            atk_score = 0

        if atk_score > 0 and any(a.upper() in high_impact for a in unique_attacks):
            atk_score += atk_cfg.get("high_impact_bonus", 1)

        atk_score = min(atk_score, atk_cfg.get("cap", 3))
        if atk_score > 0:
            score += atk_score
            breakdown.append(f"ATT&CK techniques: {', '.join(unique_attacks)} → +{atk_score}")

    if config:
        rep_cfg       = config.get("otx_reputation", {})
        threat_scores = rep_cfg.get("threat_type_scores", {})
        rep_cap       = rep_cfg.get("cap", 4)
        rep_type      = otx.get("reputation_threat_type")
        if rep_type:
            modifier = min(threat_scores.get(rep_type.lower(), 0), rep_cap)
            if modifier > 0:
                score += modifier
                breakdown.append(f"OTX reputation: {rep_type} → +{modifier}")
            else:
                breakdown.append(f"OTX reputation type: {rep_type} (unscored)")

    score = min(score, 15)

    # reputation is 0 for unknown IPs, negative means OTX community flagged it
    has_data = pulse_count > 0 or reputation < 0

    verdict = score_to_verdict(score) if has_data else "no_data"

    # evidence_count must be built from the same signals as findings_label below —
    # qualifying_count alone missed reputation-only hits (a negative OTX reputation
    # can score and verdict non-clean with zero non-noise pulses).
    otx_evidence_count = qualifying_count + (1 if reputation < 0 else 0)

    otx_findings_label = evidence_count_to_findings_label(otx_evidence_count)
    otx_findings_tier  = evidence_count_to_findings_tier(otx_evidence_count)
    if not has_qualitative_signal and otx_findings_tier in ("medium", "high"):
        # Volume alone (no malware family / ATT&CK technique / adversary
        # attribution) shouldn't read as Medium/High Findings.
        otx_findings_label = "Low Risk Findings"
        otx_findings_tier  = "low"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": otx_evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": otx_findings_label,
        "findings_tier":  otx_findings_tier,
    }


def score_abuse(abuse, config=None, asn=None):
    """Score AbuseIPDB data. Returns per-source result dict.

    Scoring is quality-driven: attack type tags are the primary signal.
    Supporting signals (confidence, recency, Tor) contribute but are capped
    so attack types carry the weight without fully determining the verdict alone.

    Scoring layers (additive, capped at 15):
      1. Confidence score  — small corroborating signal (+1 max)
      2. Recency           — ungated; recent activity is more actionable
      3. Tor exit node     — anonymization proxy adds baseline risk
      4. Attack types      — primary driver; weighted by severity, capped at 8
    """

    if not abuse:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    score          = 0
    breakdown      = []
    abuse_score    = abuse.get("abuse_score", 0)
    distinct_users = abuse.get("distinct_users", 0)
    is_tor         = abuse.get("is_tor", False)
    last_reported  = abuse.get("last_reported")

    # Confidence score — small corroborating signal only
    if abuse_score >= 80:
        score += 1
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +1")
    elif abuse_score >= 40:
        score += 1
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +1  (moderate)")
    else:
        breakdown.append(f"AbuseIPDB confidence {abuse_score}%  → +0  (low)")

    # Recency — ungated, recent reports are more actionable regardless of volume
    if last_reported:
        try:
            last_dt  = datetime.datetime.fromisoformat(last_reported[:19])
            days_ago = (datetime.datetime.now() - last_dt).days
            if days_ago <= 7:
                score += 2
                breakdown.append(f"Last reported {humanize_recency(last_dt)}       → +2  (very recent)")
            elif days_ago <= 30:
                score += 1
                breakdown.append(f"Last reported {humanize_recency(last_dt)}       → +1  (recent)")
            elif days_ago <= 90:
                breakdown.append(f"Last reported {humanize_recency(last_dt)}       → +0")
            else:
                breakdown.append(f"Last reported {humanize_recency(last_dt)}       → +0  (old)")
        except (ValueError, TypeError):
            breakdown.append(f"Last reported date unknown  → +0")
    else:
        breakdown.append(f"Last reported unknown        → +0")

    if is_tor:
        score += 1
        breakdown.append(f"Tor exit node               → +1")
    else:
        breakdown.append(f"Tor exit node               → +0")

    # Attack types — primary driver, capped at 8 so supporting signals still matter
    NOISE_CATEGORIES = {"Port Scan", "Ping", "Open Proxy"}

    attack_weights = (config or {}).get("abuseipdb_attack_weights", {})
    if attack_weights and abuse.get("top_categories"):
        high_cfg   = attack_weights.get("high", {})
        medium_cfg = attack_weights.get("medium", {})
        ignore_cfg = attack_weights.get("ignore", {})

        high_cats   = set(high_cfg.get("categories", []))
        medium_cats = set(medium_cfg.get("categories", []))
        ignore_cats = set(ignore_cfg.get("categories", []))

        high_score     = 0
        medium_score   = 0
        matched_cats   = []
        noise_excluded = []

        for cat_name, _ in abuse.get("top_categories", []):
            if cat_name in NOISE_CATEGORIES:
                noise_excluded.append(cat_name)
                continue
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
        attack_bonus = min(high_score + medium_score, 8)  # primary driver cap

        cdn_asns_cfg = (config or {}).get("cdn_asns", {})
        if asn and asn in cdn_asns_cfg:
            attack_bonus = min(attack_bonus, 3)

        if noise_excluded:
            breakdown.append(f"{', '.join(noise_excluded)} excluded (scanner noise) → +0")
        if matched_cats:
            score += attack_bonus
            breakdown.append(f"Attack types [{', '.join(matched_cats)}] → +{attack_bonus}")
        else:
            breakdown.append(f"Attack types                → +0")

    has_data = distinct_users > 0 or is_tor

    score = min(score, 15)
    verdict = score_to_verdict(score) if has_data else "no_data"

    # A Tor exit-node flag alone can score and verdict non-clean even with zero
    # reports — count it so findings_label doesn't read "No Findings" in that case.
    evidence_count = distinct_users + (1 if is_tor else 0)

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
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
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    score     = 0
    breakdown = []

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

    has_data = bool(shodan)

    score = min(score, 15)

    # Minimum evidence threshold: open ports and missing hostname alone cannot raise the verdict.
    # Mirrors Censys's threshold (which also allows cumulative tag_score >= 3, not just a single
    # high-weight tag) so low-weight-but-plural tags aren't silently discarded here either.
    meets_min_threshold = vuln_count > 0 or product_score > 0 or has_high_weight_tag or tag_score >= 3

    if has_data and meets_min_threshold:
        verdict = score_to_verdict(score)
    elif has_data:
        verdict = "clean"
    else:
        verdict = "no_data"

    # Include flagged_tags (matching Censys's flagged_labels) so a tag-driven non-clean
    # verdict isn't paired with an evidence_count of 0 / "No Findings".
    evidence_count = len(vulns) + len(flagged_products) + len(flagged_tags)

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "gated":          False,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
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
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

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

    has_data = bool(censys)

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
        "findings_label": evidence_count_to_findings_label(len(vulns) + len(flagged_products) + len(flagged_labels)),
        "findings_tier":  evidence_count_to_findings_tier(len(vulns) + len(flagged_products) + len(flagged_labels)),
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

    verdict = score_to_verdict(score) if has_data else "no_data"

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
                "evidence_count": 0, "has_data": False, "breakdown": [], "is_noise": False,
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

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
            "findings_label": evidence_count_to_findings_label(0),
            "findings_tier":  evidence_count_to_findings_tier(0),
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

    # Any of these can independently push score above 0 — not just a "malicious"
    # classification — so all of them must count as evidence, not just the first.
    # Guarded by has_data so evidence_count can never be nonzero while has_data is False
    # (e.g. actor/cve present without a classification).
    evidence_count = 1 if (has_data and (classification in ("malicious", "suspicious") or actor or cve)) else 0

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "is_noise":       False,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
    }


def score_urlhaus(urlhaus, config=None):
    if not urlhaus:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    score     = 0
    breakdown = []
    url_count = int(urlhaus.get("url_count", 0) or 0)
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
        "findings_label": evidence_count_to_findings_label(url_count),
        "findings_tier":  evidence_count_to_findings_tier(url_count),
    }


def score_threatfox(threatfox, config=None):
    if not threatfox:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    score            = 0
    breakdown        = []
    ioc_count        = threatfox.get("ioc_count", 0) or 0
    threat_type      = threatfox.get("threat_type") or ""
    confidence_level = threatfox.get("confidence_level") or 0
    malware          = threatfox.get("malware")
    tags             = threatfox.get("tags") or []

    if ioc_count >= 10:
        score += 3
        breakdown.append(f"IOC count {ioc_count:<6}           → +3")
    elif ioc_count >= 3:
        score += 2
        breakdown.append(f"IOC count {ioc_count:<6}           → +2")
    elif ioc_count == 1:
        score += 1
        breakdown.append(f"IOC count {ioc_count:<6}           → +1")
    else:
        breakdown.append(f"IOC count {ioc_count:<6}           → +0")

    if threat_type == "botnet_cc":
        score += 3
        breakdown.append(f"Threat type: {threat_type:<18} → +3  (C2 infrastructure)")
    elif threat_type == "payload_delivery":
        score += 2
        breakdown.append(f"Threat type: {threat_type:<18} → +2  (payload delivery)")
    elif threat_type == "payload":
        score += 2
        breakdown.append(f"Threat type: {threat_type:<18} → +2  (malware payload)")
    elif threat_type == "cc_skimming":
        score += 1
        breakdown.append(f"Threat type: {threat_type:<18} → +1  (credit card skimming)")
    elif threat_type:
        breakdown.append(f"Threat type: {threat_type:<18} → +0")
    else:
        breakdown.append(f"Threat type: none                → +0")

    if confidence_level >= 75:
        score += 2
        breakdown.append(f"Confidence level {confidence_level:<3}          → +2")
    elif confidence_level >= 50:
        score += 1
        breakdown.append(f"Confidence level {confidence_level:<3}          → +1")
    else:
        breakdown.append(f"Confidence level {confidence_level:<3}          → +0  (low confidence)")

    tag_score  = 0
    found_tags = []
    if config:
        for tag in tags:
            weight = config.get("tag_weights", {}).get(tag.lower(), 0)
            if weight > 0:
                tag_score += weight
                found_tags.append(tag)
    tag_score = min(tag_score, 2)
    score += tag_score
    if found_tags:
        breakdown.append(f"Tags {', '.join(found_tags):<25} → +{tag_score}  (cap +2)")
    else:
        breakdown.append(f"Tags none                        → +0")

    if malware:
        score += 1
        breakdown.append(f"Malware family: {malware:<20} → +1")
    else:
        breakdown.append(f"Malware family: none             → +0")

    score    = min(score, 10)
    has_data = ioc_count > 0

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": ioc_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(ioc_count),
        "findings_tier":  evidence_count_to_findings_tier(ioc_count),
    }


def score_hybrid(hybrid, config=None):
    if not hybrid:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

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
    has_data = bool(hybrid)

    # The verdict-only fallback path (no threat_score) and the family field can each
    # push score above 0 independently of the threat_score >= 20 check — count them too.
    has_threat_signal = (
        (threat_score is not None and threat_score >= 20) or
        (threat_score is None and hybrid.get("verdict", "") in ("malicious", "suspicious"))
    )
    evidence_count = (1 if has_threat_signal else 0) + (1 if family else 0)

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
    }


def score_urlscan(urlscan, config=None):
    if not urlscan:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

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

    malicious_title_keywords = [
        "phishing", "login", "verify", "secure", "account", "update",
        "confirm", "banking", "wallet", "signin", "portal", "access",
        "gateway", "support", "helpdesk", "recovery", "suspended",
        "unusual activity", "verify your identity", "action required",
    ]

    suspicious_title_keywords = [
        "tor exit", "tor router", "proxy", "anonymizer", "vpn",
        "exit node", "relay",
    ]

    title_score = 0
    page_title  = (urlscan.get("page_title") or "").lower()

    if page_title:
        if any(kw in page_title for kw in malicious_title_keywords):
            title_score += 3
            breakdown.append(f"Page title [{urlscan['page_title'][:40]}] → +3  (phishing keywords)")
        elif any(kw in page_title for kw in suspicious_title_keywords):
            title_score += 1
            breakdown.append(f"Page title [{urlscan['page_title'][:40]}] → +1  (suspicious infrastructure)")
        else:
            breakdown.append(f"Page title [{urlscan['page_title'][:40]}] → +0")
    else:
        breakdown.append(f"Page title none              → +0")

    title_score = min(title_score, 3)
    score += title_score

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

    has_data = bool(urlscan)

    # Categories, page-title keywords, and phishing-keyword domains each score
    # independently of the "malicious" flag — count whichever of them fired so
    # evidence_count can't read 0 while one of them pushed the verdict up.
    evidence_count = (
        (1 if malicious else 0) +
        len(categories) +
        (1 if title_score > 0 else 0) +
        len(flagged_domains)
    )

    return {
        "verdict":        score_to_verdict(score) if has_data else "no_data",
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
    }


def score_google_intel(gi, config=None):
    """Score Google Threat Intel data. Returns per-source result dict.

    Scoring layers (additive, capped at 10):
      1. Malware families found     — cap +4
      2. APT actors found           — cap +4
      3. ATT&CK technique IDs found — cap +3
      4. CVEs mentioned             — cap +2
      5. Severity keywords          — cap +3
      6. Tier-1 source bonus        — cap +2
      Co-mentioned IOCs go to pivot only — not scored here.
    Combined cap: 10.
    """
    if not gi:
        return {"verdict": "no_data", "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": [],
                "findings_label": evidence_count_to_findings_label(0),
                "findings_tier": evidence_count_to_findings_tier(0)}

    gi_cfg        = (config or {}).get("google_intel", {}) if config else {}
    scoring       = gi_cfg.get("scoring", {})

    malware_families = gi.get("malware_families") or []
    apt_actors       = gi.get("apt_actors") or []
    attack_ids       = gi.get("attack_ids") or []
    cve_ids          = gi.get("cve_ids") or []
    severity_hits    = gi.get("severity_hits") or []
    co_iocs          = gi.get("co_iocs") or {}
    co_ips           = co_iocs.get("ips") or []
    co_domains       = co_iocs.get("domains") or []
    co_hashes        = co_iocs.get("hashes") or []
    source_tiers     = gi.get("source_tiers") or {}
    search_method    = gi.get("search_method", "none")
    urls_fetched     = gi.get("urls_fetched") or []

    # Malware families score
    n_mal = len(malware_families)
    if n_mal >= 4:   malware_score = scoring.get("malware_four_plus", 4)
    elif n_mal >= 2: malware_score = scoring.get("malware_two_three", 3)
    elif n_mal == 1: malware_score = scoring.get("malware_one", 2)
    else:            malware_score = 0
    malware_score = min(malware_score, scoring.get("malware_cap", 4))

    # APT actor score
    n_apt = len(apt_actors)
    if n_apt >= 2:   apt_score = 4
    elif n_apt == 1: apt_score = 3
    else:            apt_score = 0
    apt_score = min(apt_score, 4)

    # ATT&CK score
    n_atk = len(attack_ids)
    if n_atk >= 4:   attck_score = scoring.get("attck_four_plus", 3)
    elif n_atk >= 2: attck_score = scoring.get("attck_two_three", 2)
    elif n_atk == 1: attck_score = scoring.get("attck_one", 1)
    else:            attck_score = 0
    attck_score = min(attck_score, scoring.get("attck_cap", 3))

    # CVE score
    n_cve = len(cve_ids)
    if n_cve >= 3:   cve_score = 2
    elif n_cve >= 1: cve_score = 1
    else:            cve_score = 0
    cve_score = min(cve_score, 2)

    # Severity score
    severity_score = min(len(severity_hits), 3)

    # Tier-1 source bonus — only if signals found
    tier1_count = sum(1 for t in source_tiers.values() if t == 1)
    tier2_count = sum(1 for t in source_tiers.values() if t == 2)
    has_signals = bool(malware_families or apt_actors or attack_ids or cve_ids)
    if tier1_count >= 2 and has_signals:   tier_bonus = 2
    elif tier1_count >= 1 and has_signals: tier_bonus = 1
    else:                                   tier_bonus = 0

    cap   = gi_cfg.get("cap", 10)
    score = min(
        malware_score + apt_score + attck_score + cve_score + severity_score + tier_bonus,
        cap
    )

    breakdown = []
    breakdown.append(f"Sources fetched: {len(urls_fetched)} ({tier1_count} tier-1, {tier2_count} tier-2)")

    if malware_families:
        breakdown.append(f"Malware families: {', '.join(malware_families)} → +{malware_score}")
    else:
        breakdown.append(f"Malware families: none → +0")

    if apt_actors:
        breakdown.append(f"APT actors: {', '.join(apt_actors)} → +{apt_score}")
    else:
        breakdown.append(f"APT actors: none → +0")

    if attack_ids:
        breakdown.append(f"ATT&CK techniques: {', '.join(attack_ids)} → +{attck_score}")
    else:
        breakdown.append(f"ATT&CK techniques: none → +0")

    if cve_ids:
        breakdown.append(f"CVEs found: {', '.join(list(cve_ids)[:5])} → +{cve_score}")
    else:
        breakdown.append(f"CVEs found: none → +0")

    if severity_hits:
        breakdown.append(f"Severity signals: {', '.join(list(severity_hits)[:3])} → +{severity_score}")
    else:
        breakdown.append(f"Severity signals: none → +0")

    if tier_bonus > 0:
        breakdown.append(f"Tier-1 source bonus → +{tier_bonus}")

    ioc_parts = []
    if co_ips:     ioc_parts.append(f"{len(co_ips)} IP{'s' if len(co_ips) != 1 else ''}")
    if co_domains: ioc_parts.append(f"{len(co_domains)} domain{'s' if len(co_domains) != 1 else ''}")
    if co_hashes:  ioc_parts.append(f"{len(co_hashes)} hash{'es' if len(co_hashes) != 1 else ''}")
    if ioc_parts:
        breakdown.append(f"Co-mentioned IOCs: {', '.join(ioc_parts)} → sent to pivot scan")
    else:
        breakdown.append(f"Co-mentioned IOCs: none → sent to pivot scan")

    if search_method == "DDG":
        breakdown.append("Search method: DuckDuckGo")
    else:
        breakdown.append("Search method: none")

    has_data       = bool(urls_fetched)
    evidence_count = n_mal + n_apt + n_atk + n_cve + len(severity_hits)
    verdict        = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "score":          score,
        "evidence_count": evidence_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
        "findings_label": evidence_count_to_findings_label(evidence_count),
        "findings_tier":  evidence_count_to_findings_tier(evidence_count),
    }


def score_pivot(pivot_result, config):
    """Score pivot IOC scan results. Returns {score, has_data, breakdown}."""
    if not pivot_result:
        return {"score": 0, "has_data": False, "breakdown": []}

    pivot_cfg = (config or {}).get("pivot", {})
    mal_bonus  = pivot_cfg.get("malicious_bonus", 2)
    mal_cap    = pivot_cfg.get("malicious_cap", 6)
    sus_bonus  = pivot_cfg.get("suspicious_bonus", 1)
    sus_cap    = pivot_cfg.get("suspicious_cap", 2)
    total_cap  = pivot_cfg.get("total_cap", 6)

    malicious_pivots  = pivot_result.get("malicious_pivots", [])
    suspicious_pivots = pivot_result.get("suspicious_pivots", [])
    scanned           = pivot_result.get("pivot_iocs", [])

    if not scanned:
        return {"score": 0, "has_data": False, "breakdown": []}

    mal_score = min(len(malicious_pivots) * mal_bonus, mal_cap)
    sus_score = min(len(suspicious_pivots) * sus_bonus, sus_cap)
    total     = min(mal_score + sus_score, total_cap)

    breakdown = []
    if malicious_pivots:
        breakdown.append(f"Malicious pivots {len(malicious_pivots):<4} → +{mal_score}  (cap {mal_cap})")
    if suspicious_pivots:
        breakdown.append(f"Suspicious pivots {len(suspicious_pivots):<3} → +{sus_score}  (cap {sus_cap})")
    if not malicious_pivots and not suspicious_pivots:
        breakdown.append(f"Pivot IOCs {len(scanned)} scanned     → +0  (all clean or no data)")

    return {"score": total, "has_data": True, "breakdown": breakdown}


def combined_verdict(vt=None, otx=None, abuse=None, shodan=None, whois=None,
                     censys=None, greynoise=None, urlhaus=None, hybrid=None,
                     urlscan=None, spamhaus_drop=None, threatfox=None,
                     google_intel=None, config=None, pivot_result=None):
    """Combine per-source scores into a single final verdict using a plain average.

    Gated sources (CDN/cloud ASNs with score==0) are excluded from the average.
    One override rule applies: if any source returns High, the final verdict is raised
    to at least Medium risk.
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
    threatfox_result = score_threatfox(threatfox, config)
    hybrid_result    = score_hybrid(hybrid, config)
    urlscan_result   = score_urlscan(urlscan, config)
    gi_result        = score_google_intel(google_intel, config)
    sources = {
        "VirusTotal":   vt_result,
        "OTX":          otx_result,
        "AbuseIPDB":    abuse_result,
        "Shodan":       shodan_result,
        "Censys":       censys_result,
        "GreyNoise":    greynoise_result,
        "URLhaus":      urlhaus_result,
        "ThreatFox":    threatfox_result,
        "Hybrid":       hybrid_result,
        "URLScan":      urlscan_result,
        "Google Intel": gi_result,
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
                    "score":           r["score"],
                    "evidence_count":  r["evidence_count"],
                    "has_data":        r["has_data"],
                    "findings_label":  r.get("findings_label", evidence_count_to_findings_label(r["evidence_count"])),
                    "findings_tier":   r.get("findings_tier", evidence_count_to_findings_tier(r["evidence_count"])),
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
            "spamhaus_drop": spamhaus_drop,
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
    pivot_scored = score_pivot(pivot_result, config)
    pivot_bonus  = pivot_scored["score"]
    if pivot_bonus > 0:
        final_score   = min(final_score + pivot_bonus, 20)
        final_verdict = score_to_verdict(final_score)

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

    spamhaus_bonus = 0
    if spamhaus_drop and spamhaus_drop.get("listed"):
        spamhaus_bonus = 4
        final_score    = min(final_score + spamhaus_bonus, 20)
        final_verdict  = score_to_verdict(final_score)

    vt_country      = (vt or {}).get("country", "")
    censys_country  = (censys or {}).get("country", "") if isinstance(censys, dict) else ""
    shodan_country  = (shodan or {}).get("country", "") if isinstance(shodan, dict) else ""
    geo_countries   = {c.upper() for c in [vt_country, censys_country, shodan_country] if c}
    geo_mismatch    = len(geo_countries) > 1

    for name, r in active.items():
        if r["verdict"] == "high":
            if VERDICT_ORDER.get(final_verdict, 0) < VERDICT_ORDER["medium_risk"]:
                final_verdict = "medium_risk"
                break

    _active_raw = sum(r["score"] for r in active.values())
    triggered_by = []
    for name, r in active.items():
        verdict_qualifies = VERDICT_ORDER.get(r["verdict"], 0) >= VERDICT_ORDER.get(final_verdict, 0) - 1
        score_qualifies   = r["score"] >= 3
        pct_qualifies     = _active_raw > 0 and (r["score"] / _active_raw * 100) >= 15
        if verdict_qualifies or score_qualifies or pct_qualifies:
            triggered_by.append(name)
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

    if spamhaus_bonus > 0:
        full_breakdown.append(f"── Spamhaus DROP ──")
        asname = (spamhaus_drop or {}).get("asname", "")
        full_breakdown.append(f"ASN on Spamhaus DROP list ({asname}) → +{spamhaus_bonus}")

    if pivot_scored["has_data"]:
        full_breakdown.append(f"── Pivot ──")
        full_breakdown.extend((pivot_result or {}).get("pivot_detail", []))
        if pivot_bonus > 0:
            full_breakdown.append(f"Pivot bonus total → +{pivot_bonus}")

    # Build flat score_components including all bonus entries so percentages
    # reflect what actually drove the final score, not just source subtotals.
    score_components = {name: r["score"] for name, r in sources.items() if r["has_data"]}
    if spamhaus_bonus > 0:
        score_components["Spamhaus DROP"] = spamhaus_bonus
    if whois_modifier > 0:
        score_components["WHOIS"] = whois_modifier
    if pivot_bonus > 0:
        score_components["Pivot"] = pivot_bonus

    raw_total     = sum(score_components.values())
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

    for bonus_name in ("Spamhaus DROP", "WHOIS", "Pivot"):
        if bonus_name in score_components:
            pct = round(score_components[bonus_name] / raw_total * 100)
            contribution[bonus_name] = f"{pct}%"

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
                "score":           r["score"],
                "evidence_count":  r["evidence_count"],
                "has_data":        r["has_data"],
                "findings_label":  r.get("findings_label", evidence_count_to_findings_label(r["evidence_count"])),
                "findings_tier":   r.get("findings_tier", evidence_count_to_findings_tier(r["evidence_count"])),
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
        "geo_mismatch":               geo_mismatch,
        "geo_countries":              sorted(geo_countries),
        "spamhaus_drop":              spamhaus_drop,
        "pivot_influenced":           pivot_bonus >= 4,
        "pivot_bonus":                pivot_bonus,
    }