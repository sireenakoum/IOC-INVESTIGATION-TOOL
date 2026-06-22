import os
import requests
from dotenv import load_dotenv
from cache import cache_get, cache_set

load_dotenv()
THREATFOX_API_KEY = os.getenv("URLHAUS_API_KEY")

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

_THREAT_PRIORITY = ["botnet_cc", "payload_delivery", "payload", "cc_skimming"]


def threatfox_check(indicator, ind_type):
    if ind_type not in ("ip", "domain", "url", "hash"):
        return None

    cached = cache_get(indicator, "threatfox")
    if cached:
        print(f"  [CACHE HIT] threatfox — cached 0 day(s) ago")
        return cached

    if not THREATFOX_API_KEY:
        return None

    headers = {"Auth-Key": THREATFOX_API_KEY}
    payload = {"query": "search_ioc", "search_term": indicator, "exact_match": True}
    try:
        response = requests.post(BASE_URL, headers=headers, json=payload, timeout=15)
    except requests.exceptions.Timeout:
        print("  [ThreatFox] Request timed out — skipping, continuing scan")
        return None
    except requests.exceptions.ConnectionError:
        print("  [ThreatFox] Connection error, check your network — skipping, continuing scan")
        return None

    if response.status_code != 200:
        print(f"  [ThreatFox] Error {response.status_code}: {response.text[:200]}")
        return None

    body = response.json()

    query_status = body.get("query_status")
    if query_status != "ok":
        return None

    results = body.get("data")
    if not results or not isinstance(results, list):
        return None
    if not isinstance(results[0], dict):
        return None

    iocs_raw  = results
    ioc_count = len(iocs_raw)

    best = None
    for priority in _THREAT_PRIORITY:
        match = next((r for r in iocs_raw if r.get("threat_type") == priority), None)
        if match:
            best = match
            break
    if best is None and iocs_raw:
        best = iocs_raw[0]

    threat_type     = best.get("threat_type") if best else None
    malware         = best.get("malware_printable") if best else None
    malware_alias   = best.get("malware_alias") if best else None
    confidence_level = best.get("confidence_level") if best else None

    dates      = sorted(r.get("first_seen") for r in iocs_raw if r.get("first_seen"))
    first_seen = dates[0] if dates else None

    all_tags = []
    seen_tags = set()
    for r in iocs_raw:
        for tag in (r.get("tags") or []):
            if tag not in seen_tags:
                seen_tags.add(tag)
                all_tags.append(tag)

    iocs = [
        {
            "ioc":              r.get("ioc"),
            "ioc_type":         r.get("ioc_type"),
            "threat_type":      r.get("threat_type"),
            "malware_printable": r.get("malware_printable"),
            "confidence_level": r.get("confidence_level"),
            "first_seen":       r.get("first_seen"),
        }
        for r in iocs_raw[:5]
    ]

    result = {
        "ioc_count":        ioc_count,
        "threat_type":      threat_type,
        "malware":          malware,
        "malware_alias":    malware_alias,
        "confidence_level": confidence_level,
        "first_seen":       first_seen,
        "tags":             all_tags,
        "iocs":             iocs,
    }

    cache_set(indicator, "threatfox", result)
    return result
