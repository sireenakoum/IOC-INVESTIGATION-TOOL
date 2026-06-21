import os
import requests
from dotenv import load_dotenv
from cache import cache_get, cache_set

load_dotenv()
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")

BASE_URL = "https://urlhaus-api.abuse.ch/v1/host/"

_THREAT_PRIORITY = ["ransomware", "banker", "trojan", "dropper", "malware"]


def urlhaus_check(indicator, ind_type):
    if ind_type not in ("ip", "domain"):
        return None

    cached = cache_get(indicator, "urlhaus")
    if cached:
        return cached

    if not URLHAUS_API_KEY:
        return None

    headers = {"Auth-Key": URLHAUS_API_KEY}
    try:
        response = requests.post(BASE_URL, headers=headers, data={"host": indicator}, timeout=15)
    except requests.exceptions.Timeout:
        print("  [URLhaus] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [URLhaus] Connection error, check your network")
        return None

    if response.status_code != 200:
        print(f"  [URLhaus] Error {response.status_code}: {response.text[:200]}")
        return None

    data = response.json()

    if data.get("query_status") in ("no_results", "invalid_host"):
        return None

    urls_raw  = data.get("urls", [])
    url_count = data.get("url_count", len(urls_raw))

    all_threats = [u.get("threat") for u in urls_raw if u.get("threat")]
    threat = None
    for priority in _THREAT_PRIORITY:
        match = next((t for t in all_threats if priority in t.lower()), None)
        if match:
            threat = match
            break
    if threat is None and all_threats:
        threat = all_threats[0]

    dates      = sorted(u.get("date_added") for u in urls_raw if u.get("date_added"))
    first_seen = dates[0] if dates else None

    urls = [
        {
            "url":        u.get("url"),
            "threat":     u.get("threat"),
            "url_status": u.get("url_status"),
            "date_added": u.get("date_added"),
        }
        for u in urls_raw[:5]
    ]

    result = {
        "url_count":  url_count,
        "threat":     threat,
        "first_seen": first_seen,
        "urls":       urls,
    }

    cache_set(indicator, "urlhaus", result)
    return result
