import time
import requests

BASE_URL = "https://www.spamhaus.org/drop/asndrop.json"
_TTL_SECONDS = 6 * 3600

_cache_data      = None   # {asn_int: record_dict}
_cache_timestamp = 0.0


def _fetch_list():
    global _cache_data, _cache_timestamp

    try:
        response = requests.get(BASE_URL, timeout=20)
    except requests.exceptions.Timeout:
        print("  [Spamhaus DROP] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [Spamhaus DROP] Connection error, check your network")
        return None

    if response.status_code != 200:
        print(f"  [Spamhaus DROP] Error {response.status_code}: {response.text[:200]}")
        return None

    import json
    listing = {}
    for line in response.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("type") == "metadata":
            continue
        asn = record.get("asn")
        if asn is not None:
            listing[int(asn)] = record

    _cache_data      = listing
    _cache_timestamp = time.monotonic()
    return listing


def _get_list():
    if _cache_data is not None and (time.monotonic() - _cache_timestamp) < _TTL_SECONDS:
        age_days = int((time.monotonic() - _cache_timestamp) / 86400)
        print(f"  [CACHE HIT] spamhaus — cached {age_days} day(s) ago")
        return _cache_data
    return _fetch_list()


def spamhaus_asn_check(asn):
    if asn is None:
        return None

    asn_str = str(asn).strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]

    try:
        asn_int = int(asn_str)
    except ValueError:
        return None

    listing = _get_list()
    if listing is None:
        return None

    record = listing.get(asn_int)
    if record is None:
        return {"listed": False}

    return {
        "listed": True,
        "asname": record.get("asname"),
        "cc":     record.get("cc"),
        "domain": record.get("domain"),
        "rir":    record.get("rir"),
    }
