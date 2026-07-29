import os
import time
import datetime
import requests
from cache import cache_get, cache_set, LOCAL_USER_ID
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY")
BASE_URL_VT = "https://www.virustotal.com/api/v3"
headers_VT  = {"x-apikey": VT_API_KEY}

TYPE_PATH = {
    "ip":     "ip_addresses",
    "hash":   "files",
    "domain": "domains",
}

# VirusTotal


def _fetch_vt_comments(indicator, ind_type):
    cached = cache_get(indicator, "vt_comments")
    if cached is not None:
        return cached

    path = TYPE_PATH.get(ind_type, "domains")
    url  = f"{BASE_URL_VT}/{path}/{indicator}/comments"

    try:
        response = requests.get(
            url, headers=headers_VT,
            params={"limit": 10, "relationships": "author"},
        )
    except requests.exceptions.RequestException as e:
        print(f"  [VT] Comments request failed ({e.__class__.__name__}) — skipping, continuing scan")
        return []

    if response.status_code != 200:
        print(f"  [VT] Comments endpoint error {response.status_code} — skipping, continuing scan")
        return []

    comments = []
    for item in response.json().get("data", []):
        attrs = item.get("attributes", {})
        text  = (attrs.get("text") or "").strip()
        if len(text) < 10:
            continue

        ts       = attrs.get("date")
        date_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "unknown"
        votes    = attrs.get("votes", {})

        author_data = item.get("relationships", {}).get("author", {}).get("data", {})
        author      = author_data.get("id") if author_data else None

        comments.append({
            "date":           date_str,
            "author":         author or "anonymous",
            "text":           text[:300],
            "votes_positive": votes.get("positive", 0),
            "votes_negative": votes.get("negative", 0),
        })

    cache_set(indicator, "vt_comments", comments)
    return comments


def _fetch_vt_relations(indicator, ind_type):
    cached = cache_get(indicator, "vt_relations")
    if cached is not None:
        return cached

    if ind_type == "ip":
        endpoints = [
            ("communicating_files", f"{BASE_URL_VT}/ip_addresses/{indicator}/communicating_files"),
            ("downloaded_files",    f"{BASE_URL_VT}/ip_addresses/{indicator}/downloaded_files"),
            ("resolutions",         f"{BASE_URL_VT}/ip_addresses/{indicator}/resolutions"),
        ]
    elif ind_type == "domain":
        endpoints = [
            ("communicating_files", f"{BASE_URL_VT}/domains/{indicator}/communicating_files"),
            ("downloaded_files",    f"{BASE_URL_VT}/domains/{indicator}/downloaded_files"),
            ("resolutions",         f"{BASE_URL_VT}/domains/{indicator}/resolutions"),
        ]
    else:
        endpoints = [
            ("contacted_ips",     f"{BASE_URL_VT}/files/{indicator}/contacted_ips"),
            ("contacted_domains", f"{BASE_URL_VT}/files/{indicator}/contacted_domains"),
            ("contacted_urls",    f"{BASE_URL_VT}/files/{indicator}/contacted_urls"),
        ]

    relations = {}

    for rel_name, url in endpoints:
        try:
            resp = requests.get(url, headers=headers_VT, params={"limit": 5})
        except requests.exceptions.RequestException as e:
            print(f"  [VT] Relations/{rel_name} request failed ({e.__class__.__name__}) — skipping, continuing scan")
            relations[rel_name] = []
            continue

        if resp.status_code == 404:
            relations[rel_name] = []
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            print(f"  [VT] Relations/{rel_name} error {resp.status_code} — skipping, continuing scan")
            relations[rel_name] = []
            continue

        if resp.status_code != 200:
            relations[rel_name] = []
            continue

        items = []
        for entry in resp.json().get("data", []):
            attrs = entry.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            if rel_name == "resolutions":
                items.append({
                    "hostname": attrs.get("host_name") or attrs.get("hostname") or "",
                    "ip":       attrs.get("ip_address") or "",
                })
            elif rel_name in ("communicating_files", "downloaded_files"):
                items.append({
                    "id":         entry.get("id", ""),
                    "malicious":  stats.get("malicious", 0),
                    "undetected": stats.get("undetected", 0),
                })
            else:
                items.append({
                    "id":        entry.get("id") or attrs.get("ip_address") or attrs.get("url") or "",
                    "malicious": stats.get("malicious", 0),
                })

        relations[rel_name] = items

    cache_set(indicator, "vt_relations", relations)
    return relations


def vt_request_rescan(indicator, ind_type):
    path = TYPE_PATH.get(ind_type, "domains")
    url  = f"{BASE_URL_VT}/{path}/{indicator}/analyse"

    try:
        response = requests.post(url, headers=headers_VT)
    except requests.exceptions.RequestException:
        print("  [VT] Rescan request failed, using cached report")
        return None

    if response.status_code != 200:
        print(f"  [VT] Rescan request error {response.status_code}, using cached report")
        return None

    return response.json().get("data", {}).get("id")


def vt_wait_for_analysis(analysis_id, timeout=60, poll_interval=15):
    url     = f"{BASE_URL_VT}/analyses/{analysis_id}"
    elapsed = 0

    while elapsed < timeout:
        try:
            response = requests.get(url, headers=headers_VT)
        except requests.exceptions.RequestException:
            return False

        if response.status_code != 200:
            return False

        status = response.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return True

        time.sleep(poll_interval)
        elapsed += poll_interval

    print("  [VT] Rescan still queued after timeout, using latest available report")
    return False


def vt_check(indicator, ind_type, skip_rescan=False, user_id=LOCAL_USER_ID, light=False):
    """
    light=True skips the comments/relations fetch (4 extra sequential HTTP
    calls to VT: comments + communicating_files + downloaded_files +
    resolutions/contacted_*). Used by pivot scans, which run under a tight
    shared timeout and don't need the full community/relations detail that
    a top-level scan surfaces in its report — just a verdict signal.
    """

    cached = cache_get(indicator, "virustotal", user_id)
    if cached:
        if light:
            cached["comments"] = []
            cached["relations"] = {}
        else:
            cached["comments"] = _fetch_vt_comments(indicator, ind_type)
            cached["relations"] = _fetch_vt_relations(indicator, ind_type)
        cached["rescan_timed_out"] = False
        cached["self_rescanned"] = False
        return cached

    rescan_timed_out = False
    self_rescanned = False
    if not skip_rescan:
        analysis_id = vt_request_rescan(indicator, ind_type)
        if analysis_id:
            completed = vt_wait_for_analysis(analysis_id)
            rescan_timed_out = not completed
            self_rescanned    = completed

    if ind_type == "ip":
        url = f"{BASE_URL_VT}/ip_addresses/{indicator}"
    elif ind_type == "hash":
        url = f"{BASE_URL_VT}/files/{indicator}"
    else:
        url = f"{BASE_URL_VT}/domains/{indicator}"

    try:
        response = requests.get(url, headers=headers_VT)
    except requests.exceptions.RequestException:
        print("  [VT] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 429:
        print("  [VT] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [VT] Error {response.status_code}: {response.text[:200]}")
        return None

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    all_vendor_results = attrs.get("last_analysis_results", {})
    last_dns_records= attrs.get("last_dns_records",{})

    dns_records= []

    for record in last_dns_records:
        record_type = record.get("type", "")
        record_value = record.get("value", "")
        record_ttl = record.get("ttl", "")
        dns_records.append(f"{record_type}: {record_value} (TTL: {record_ttl})")

    malicious_vendors = []

    for vendor_name, vendor_data in all_vendor_results.items():
        if vendor_data.get("category") == "malicious":
            threat_name = vendor_data.get("result", "")
            one_vendor = {
                "vendor": vendor_name,
                "name":   threat_name
            }
            malicious_vendors.append(one_vendor)

    malicious_vendors = malicious_vendors[:5]
    tags = attrs.get("tags", [])
    last_scan_date = attrs.get("last_analysis_date", None)

    result = {
        "malicious":         stats.get("malicious", 0),
        "suspicious":        stats.get("suspicious", 0),
        "harmless":          stats.get("harmless", 0),
        "undetected":        stats.get("undetected", 0),
        "malicious_vendors": malicious_vendors,
        "tags":              tags,
        "last_scan_date":    last_scan_date,
        "dns_records":       dns_records,
        "rescan_timed_out":  rescan_timed_out,
        "self_rescanned":    self_rescanned,
    }

    if ind_type == "ip":
        result["country"] = attrs.get("country", "Unknown")
        result["asn"]     = attrs.get("asn", "Unknown")

    if ind_type == "domain":
        def _fmt_date(ts):
            if not ts:
                return None
            try:
                return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            except (TypeError, ValueError, OSError):
                return None

        result["registrar"]       = attrs.get("registrar")
        result["creation_date"]   = _fmt_date(attrs.get("creation_date"))
        result["expiration_date"] = _fmt_date(attrs.get("expiration_date"))
        result["last_update_date"] = _fmt_date(attrs.get("last_update_date"))

    cache_set(indicator, "virustotal", result, user_id)

    if light:
        result["comments"] = []
        result["relations"] = {}
    else:
        result["comments"] = _fetch_vt_comments(indicator, ind_type)
        result["relations"] = _fetch_vt_relations(indicator, ind_type)

    return result