import os
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()

HYBRID_API_KEY = os.getenv("HYBRID_API_KEY")


def hybrid_check(indicator, ind_type):
    if ind_type not in ("hash", "ip", "domain"):
        return None

    if not HYBRID_API_KEY:
        return None

    cached = cache_get(indicator, "hybrid")
    if cached:
        return cached

    headers = {
        "api-key":    HYBRID_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept":     "application/json",
    }

    try:
        if ind_type == "hash":
            response = requests.get(
                "https://www.hybrid-analysis.com/api/v2/search/hash",
                headers=headers,
                params={"hash": indicator},
                timeout=15,
            )
        else:
            field    = "host" if ind_type == "ip" else "domain"
            response = requests.post(
                "https://www.hybrid-analysis.com/api/v2/search/terms",
                headers=headers,
                data={field: indicator},
                timeout=15,
            )
    except requests.exceptions.Timeout:
        print("  [Hybrid Analysis] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [Hybrid Analysis] Connection error, check your network")
        return None

    if response.status_code != 200:
        print(f"  [Hybrid Analysis] Error {response.status_code}: {response.text[:200]}")
        return None

    data    = response.json()
    reports = []
    if isinstance(data, list):
        reports = data
    elif isinstance(data, dict):
        for key in ("result", "results", "reports"):
            if isinstance(data.get(key), list):
                reports = data[key]
                break

    if not reports:
        return None

    report = max(reports, key=lambda r: r.get("threat_score") or 0)
    report_id    = report.get("id")
    threat_score = report.get("threat_score")
    family       = []

    if report_id and (report.get("threat_score") or 0) >= 50:
        detail_url  = f"https://www.hybrid-analysis.com/api/v2/report/{report_id}/summary"
        detail_resp = requests.get(detail_url, headers=headers, timeout=15)
        if "application/json" not in detail_resp.headers.get("content-type", ""):
            pass  # skip detail enrichment
        elif detail_resp.status_code == 200:
            detail       = detail_resp.json()
            threat_score = detail.get("threat_score")
            vx_family    = detail.get("vx_family") or ""
            family       = [vx_family] if vx_family else []

    result = {
        "threat_score": threat_score,
        "verdict":      report.get("verdict"),
        "type":         report.get("environment_description"),
        "family":       family,
    }

    cache_set(indicator, "hybrid", result)
    return result
