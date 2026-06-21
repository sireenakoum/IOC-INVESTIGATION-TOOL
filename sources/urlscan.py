import os
import time
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
BASE_URL = "https://urlscan.io/api/v1/search/"


def urlscan_check(indicator, ind_type):
    if not URLSCAN_API_KEY:
        return None

    cached = cache_get(indicator, "urlscan")
    if cached:
        return cached

    headers = {"API-Key": URLSCAN_API_KEY}
    params  = {"q": indicator}

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=15)
    except requests.exceptions.Timeout:
        print("  [URLScan] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [URLScan] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 401:
        print("  [URLScan] Invalid API credentials")
        return None
    if response.status_code == 429:
        print("  [URLScan] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [URLScan] Error {response.status_code}: {response.text[:200]}")
        return None

    data    = response.json()
    results = data.get("results", [])

    if not results:
        print(f"  [URLScan] No existing scans, submitting fresh scan...")
        try:
            sub = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers={**headers, "Content-Type": "application/json"},
                json={"url": f"http://{indicator}", "visibility": "public"},
                timeout=15,
            )
        except Exception:
            return None
        if sub.status_code != 200:
            print(f"  [URLScan] Submission failed {sub.status_code}")
            return None
        uuid = sub.json().get("uuid")
        if not uuid:
            return None
        print(f"  [URLScan] Submitted (uuid: {uuid}), waiting up to 60s...")
        result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
        scan_data = None
        for _ in range(6):
            time.sleep(10)
            try:
                r = requests.get(result_url, headers=headers, timeout=15)
            except Exception:
                continue
            if r.status_code == 200:
                scan_data = r.json()
                break
        if not scan_data:
            print(f"  [URLScan] Scan timed out")
            return None
        page = scan_data.get("page", {})
        verdicts = scan_data.get("verdicts", {}).get("overall", {})
        NOISE_TITLES = {
            "apache2 ubuntu default page: it works",
            "apache2 debian default page",
            "iis windows server",
            "welcome to nginx",
            "403 forbidden",
            "400 bad request",
        }
        title = (page.get("title") or "").strip()
        result = {
            "malicious":  verdicts.get("malicious", False),
            "categories": verdicts.get("categories", []),
            "page_title": title if title.lower() not in NOISE_TITLES else None,
            "server":     page.get("server"),
            "ip":         page.get("ip"),
            "domains":    [page.get("domain")] if page.get("domain") and page.get("domain") != indicator else [],
        }
        cache_set(indicator, "urlscan", result)
        return result

    malicious = any(
        r.get("verdicts", {}).get("overall", {}).get("malicious", False)
        for r in results
    )

    categories = []
    for r in results:
        for cat in r.get("verdicts", {}).get("overall", {}).get("categories", []):
            if cat not in categories:
                categories.append(cat)

    page = results[0].get("page", {})

    domains = []
    for r in results:
        d = r.get("page", {}).get("domain")
        if d and d not in domains and d != indicator:
            domains.append(d)

    NOISE_TITLES = {
        "apache2 ubuntu default page: it works",
        "apache2 debian default page",
        "iis windows server",
        "welcome to nginx",
        "403 forbidden",
        "400 bad request",
    }
    page_title = None
    for r in results:
        t = (r.get("page", {}).get("title") or "").strip()
        if t and t.lower() not in NOISE_TITLES:
            page_title = t
            break

    result = {
        "malicious":  malicious,
        "categories": categories,
        "page_title": page_title,
        "server":     page.get("server"),
        "ip":         page.get("ip"),
        "domains":    domains[:10],
    }

    cache_set(indicator, "urlscan", result)
    return result
