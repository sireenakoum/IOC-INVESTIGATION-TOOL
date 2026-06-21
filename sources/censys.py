import os
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()

CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")

BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"


def censys_check(indicator, ind_type):
    if ind_type != "ip":
        return None

    if not CENSYS_API_KEY:
        return None

    cached = cache_get(indicator, "censys")
    if cached:
        return cached

    url     = f"{BASE_URL}/{indicator}"
    headers = {"Authorization": f"Bearer {CENSYS_API_KEY}"}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.Timeout:
        print("  [Censys] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [Censys] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 401:
        print("  [Censys] Invalid API credentials")
        return None
    if response.status_code == 429:
        print("  [Censys] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [Censys] Error {response.status_code}: {response.text[:200]}")
        return None

    data = response.json().get("result", {}).get("resource", {})

    ip = data.get("ip", indicator)

    asn_data = data.get("autonomous_system", {})
    org = asn_data.get("name") or asn_data.get("description") or ""
    asn = f"AS{asn_data['asn']}" if asn_data.get("asn") else ""

    location = data.get("location", {})
    country = location.get("country") or location.get("country_code") or ""

    ports        = []
    services     = []
    all_vulns    = []

    for svc in data.get("services", []):
        port      = svc.get("port")
        transport = (svc.get("transport_protocol") or "TCP").lower()

        if port is not None and port not in ports:
            ports.append(port)

        software_list = svc.get("software", [])
        product = ""
        version = ""
        for sw in software_list:
            if sw.get("product"):
                product = sw.get("product", "")
                version = sw.get("version", "")
                break
        if not product:
            product = svc.get("protocol") or ""

        services.append({
            "port":      port,
            "transport": transport,
            "product":   product,
            "version":   version,
        })

        for vuln in svc.get("vulnerabilities", []):
            cve_id = vuln.get("cve") or vuln.get("id") or ""
            if cve_id and cve_id not in all_vulns:
                all_vulns.append(cve_id)

    labels = []
    for svc in data.get("services", []):
        for lbl in svc.get("labels", []):
            val = lbl.get("value") if isinstance(lbl, dict) else str(lbl)
            if val and val not in labels:
                labels.append(val)
    # Also check host-level labels as fallback
    for lbl in data.get("labels", []):
        val = lbl.get("value") if isinstance(lbl, dict) else str(lbl)
        if val and val not in labels:
            labels.append(val)
    last_update = data.get("last_updated_at") or ""

    hostnames = data.get("dns", {}).get("reverse_dns", {}).get("names", [])
    dns_names = data.get("dns", {}).get("names", [])

    favicon_hashes         = []
    http_titles            = []
    http_server_headers    = []
    ssh_host_key_fingerprints = []
    hassh_fingerprints     = []

    for svc in data.get("services", []):
        for endpoint in svc.get("endpoints", []):
            http = endpoint.get("http", {})
            for favicon in http.get("favicons", []):
                h = favicon.get("hash_shodan")
                if h is not None:
                    favicon_hashes.append(h)
            title = http.get("html_title")
            if title:
                http_titles.append(title)
            for sv in http.get("headers", {}).get("Server", {}).get("headers", []):
                if sv:
                    http_server_headers.append(sv)

        fp = svc.get("ssh", {}).get("server_host_key", {}).get("fingerprint_sha256")
        if fp is not None:
            ssh_host_key_fingerprints.append(fp)
        hassh = svc.get("ssh", {}).get("hassh_fingerprint")
        if hassh is not None:
            hassh_fingerprints.append(hassh)

    os_product = data.get("operating_system", {}).get("product", "")

    result = {
        "ip":                       ip,
        "org":                      org,
        "asn":                      asn,
        "country":                  country,
        "ports":                    ports,
        "services":                 services,
        "vulns":                    all_vulns,
        "labels":                   labels,
        "last_update":              last_update,
        "certificates":             [],
        "hostnames":                hostnames,
        "dns_names":                dns_names,
        "favicon_hashes":           favicon_hashes,
        "http_titles":              http_titles,
        "http_server_headers":      http_server_headers,
        "ssh_host_key_fingerprints": ssh_host_key_fingerprints,
        "hassh_fingerprints":       hassh_fingerprints,
        "os":                       os_product,
    }

    cache_set(indicator, "censys", result)
    return result
