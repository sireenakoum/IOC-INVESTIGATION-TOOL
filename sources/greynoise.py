import requests
from cache import cache_get, cache_set, LOCAL_USER_ID

BASE_URL = "https://api.greynoise.io/v3/community"


def greynoise_check(indicator, ind_type, user_id=LOCAL_USER_ID):
    if ind_type != "ip":
        return None

    cached = cache_get(indicator, "greynoise", user_id)
    if cached:
        return cached

    url = f"{BASE_URL}/{indicator}"

    try:
        response = requests.get(url)
    except requests.exceptions.ConnectionError:
        print("  [GreyNoise] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 401:
        print("  [GreyNoise] Invalid API credentials")
        return None
    if response.status_code == 429:
        print("  [GreyNoise] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [GreyNoise] Error {response.status_code}: {response.text[:200]}")
        return None

    data = response.json()

    result = {
        "classification": data.get("classification"),
        "actor":          data.get("actor"),
        "cve":            data.get("cve"),
        "tags":           data.get("tags", []),
        "noise":          data.get("noise", False),
    }

    cache_set(indicator, "greynoise", result, user_id)
    return result
