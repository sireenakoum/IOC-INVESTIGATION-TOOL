import requests
from dotenv import load_dotenv
import ipaddress
import os

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

BASE_URL = "https://otx.alienvault.com/api/v1"
headers = {"X-OTX-API-KEY": OTX_API_KEY}

# Step 2: Query an IP address
def check_ip(ip):
    url = f"{BASE_URL}/indicators/IPv4/{ip}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        country     = data.get("country_name", "Unknown")
        asn         = data.get("asn", "Unknown")
        reputation  = data.get("reputation", 0)

        print(f"\n{'='*40}")
        print(f"  OTX Report: {ip}")
        print(f"{'='*40}")
        print(f"  Country    : {country}")
        print(f"  ASN        : {asn}")
        print(f"  Reputation : {reputation}")
        print(f"  Pulses     : {pulse_count} threat reports")
        print(f"{'='*40}\n")
    else:
        print(f"Error {response.status_code}: {response.text}")

# Step 3a: Query a domain
def check_domain(domain):
    url = f"{BASE_URL}/indicators/domain/{domain}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        country     = data.get("country_name", "Unknown")
        alexa       = data.get("alexa", "Unknown")

        print(f"\n{'='*40}")
        print(f"  OTX Report: {domain}")
        print(f"{'='*40}")
        print(f"  Country    : {country}")
        print(f"  Alexa Rank : {alexa}")
        print(f"  Pulses     : {pulse_count} threat reports")
        print(f"{'='*40}\n")
    else:
        print(f"Error {response.status_code}: {response.text}")

# Step 3b: Query a file hash (MD5, SHA1, or SHA256)
def check_hash(file_hash):
    url = f"{BASE_URL}/indicators/file/{file_hash}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pulse_count  = data.get("pulse_info", {}).get("count", 0)
        malware_fams = data.get("pulse_info", {}).get("references", [])

        print(f"\n{'='*40}")
        print(f"  OTX Report: {file_hash[:20]}...")
        print(f"{'='*40}")
        print(f"  Pulses     : {pulse_count} threat reports")
        print(f"  References : {len(malware_fams)}")
        print(f"{'='*40}\n")
    else:
        print(f"Error {response.status_code}: {response.text}")

def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def checkIndicator(indicator):
    if is_valid_ip(indicator):
        check_ip(indicator)
    elif "." in indicator:
        check_domain(indicator)
    elif len(indicator) in [32,40,64] and all(c in "0123456789abcdef" for c in indicator.lower()):
        check_hash(indicator)
    else:
        print("Invalid indicator format. Please enter a valid IP address, domain, or file hash.")
while True:
    indicator = input("Enter an IP address, domain, or file hash to check or q to quit:")
    checkIndicator(indicator)
    if indicator.lower()=="q":
        break

    