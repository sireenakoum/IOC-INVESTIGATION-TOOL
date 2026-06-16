import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
ip_address = input("Enter the IP address to check: ")
def check_ip(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    data= response.json()
    print(json.dumps(data, indent=2))
check_ip(ip_address)

