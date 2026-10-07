import urllib.request
import json
import socket
import asyncio
import os
import time

print("Testing APNIC / RDAP IP lookup...")
try:
    ip = socket.gethostbyname("vnexpress.net")
    print(f"vnexpress.net IP: {ip}")
    req = urllib.request.Request(f"https://rdap.apnic.net/ip/{ip}", headers={"User-Agent": "SafeZone-Bot/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode())
        country = data.get("country", "")
        print(f"RDAP Country: {country}")
except Exception as e:
    print(f"Error: {e}")
