"""
OWASP ZAP Automation Script Example
This script demonstrates how to use the OWASP ZAP Python API to scan your Flask web application for common web vulnerabilities.

Requirements:
- Install OWASP ZAP (https://www.zaproxy.org/download/)
- Install zapv2 Python package: pip install python-owasp-zap-v2.4
- Start ZAP in daemon mode: zap.bat -daemon -port 8090 (Windows) or zap.sh -daemon -port 8090 (Linux/Mac)

USAGE:
    python zap_scan.py
"""
from zapv2 import ZAPv2
import time

# Configuration
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8090'
ZAP_API_KEY = ''  # Set if you configured an API key in ZAP
TARGET = 'http://localhost:5000'  # Change to your app's URL if needed

zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}', 'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})

print(f"Accessing target {TARGET}")
zap.urlopen(TARGET)

# Spider the target
print("[+] Spidering target...")
scanid = zap.spider.scan(TARGET)
while int(zap.spider.status(scanid)) < 100:
    print(f"Spider progress: {zap.spider.status(scanid)}%")
    time.sleep(2)
print("[+] Spider completed.")

# Passive scan (automatic)
time.sleep(2)

# Active scan
print("[+] Starting active scan...")
scanid = zap.ascan.scan(TARGET)
while int(zap.ascan.status(scanid)) < 100:
    print(f"Active scan progress: {zap.ascan.status(scanid)}%")
    time.sleep(5)
print("[+] Active scan completed.")

# Report the results
print("\n[+] Alerts:")
for alert in zap.core.alerts(baseurl=TARGET)['alerts']:
    print(f"- {alert['alert']} (Risk: {alert['risk']}) - {alert['url']}")
    print(f"  Description: {alert['description'][:100]}...")
    print()

print("[+] Scan complete. Review the above alerts for possible vulnerabilities.")
