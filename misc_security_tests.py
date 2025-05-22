"""
Security Assessment Script: CSRF, Clickjacking, and Known Vulnerabilities
- Tests for CSRF vulnerabilities
- Tests for clickjacking vulnerabilities
- Checks for known vulnerabilities in dependencies

USAGE: python misc_security_tests.py

WARNING: Only use this script on systems you own or have explicit permission to test.
"""
import requests
import re
import subprocess
import sys

BASE_URL = "http://localhost:5000"  # Change as needed
LOGIN_ENDPOINT = "/login"
TRANSFER_ENDPOINT = "/transfer"

# --- CSRF Test ---
def test_csrf():
    print("[+] Testing for CSRF vulnerabilities on transfer endpoint...")
    session = requests.Session()
    # Login first
    resp = session.get(BASE_URL + LOGIN_ENDPOINT)
    csrf_token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', resp.text)
    csrf_token = csrf_token.group(1) if csrf_token else ""
    data = {"username": "admin", "password": "admin123", "csrf_token": csrf_token}
    session.post(BASE_URL + LOGIN_ENDPOINT, data=data)
    # Attempt POST to transfer WITHOUT CSRF token
    data = {"recipient_username": "testuser", "amount": "1", "transfer_type": "username"}
    resp = session.post(BASE_URL + TRANSFER_ENDPOINT, data=data)
    if resp.status_code == 400 or "CSRF" in resp.text or "csrf" in resp.text:
        print("  [+] CSRF protection appears to be in place (request blocked). Good!")
    else:
        print("  [!] Possible CSRF vulnerability: POST without CSRF token was not blocked!")

# --- Clickjacking Test ---
def test_clickjacking():
    print("[+] Testing for clickjacking protection (X-Frame-Options header)...")
    resp = requests.get(BASE_URL)
    xfo = resp.headers.get("X-Frame-Options")
    cto = resp.headers.get("Content-Security-Policy")
    if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        print(f"  [+] X-Frame-Options header set to {xfo}. Good!")
    elif cto and "frame-ancestors" in cto:
        print(f"  [+] Content-Security-Policy frame-ancestors directive found. Good!")
    else:
        print("  [!] No clickjacking protection headers found!")

# --- Known Vulnerabilities Test ---
def test_known_vulnerabilities():
    print("[+] Checking for known vulnerabilities in dependencies (using pip-audit)...")
    try:
        result = subprocess.run([sys.executable, "-m", "pip_audit"], capture_output=True, text=True)
        if result.returncode == 0 and "No known vulnerabilities found" in result.stdout:
            print("  [+] No known vulnerabilities found in dependencies. Good!")
        else:
            print(result.stdout)
            print("  [!] Review the above output for vulnerable packages.")
    except Exception as e:
        print(f"  [!] Could not run pip-audit: {e}\n    To use this feature, install pip-audit: pip install pip-audit")

# --- Main ---
def main():
    test_csrf()
    print()
    test_clickjacking()
    print()
    test_known_vulnerabilities()

if __name__ == "__main__":
    main()
