"""
Security Assessment Script: Authentication Testing
- Tests for weak passwords
- Attempts password cracking with common passwords
- Attempts authentication bypass (SQL injection payloads)

USAGE: python security_auth_test.py
"""
import requests
import re

BASE_URL = "http://localhost:5000"  # Change to your app's URL if needed
LOGIN_ENDPOINT = "/login"
USERNAME = "admin"  # Change as needed
COMMON_PASSWORDS = [
    "password", "123456", "admin", "admin123", "letmein", "qwerty", "password1", "12345678", "welcome"
]
BYPASS_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "' OR ''='"]


def get_csrf_token(session, url):
    resp = session.get(url)
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', resp.text)
    return match.group(1) if match else ""


def test_weak_passwords():
    print("[+] Testing for weak passwords...")
    session = requests.Session()
    for pwd in COMMON_PASSWORDS:
        csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
        data = {
            "username": USERNAME,
            "password": pwd,
            "csrf_token": csrf_token
        }
        result = session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
        if result.status_code == 302 and "session" in result.headers.get("Set-Cookie", ""):
            print(f"[!] Weak password accepted: {pwd}")
        else:
            print(f"[-] Password rejected: {pwd}")


def test_auth_bypass():
    print("[+] Testing for authentication bypass (SQLi payloads)...")
    session = requests.Session()
    for payload in BYPASS_PAYLOADS:
        csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
        data = {
            "username": payload,
            "password": payload,
            "csrf_token": csrf_token
        }
        result = session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
        if result.status_code == 302 and "session" in result.headers.get("Set-Cookie", ""):
            print(f"[!] Possible authentication bypass with payload: {payload}")
        else:
            print(f"[-] Payload rejected: {payload}")


def main():
    test_weak_passwords()
    print()
    test_auth_bypass()

if __name__ == "__main__":
    main()
