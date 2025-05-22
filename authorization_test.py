"""
Security Assessment Script: Authorization
- Tests for improper access control (horizontal/vertical privilege escalation)

USAGE: python authorization_test.py

WARNING: Only use this script on systems you own or have explicit permission to test.
"""
import requests
import re

BASE_URL = "http://localhost:5000"  # Change as needed
LOGIN_ENDPOINT = "/login"
ADMIN_DASHBOARD = "/admin"
MANAGER_DASHBOARD = "/manager"
USER_ACCOUNT = "/account"

# Test users (set valid credentials for your app)
USERS = [
    {"username": "admin", "password": "admin123", "role": "admin"},
    {"username": "manager", "password": "manager123", "role": "manager"},
    {"username": "user", "password": "user123", "role": "user"},
]


def get_csrf_token(session, url):
    resp = session.get(url)
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', resp.text)
    return match.group(1) if match else ""


def login(session, username, password):
    csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
    data = {"username": username, "password": password, "csrf_token": csrf_token}
    resp = session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
    return resp.status_code == 302 and "session" in resp.headers.get("Set-Cookie", "")


def test_access_control():
    print("[+] Testing for improper access control...")
    for user in USERS:
        session = requests.Session()
        if not login(session, user["username"], user["password"]):
            print(f"[-] Could not log in as {user['username']}. Skipping access control tests for this user.")
            continue
        # Test admin dashboard access
        resp = session.get(BASE_URL + ADMIN_DASHBOARD)
        if user["role"] != "admin" and resp.status_code == 200:
            print(f"[!] Improper access: {user['role']} '{user['username']}' accessed admin dashboard!")
        # Test manager dashboard access
        resp = session.get(BASE_URL + MANAGER_DASHBOARD)
        if user["role"] != "manager" and resp.status_code == 200:
            print(f"[!] Improper access: {user['role']} '{user['username']}' accessed manager dashboard!")
        # Test user account access
        resp = session.get(BASE_URL + USER_ACCOUNT)
        if resp.status_code != 200:
            print(f"[!] {user['role']} '{user['username']}' could not access their own account page!")
    print("[+] Access control tests completed.")


def main():
    test_access_control()

if __name__ == "__main__":
    main()