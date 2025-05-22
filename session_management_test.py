"""
Session Management Security Assessment Script
- Tests for session fixation and session hijacking vulnerabilities

USAGE: python session_management_test.py

This script assumes:
- The login endpoint is /login
- The app uses a session cookie named 'session' (Flask default)
- The app is running on http://localhost:5000

WARNING: Only use this script on systems you own or have explicit permission to test.
"""
import requests
import re

BASE_URL = "http://localhost:5000"
LOGIN_ENDPOINT = "/login"
USERNAME = "admin"  # Change as needed
PASSWORD = "admin123"  # Set to a valid password for the test user
SESSION_COOKIE_NAME = "session"


def get_csrf_token(session, url):
    resp = session.get(url)
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', resp.text)
    return match.group(1) if match else ""


def test_session_fixation():
    print("[+] Testing for session fixation...")
    session = requests.Session()
    # Get a session cookie before login
    session.get(BASE_URL + LOGIN_ENDPOINT)
    pre_login_cookie = session.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "csrf_token": csrf_token
    }
    session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
    post_login_cookie = session.cookies.get(SESSION_COOKIE_NAME)
    if pre_login_cookie and post_login_cookie:
        if pre_login_cookie == post_login_cookie:
            print("[!] Session fixation possible: session cookie did not change after login!")
        else:
            print("[+] Session cookie changed after login (no fixation). Good!")
    else:
        print("[-] Could not retrieve session cookies for fixation test.")


def test_session_hijacking():
    print("[+] Testing for session hijacking...")
    # Simulate attacker: use a valid session cookie from a real login
    session = requests.Session()
    csrf_token = get_csrf_token(session, BASE_URL + LOGIN_ENDPOINT)
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "csrf_token": csrf_token
    }
    session.post(BASE_URL + LOGIN_ENDPOINT, data=data, allow_redirects=False)
    valid_cookie = session.cookies.get(SESSION_COOKIE_NAME)
    if not valid_cookie:
        print("[-] Could not obtain a valid session cookie for hijacking test.")
        return
    # Simulate attacker using the stolen cookie
    hijack_session = requests.Session()
    hijack_session.cookies.set(SESSION_COOKIE_NAME, valid_cookie)
    resp = hijack_session.get(BASE_URL + "/account", allow_redirects=False)
    if resp.status_code == 200 and USERNAME in resp.text:
        print(f"[!] Session hijacking possible: account page accessible with stolen cookie!")
    else:
        print("[+] Session hijacking not possible (cookie alone is not enough or user is logged out). Good!")


def main():
    test_session_fixation()
    print()
    test_session_hijacking()

if __name__ == "__main__":
    main()
