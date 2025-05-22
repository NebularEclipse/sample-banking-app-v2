"""
Security Assessment Script: Data Storage & Network Communication
- Verifies that sensitive data is stored securely (e.g., passwords hashed, no secrets in code)
- Verifies that all network communication uses HTTPS

USAGE: python data_network_security_test.py

WARNING: Only use this script on systems you own or have explicit permission to test.
"""
import os
import re
import requests

# --- Data Storage Checks ---

def check_env_secrets():
    print("[+] Checking for secrets in environment variables...")
    secrets_found = False
    for key, value in os.environ.items():
        if any(s in key.lower() for s in ["secret", "password", "key", "token"]):
            print(f"  [!] Found environment variable: {key}")
            secrets_found = True
    if not secrets_found:
        print("  [+] No obvious secrets found in environment variables.")

def check_code_for_secrets(filepaths):
    print("[+] Checking for hardcoded secrets in code files...")
    pattern = re.compile(r'(secret|password|key|token)[\s:=]+["\']?[^"\']+["\']?', re.IGNORECASE)
    for filepath in filepaths:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                if pattern.search(line):
                    print(f"  [!] Possible secret in {filepath} at line {i}: {line.strip()}")

def check_password_hashing(filepath):
    print(f"[+] Checking for password hashing in {filepath}...")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        if 'bcrypt' in content or 'generate_password_hash' in content:
            print("  [+] Passwords appear to be hashed (bcrypt or werkzeug detected). Good!")
        else:
            print("  [!] No password hashing detected! Check your user model.")

# --- Network Communication Checks ---

def check_https_enforcement(base_url):
    print("[+] Checking if HTTP is redirected to HTTPS...")
    try:
        resp = requests.get(base_url.replace('https://', 'http://'), allow_redirects=False)
        if resp.status_code in (301, 302) and resp.headers.get('Location', '').startswith('https://'):
            print("  [+] HTTP is redirected to HTTPS. Good!")
        else:
            print("  [!] HTTP is NOT redirected to HTTPS!")
    except Exception as e:
        print(f"  [!] Error checking HTTP to HTTPS redirection: {e}")

# --- Main ---
def main():
    # Data storage checks
    check_env_secrets()
    check_code_for_secrets([
        'app.py', 'extensions.py', 'models.py', 'routes.py', 'forms.py'
    ])
    check_password_hashing('models.py')
    print()
    # Network communication check
    check_https_enforcement('https://localhost:5000')

if __name__ == "__main__":
    main()
