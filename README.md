# BPTC Banking

A user-friendly and responsive Flask-based banking application designed for deployment on PythonAnywhere. This application allows users to create accounts, perform simulated money transfers, view transaction history, and securely manage credentials.

---

## Table of Contents
- [New Security Features & Enhancements (2025)](#new-security-features--enhancements-2025)
- [Team Members](#team-members)
- [Features](#features)
- [Security Overview](#security-overview)
- [Automated Security Assessment Scripts](#automated-security-assessment-scripts)
- [Getting Started](#getting-started)
- [Database Setup](#database-setup)
- [How to Use Security Scripts](#how-to-use-security-scripts)
- [Deploying to PythonAnywhere](#deploying-to-pythonanywhere)
- [Usage](#usage)
- [User Roles](#user-roles)
- [Address Management](#address-management)
- [Technologies Used](#technologies-used)
- [Rate Limiting](#rate-limiting)
- [License](#license)

---

## New Security Features & Enhancements (2025)
- **6-digit PIN verification** required for all account access (user, admin, manager)
- **PIN creation and reset**: Users must create a 6-digit PIN; can reset PIN after password confirmation
- **PIN lockout**: After 3 incorrect PIN attempts, user is prompted to reset PIN
- **Automatic logout** after 15 minutes of inactivity (session timeout)
- **Inactivity warning modal**: User is warned 1 minute before auto-logout
- **All PINs securely hashed** in the database
- **Admin/Manager tools**: User and transaction management dashboards
- **Export Users/Transactions (CSV)**: Admins and managers can export user and transaction data
- **Transaction summary per user**: Admins can view and export a summary of all transactions for any user
- **User activation/deactivation**: Admins can activate or deactivate user accounts
- **Reset PIN**: Admins can reset user PINs
- **Modern, professional UI**: Redesigned footer, improved layout, and legal pages (Privacy Policy, Terms of Service)
- **Improved error handling**: Robust feedback for all user/admin actions

## Team Members
- Bata, Gian Carlo
- Papa, Nikko
- Tagum, Leo
- Calingacion, Almira

## Features
- User authentication (login, register, password recovery)
- Account management (balance, transaction history)
- Fund transfer (with confirmation and history)
- User roles: Regular, Admin, Manager
- Admin: Approve/activate/deactivate users, deposit, create/edit users, reset PIN, export users, view/export user transaction summaries
- Manager: Manage admins, view logs, monitor transfers, export transactions
- PSGC API integration for address selection
- Security: bcrypt, secure sessions, CSRF, rate limiting

## Security Overview
- Strong password policy (min 8 chars, upper/lowercase, number, special char)
- Passwords hashed with bcrypt
- Secure session management (cookie flags, timeout, fixation prevention)
- CSRF protection for all forms
- Rate limiting on sensitive endpoints
- HTTPS enforcement in production
- Generic error handlers and user-friendly error pages
- Jinja2 auto-escaping enforced
- Secrets/credentials loaded from environment variables
- Audit logging for sensitive changes
- Clickjacking protection via headers
- Automatic logout after 15 minutes of inactivity (session timeout)

## Automated Security Assessment Scripts
Scripts for security testing (for authorized use only):
- `security_auth_test.py`: Tests for weak passwords and authentication bypass
- `session_management_test.py`: Session fixation/hijacking tests
- `data_network_security_test.py`: Checks for secure storage and HTTPS
- `input_validation_test.py`: SQLi, XSS, command injection tests
- `authorization_test.py`: Access control tests
- `misc_security_tests.py`: CSRF, clickjacking, dependency checks
- `zap_scan.py`: Example OWASP ZAP scan script

> **Note:** Update credentials/URLs as needed before running scripts.

---

## Getting Started
### Prerequisites
- Python 3.7+
- pip
- MySQL Server 5.7+ or MariaDB 10.2+

### Installation
1. **Clone the repository:**
   ```
   git clone https://github.com/NebularEclipse/simple-banking-app-v2.git
   cd simple-banking-app
   # Set up your own repository
   git remote remove origin
   git remote add origin https://github.com/yourusername/simple-banking-app-v3.git
   git branch -M main
   git push -u origin main
   # If not working, try:
   git pull origin main --rebase
   # Replace 'yourusername' with your GitHub username
   ```
2. **Install required packages:**
   ```
   pip install -r requirements.txt
   ```
3. **Run the application:**
   ```
   python app.py
   # Before this, set up the database (see below), then run the app.
   ```
4. **Access at:** `http://localhost:5000`

---

## Database Setup
1. **Install MySQL Server or XAMPP (with MariaDB)**
2. **Create a database user and set privileges:**
   ```
   mysql -u root -p
   CREATE DATABASE simple_banking;
   CREATE USER 'bankapp'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON *.* TO 'bankapp'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```
3. **Update the `.env` file:**
   ```
   DATABASE_URL=mysql+pymysql://bankapp:your_password@localhost/simple_banking
   MYSQL_USER=bankapp
   MYSQL_PASSWORD=your_password
   MYSQL_HOST=localhost
   MYSQL_PORT=3306
   MYSQL_DATABASE=simple_banking
   ```
4. **Initialize the database:**
   ```
   python init_db.py
   ```

---

## How to Use Security Scripts
1. Run your Flask app (`python app.py`)
2. Run each script individually, e.g.:
   ```
   python security_auth_test.py
   python session_management_test.py
   # ...etc
   ```
3. Review output for warnings or vulnerabilities.

---

## Deploying to PythonAnywhere
1. Create an account at [pythonanywhere.com](https://www.pythonanywhere.com)
2. Upload code using Git
3. Install requirements
4. Set up MySQL database and update `.env`
5. Initialize database: `python init_db.py`
6. Configure web app via dashboard
7. Add environment variables for security

---

## Usage
- Register, login, manage account, transfer funds, reset password
- Admin: Approve users, manage accounts, deposit, edit users
- Manager: Manage admins, view logs, monitor transfers

## User Roles
- **Regular:** Manage own account, transfer, view history
- **Admin:** All regular privileges + approve/activate/deactivate users, deposit, create/edit users, reset PIN, export users, view/export user transaction summaries
- **Manager:** All admin privileges + manage admins, view logs, monitor transfers, export transactions

## Address Management
- PSGC API for standardized Philippine addresses (Region, Province, City, Barangay)

## Technologies Used
- Python, Flask, MySQL, SQLAlchemy, HTML, CSS, Bootstrap 5
- Flask-Login, Flask-Bcrypt, Flask-WTF, Flask-Limiter, PSGC API

## Rate Limiting
- Login: 10/min
- Registration: 5/min
- Password Reset: 5/hour
- Transfer: 20/hour
- API: 30/min
- Admin Dashboard: 60/hour
- Admin Account Creation: 20/hour
- Admin Deposits: 30/hour
- Manager Dashboard: 60/hour
- Admin Creation: 10/hour

For production, We use Redis for rate limit storage:
```
REDIS_URL=redis://localhost:6379/0
```

---

## License
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
