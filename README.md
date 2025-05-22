# BPTC Banking

A user-friendly and responsive Flask-based banking application designed for deployment on PythonAnywhere. This application allows users to create accounts, perform simulated money transfers between accounts, view transaction history, and securely manage their credentials.

## Team Members
- **Bata, Gian Carlo**
- **Papa, Nikko**
- **Tagum, Leo**
- **Calingacion, Almira**

## Security Enhancements (2025)
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

## Automated Security Assessment Scripts
- `security_auth_test.py`: Tests for weak passwords and authentication bypass
- `session_management_test.py`: Session fixation/hijacking tests
- `data_network_security_test.py`: Checks for secure storage and HTTPS
- `input_validation_test.py`: SQLi, XSS, command injection tests
- `authorization_test.py`: Access control tests
- `misc_security_tests.py`: CSRF, clickjacking, dependency checks
- `zap_scan.py`: Example OWASP ZAP scan script

> **Note:** For authorized security testing only. Update credentials/URLs as needed.

## How to Use Security Scripts
1. Run your Flask app (`python app.py`)
2. Run each script individually, e.g.:
   ```
   python security_auth_test.py
   python session_management_test.py
   # ...etc
   ```
3. Review output for warnings or vulnerabilities.

## Features
- User authentication (login, register, password recovery)
- Account management (balance, transaction history)
- Fund transfer (with confirmation and history)
- User roles: Regular, Admin, Manager
- Admin: Approve/activate/deactivate users, deposit, create/edit users
- Manager: Manage admins, view logs, monitor transfers
- PSGC API integration for address selection
- Security: bcrypt, secure sessions, CSRF, rate limiting

## Getting Started
### Prerequisites
- Python 3.7+
- pip
- MySQL Server 5.7+ or MariaDB 10.2+

### Database Setup
1. Install MySQL Server or MariaDB
2. Create a database user and set privileges:
   ```
   mysql -u root -p
   CREATE USER 'bankapp'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON *.* TO 'bankapp'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```
3. Update the `.env` file:
   ```
   DATABASE_URL=mysql+pymysql://bankapp:your_password@localhost/simple_banking
   MYSQL_USER=bankapp
   MYSQL_PASSWORD=your_password
   MYSQL_HOST=localhost
   MYSQL_PORT=3306
   MYSQL_DATABASE=simple_banking
   ```
4. Initialize the database:
   ```
   python init_db.py
   ```

### Installation
1. Clone the repository:
   ```
   git clone https://github.com/lanlanjr/simple-banking-app.git
   cd simple-banking-app
   # Set up your own repository
   git remote remove origin
   git remote add origin https://github.com/yourusername/simple-banking-app-v2.git
   git branch -M main
   git push -u origin main
   # Replace 'yourusername' with your GitHub username
   ```
2. Install required packages:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Access at `http://localhost:5000`

## Deploying to PythonAnywhere
1. Create an account at [pythonanywhere.com](https://www.pythonanywhere.com)
2. Upload code using Git
3. Install requirements
4. Set up MySQL database and update `.env`
5. Initialize database: `python init_db.py`
6. Configure web app via dashboard
7. Add environment variables for security

## Usage
- Register, login, manage account, transfer funds, reset password
- Admin: Approve users, manage accounts, deposit, edit users
- Manager: Manage admins, view logs, monitor transfers

## User Roles
- Regular: Manage own account, transfer, view history
- Admin: All regular privileges + approve/activate/deactivate users, deposit, create/edit users
- Manager: All admin privileges + manage admins, view logs, monitor transfers

## Address Management
- PSGC API for standardized Philippine addresses (Region, Province, City, Barangay)

## Technologies Used
- Python, Flask, MySQL, SQLAlchemy, HTML, CSS, Bootstrap 5, Flask-Login, Flask-Bcrypt, Flask-WTF, Flask-Limiter, PSGC API

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

For production, use Redis for rate limit storage:
```
REDIS_URL=redis://localhost:6379/0
```

## License
MIT License - see LICENSE file for details.
