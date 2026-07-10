# 🌌 Darkweb Monitoring (DWM) Intelligence Portal

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)

A modern, high-performance **Darkweb Monitoring & URL Threat Intelligence Simulator** built with Flask, SQLite, and a custom design system. It allows users to scan URLs against known darkweb threats, simulate data leak detection, and review security logs in real-time, complete with multi-tenant data isolation and a beautiful light/dark theme system.

---

## ✨ Features

* **🔍 Real-Time Threat Analysis**: Simulates deep web scanning, checking for ransomware, onion link redirects, credentials leakage, and botnet associations.
* **🛡️ Secure Multi-Tenancy**: Complete data isolation. Registered users can only view their own scan history and threat counters.
* **🔑 Secure Authentication Flow**:
  * Passwords hashed securely using `werkzeug.security`.
  * Secure verification codes (OTPs) dispatched to users' email addresses.
  * Resend codes and password reset workflows fully integrated.
* **🎨 Premium Responsive UI**:
  * Clean, cyberpunk/darkweb dashboard style.
  * Dynamic CSS variables for high-contrast light/dark modes.
  * Custom SVG-based theme toggle with smooth animations.

---

## 🛠️ Tech Stack

* **Backend**: Python, Flask, SQLite3
* **Frontend**: HTML5, Vanilla CSS, FontAwesome 6, Orbitron & Inter Typography
* **WSGI Server**: Gunicorn (for production)
* **Email Delivery**: SMTP (`smtplib` with STARTTLS / SSL support)

---

## 📂 Directory Structure

```text
├── app.py              # Main Flask web application routes & database setup
├── detector.py         # Underlying threat monitoring simulator rules engine
├── check_users.py      # Diagnostic database tool to view registered users
├── requirements.txt    # Production Python dependencies (Flask & Gunicorn)
├── templates/          # Frontend templates (auth.html & index.html)
└── scans.db            # SQLite Database (generated on run)
```

---

## 🚀 Local Quickstart

### 1. Clone the repository
```bash
git clone https://github.com/keerthanareddyyy/DWM-Intelligence-Portal.git
cd DWM-Intelligence-Portal
```

### 2. Set up a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables (Required for Email OTP)
Create a `.env` file in the root directory:
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
```

### 5. Run the server
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your web browser.


---

## 🔒 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
