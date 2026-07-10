# 🌌 Darkweb Monitoring (DWM) Intelligence Portal

[![Deploy to Render](https://render.com/images/deploy-to-render.svg)](https://render.com)
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
  * Dynamic fail-safe SMTP fallback (falls back to a simulated OTP warning banner if SMTP is unconfigured or blocked, preventing user lockout).
* **🎨 Premium Responsive UI**:
  * Clean, cyberpunk/darkweb dashboard style.
  * Dynamic CSS variables for high-contrast light/dark modes.
  * Custom SVG-based theme toggle with smooth animations.
* **📦 Render Deploy Ready**: Comes pre-configured with a `Procfile` and `render.yaml` for one-click deployment.

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
├── Procfile            # Deployment execution command for Render
├── render.yaml         # Blueprint specification for easy cloud setup
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

### 4. Configure environment variables (Optional for Email OTP)
Create a `.env` file in the root directory:
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
```
*Note: If no `.env` file is present, the app runs in **Simulated Mode**, automatically displaying registration and verification codes directly in the browser's warning banners.*

### 5. Run the server
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your web browser.

---

## ☁️ Deploying to Render (Free Tier)

### One-Click Blueprint Deployment
1. Go to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** and select **Blueprint**.
3. Connect your repository: `keerthanareddyyy/DWM-Intelligence-Portal`.
4. Enter the required variables when prompted (e.g. SMTP configuration) and click **Apply**.

### Manual Web Service Configuration
* **Service Type**: Web Service
* **Language**: Python
* **Build Command**: `pip install -r requirements.txt`
* **Start Command**: `gunicorn app:app`
* **Environment Variables**: Add your `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` keys under the Advanced tab.

---

## 🔒 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
