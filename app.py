from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from detector import analyze_url
import sqlite3
import json
import os
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Load local .env file if it exists
if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    key, val = parts
                    os.environ[key.strip()] = val.strip()

app = Flask(__name__)
app.secret_key = "dwm_simulation_secret_key_1337"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scans.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            domain TEXT,
            status TEXT,
            risk INTEGER,
            color TEXT,
            threats TEXT,
            log TEXT,
            metadata TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Dynamically add verification columns if they do not exist
    try:
        conn.execute('ALTER TABLE scans ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN otp_code TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute('ALTER TABLE users ADD COLUMN otp_expiry TEXT')
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

init_db()

def send_otp_email(recipient, otp):
    subject = "DWM Intelligence Portal - Verification Code"
    body = f"""[SECURE TRANSMISSION]

Your Darkweb Monitoring Portal authorization OTP code is:

👉 {otp} 👈

This code is valid for 5 minutes. If you did not request this, please ignore this transmission.

SECURITY NOTICE: Do not share this code with anyone. DWM operators will never ask for your authorization code."""

    smtp_server = os.environ.get("SMTP_SERVER")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM", smtp_username or "noreply@dwm.io")

    print(f"[SMTP] Attempting to send OTP email to {recipient}...")

    if not (smtp_server and smtp_port and smtp_username and smtp_password):
        print("[SMTP ERROR] Missing SMTP environment configuration.")
        return False

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = smtp_from
        msg['To'] = recipient

        port = int(smtp_port)
        if port == 465:
            with smtplib.SMTP_SSL(smtp_server, port, timeout=10) as server:
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_from, [recipient], msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, port, timeout=10) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_from, [recipient], msg.as_string())
        print(f"[SMTP SUCCESS] Successfully sent OTP email to {recipient}")
        return True
    except Exception as e:
        import traceback
        print(f"[SMTP ERROR] Failed to send email to {recipient}: {e}")
        traceback.print_exc()
        return False

@app.route("/auth")
def auth_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("auth.html")

@app.route("/register", methods=["POST"])
def register():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    password = request.form.get("password")

    if not firstname or not lastname or not email or not password:
        return redirect(url_for('auth_page', error="All fields are required"))

    hashed_pw = generate_password_hash(password)
    otp = f"{random.randint(100000, 999999)}"
    expiry = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S.%f")

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if user:
        if user['is_verified']:
            conn.close()
            return redirect(url_for('auth_page', error="Email address already registered"))
        else:
            # Update the unverified user with new details & new OTP
            conn.execute('''
                UPDATE users 
                SET firstname = ?, lastname = ?, password = ?, otp_code = ?, otp_expiry = ?, is_verified = 0
                WHERE email = ?
            ''', (firstname, lastname, hashed_pw, otp, expiry, email))
            conn.commit()
    else:
        try:
            conn.execute('''
                INSERT INTO users (firstname, lastname, email, password, is_verified, otp_code, otp_expiry)
                VALUES (?, ?, ?, ?, 0, ?, ?)
            ''', (firstname, lastname, email, hashed_pw, otp, expiry))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return redirect(url_for('auth_page', error="Registration conflict occurred"))
    
    conn.close()
    
    # Send OTP
    sent = send_otp_email(email, otp)
    if not sent:
        return redirect(url_for('auth_page', action='register', error="Failed to send verification email. Please check your SMTP configuration or try again."))

    session['pending_email'] = email
    session['pending_action'] = 'verify'
    return redirect(url_for('auth_page', action='verify', msg="A verification OTP has been sent to your email."))

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return redirect(url_for('auth_page', error="Email and password are required"))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        if not user['is_verified']:
            # Unverified account - require OTP
            otp = f"{random.randint(100000, 999999)}"
            expiry = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S.%f")
            
            conn = get_db_connection()
            conn.execute('''
                UPDATE users 
                SET otp_code = ?, otp_expiry = ?
                WHERE email = ?
            ''', (otp, expiry, email))
            conn.commit()
            conn.close()

            sent = send_otp_email(email, otp)
            if not sent:
                return redirect(url_for('auth_page', error="Failed to send verification email. Please try again later."))

            session['pending_email'] = email
            session['pending_action'] = 'verify'
            return redirect(url_for('auth_page', action='verify', msg="Email verification is pending. A new OTP has been sent."))

        session['user_id'] = user['id']
        session['user_name'] = f"{user['firstname']} {user['lastname']}"
        session['user_email'] = user['email']
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('auth_page', error="Invalid email or password"))

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get('pending_email')
    action = session.get('pending_action')
    otp = request.form.get("otp")

    if not email or not otp:
        return redirect(url_for('auth_page', error="Session expired or invalid request"))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        conn.close()
        return redirect(url_for('auth_page', error="User account not found"))

    stored_otp = user['otp_code']
    otp_expiry_str = user['otp_expiry']
    
    if otp_expiry_str:
        try:
            otp_expiry = datetime.strptime(otp_expiry_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                otp_expiry = datetime.strptime(otp_expiry_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                otp_expiry = None
    else:
        otp_expiry = None

    if not stored_otp or not otp_expiry or datetime.now() > otp_expiry or stored_otp != otp:
        conn.close()
        return redirect(url_for('auth_page', action=action, error="Invalid or expired OTP code"))

    if action == 'verify':
        conn.execute('UPDATE users SET is_verified = 1, otp_code = NULL, otp_expiry = NULL WHERE email = ?', (email,))
        conn.commit()
        conn.close()
        
        session['user_id'] = user['id']
        session['user_name'] = f"{user['firstname']} {user['lastname']}"
        session['user_email'] = user['email']
        session.pop('pending_email', None)
        session.pop('pending_action', None)
        return redirect(url_for('dashboard'))
    else:
        conn.close()
        # Session states continue for reset
        return redirect(url_for('auth_page', action='reset'))

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form.get("email")
    if not email:
        return redirect(url_for('auth_page', action='forgot', error="Email is required"))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        conn.close()
        return redirect(url_for('auth_page', action='forgot', error="Email address not found"))

    otp = f"{random.randint(100000, 999999)}"
    expiry = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S.%f")

    conn.execute('''
        UPDATE users 
        SET otp_code = ?, otp_expiry = ?
        WHERE email = ?
    ''', (otp, expiry, email))
    conn.commit()
    conn.close()

    sent = send_otp_email(email, otp)
    if not sent:
        return redirect(url_for('auth_page', action='forgot', error="Failed to send password reset email. Please try again later."))

    session['pending_email'] = email
    session['pending_action'] = 'reset'
    return redirect(url_for('auth_page', action='reset', msg="A password reset OTP has been sent to your email."))

@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = session.get('pending_email')
    action = session.get('pending_action')
    otp = request.form.get("otp")
    new_password = request.form.get("password")

    if not email or action != 'reset':
        return redirect(url_for('auth_page', error="Session expired or invalid request"))

    if not otp or not new_password:
        return redirect(url_for('auth_page', action='reset', error="All fields are required"))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        conn.close()
        return redirect(url_for('auth_page', error="User account not found"))

    stored_otp = user['otp_code']
    otp_expiry_str = user['otp_expiry']
    
    if otp_expiry_str:
        try:
            otp_expiry = datetime.strptime(otp_expiry_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                otp_expiry = datetime.strptime(otp_expiry_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                otp_expiry = None
    else:
        otp_expiry = None

    if not stored_otp or not otp_expiry or datetime.now() > otp_expiry or stored_otp != otp:
        conn.close()
        return redirect(url_for('auth_page', action='reset', error="Invalid or expired OTP code"))

    hashed_pw = generate_password_hash(new_password)
    conn.execute('''
        UPDATE users 
        SET password = ?, otp_code = NULL, otp_expiry = NULL, is_verified = 1
        WHERE email = ?
    ''', (hashed_pw, email))
    conn.commit()
    conn.close()

    session.pop('pending_email', None)
    session.pop('pending_action', None)
    return redirect(url_for('auth_page', msg="Password reset successful. Please log in."))

@app.route("/resend-otp")
def resend_otp():
    email = session.get('pending_email')
    action = session.get('pending_action')

    if not email or not action:
        return redirect(url_for('auth_page', error="Session expired or invalid request"))

    otp = f"{random.randint(100000, 999999)}"
    expiry = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S.%f")

    conn = get_db_connection()
    conn.execute('''
        UPDATE users 
        SET otp_code = ?, otp_expiry = ?
        WHERE email = ?
    ''', (otp, expiry, email))
    conn.commit()
    conn.close()

    sent = send_otp_email(email, otp)
    target_action = 'verify' if action == 'verify' else 'reset'
    if not sent:
        return redirect(url_for('auth_page', action=target_action, error="Failed to resend OTP. Please try again later."))
    return redirect(url_for('auth_page', action=target_action, msg="A new OTP code has been sent."))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('auth_page'))

@app.route("/", methods=["GET", "POST"])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth_page'))

    conn = get_db_connection()
    user_id = session['user_id']
    
    # Get stats filtered by user
    total_scans = conn.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,)).fetchone()[0]
    critical_scans = conn.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND risk >= 75', (user_id,)).fetchone()[0]
    recent_scans = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5', (user_id,)).fetchall()
    
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = analyze_url(url)
            # Save to DB
            conn.execute('''
                INSERT INTO scans (user_id, url, domain, status, risk, color, threats, log, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                result['url'],
                result['domain'],
                result['status'],
                result['risk'],
                result['color'],
                json.dumps(result['threats']),
                json.dumps(result['log']),
                json.dumps(result['metadata'])
            ))
            conn.commit()
            
            # Recalculate stats for template render
            total_scans = conn.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,)).fetchone()[0]
            critical_scans = conn.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND risk >= 75', (user_id,)).fetchone()[0]
            recent_scans = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5', (user_id,)).fetchall()
    
    conn.close()
    
    return render_template("index.html", 
                         result=result, 
                         total_scans=total_scans, 
                         critical_scans=critical_scans,
                         recent_scans=recent_scans,
                         view="scanner")

@app.route("/history")
def history():
    if 'user_id' not in session:
        return redirect(url_for('auth_page'))

    conn = get_db_connection()
    user_id = session['user_id']
    all_scans = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC', (user_id,)).fetchall()
    conn.close()
    
    # Process threats/metadata from JSON strings
    processed_scans = []
    for scan in all_scans:
        s = dict(scan)
        s['threats'] = json.loads(s['threats'])
        s['metadata'] = json.loads(s['metadata'])
        processed_scans.append(s)
        
    return render_template("index.html", scans=processed_scans, view="history")

@app.route("/delete/<int:scan_id>")
def delete_scan(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('auth_page'))

    conn = get_db_connection()
    user_id = session['user_id']
    conn.execute('DELETE FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('history'))

# Trigger reload to read new .env SMTP settings
if __name__ == "__main__":
    app.run(debug=True)
