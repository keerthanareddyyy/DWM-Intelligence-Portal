import sqlite3
import json

DB_PATH = "scans.db"

def list_registered_users():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if not cursor.fetchone():
            print("[-] The 'users' table does not exist yet. Run the app to create it.")
            conn.close()
            return
            
        users = cursor.execute("SELECT id, firstname, lastname, email, is_verified FROM users").fetchall()
        conn.close()
        
        if not users:
            print("[*] No registered candidates found in the database yet.")
            return
            
        print(f"\n[+] Found {len(users)} registered candidate(s) in 'scans.db':")
        print("-" * 80)
        print(f"{'ID':<5} | {'First Name':<15} | {'Last Name':<15} | {'Email':<30} | {'Verified':<8}")
        print("-" * 80)
        for u in users:
            verified_status = "YES" if u['is_verified'] else "NO"
            print(f"{u['id']:<5} | {u['firstname']:<15} | {u['lastname']:<15} | {u['email']:<30} | {verified_status:<8}")
        print("-" * 80 + "\n")
    except Exception as e:
        print(f"[-] Error querying database: {e}")

if __name__ == "__main__":
    list_registered_users()
