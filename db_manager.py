import sqlite3
import hashlib
import secrets
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "stegovault.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                salt_hex TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                module TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        """)
        conn.commit()

def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return dk.hex()

def register_user(email: str, password: str) -> tuple[bool, str]:
    clean_email = email.strip().lower()
    if not clean_email or not password.strip():
        return False, "Email and password cannot be empty."
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    salt = secrets.token_bytes(16)
    pwd_hash = _hash_password(password, salt)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (email, salt_hex, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (clean_email, salt.hex(), pwd_hash, now)
            )
            conn.commit()
        return True, "Account created successfully! Please sign in."
    except sqlite3.IntegrityError:
        return False, "This email is already registered. Please sign in."

def verify_user(email: str, password: str) -> tuple[bool, str]:
    clean_email = email.strip().lower()
    if not clean_email or not password.strip():
        return False, "Please enter both email and password."

    with get_connection() as conn:
        row = conn.execute(
            "SELECT salt_hex, password_hash FROM users WHERE email = ?",
            (clean_email,)
        ).fetchone()

    if not row:
        return False, "Account not found! Please click 'Create Account' below first."

    expected_hash = row["password_hash"]
    actual_hash = _hash_password(password, bytes.fromhex(row["salt_hex"]))

    if secrets.compare_digest(expected_hash, actual_hash):
        return True, "Login successful!"
    return False, "Incorrect password! Access denied."

def log_user_activity(user_email: str, module: str, status: str, details: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO activity_logs (user_email, module, status, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_email.strip().lower(), module, status, details, now)
        )
        conn.commit()

def get_user_activity(user_email: str, limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp AS Timestamp, module AS Module, status AS Status, details AS Details "
            "FROM activity_logs WHERE user_email = ? ORDER BY id DESC LIMIT ?",
            (user_email.strip().lower(), limit)
        ).fetchall()
    return [dict(r) for r in rows]

def clear_user_activity(user_email: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM activity_logs WHERE user_email = ?", (user_email.strip().lower(),))
        conn.commit()

# Automatically initialize tables on import
init_db()
