"""User accounts, roles, and the activity log backing the Users & Activity
Log admin page. Schema/seed helpers live here (same role as
sources/app_config.py); per-request queries stay inline in web/app.py,
matching how the rest of that file talks to the DB directly.
"""
import sqlite3
import secrets
from datetime import datetime

from passlib.context import CryptContext

from cache import DB_PATH

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# The live DB already had a hand-created `users` table (email, password_hash,
# api_key, created_at, is_verified, verification_token, role) with no schema
# code committed anywhere in the repo — so a fresh/wiped DB (e.g. Render's
# free tier, which resets on every redeploy — see web/app.py's ensure_seeded
# comment for the same issue elsewhere) would crash the whole auth system on
# first request. init_users_table() below recreates that same shape
# idempotently and adds the columns this feature needs, so it self-heals
# the same way output.init_history_table()/cache.init_db() already do.
BOOTSTRAP_ADMIN_EMAIL = "sireen.akoum@gmail.com"

# Viewer (read-only, no scan access) was removed: the app has no report
# ownership/team-scoping, so every role sees the exact same data — a
# read-only role only ever gated the ability to scan, not what was visible.
# That made it a role with no real distinction from Analyst. Don't
# reintroduce it without first building actual visibility scoping for it
# to enforce.
ROLES = ("Admin", "Analyst")
STATUSES = ("Active", "Suspended")
EVENT_TYPES = ("Login", "Logout", "Scan run", "Account created", "Account deleted", "Report exported")

# Account created/deleted happen to accounts that can't view "their own
# activity" the way Login/Scan events can (the account doesn't exist yet,
# or no longer does) — so these are excluded from the Analyst self-activity
# view (/api/activity/me) and only ever shown in the Admin-facing views.
ADMIN_ONLY_EVENT_TYPES = ("Account created", "Account deleted")


def init_users_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            role VARCHAR(20) DEFAULT 'USER'
        )
    """)
    conn.commit()
    for col, col_type in [
        ("name", "TEXT"),
        ("status", "TEXT DEFAULT 'Active'"),
        ("last_login", "TEXT"),
        ("created_by", "INTEGER"),
        ("must_change_password", "INTEGER DEFAULT 0"),
        ("invite_token", "TEXT"),
        ("invite_token_expires", "TEXT"),
        ("is_bootstrap", "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists — safe no-op on every later call

    # Pre-existing installs default `role` to the placeholder 'USER' value
    # the table was hand-created with. Normalize onto the Admin/Analyst
    # scheme this feature introduces. Also catches any row still holding
    # the removed Viewer role (see ROLES above) and migrates it to Analyst —
    # they gain scan access they didn't have, the safe direction to err on
    # for an internal tool with no data visibility distinction to preserve.
    # Idempotent: once migrated no row still has 'USER'/NULL/'Viewer', so
    # this is a no-op on every later call.
    conn.execute("UPDATE users SET role = 'Analyst' WHERE role IS NULL OR role NOT IN ('Admin', 'Analyst')")
    conn.execute("UPDATE users SET status = 'Active' WHERE status IS NULL")
    conn.commit()
    conn.close()


def init_activity_log_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            event_type  TEXT NOT NULL,
            details     TEXT,
            timestamp   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp)")
    conn.commit()
    conn.close()


def ensure_users_seeded():
    """Idempotent bootstrap: promote/protect the fixed superuser account
    (sireen.akoum@gmail.com — a bootstrap superuser, not a hardcoded special
    case scattered through the app; call sites just check the `is_bootstrap`
    column). Called at import time in web/app.py, same self-healing
    convention as sources.app_config.ensure_seeded(). Returns an invite
    token if a brand-new account had to be created (so the caller can email
    it), else None — the account already existing is the common case on
    this repo's live DB.
    """
    init_users_table()
    init_activity_log_table()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    row = cur.execute("SELECT id FROM users WHERE email = ?", (BOOTSTRAP_ADMIN_EMAIL,)).fetchone()

    if row:
        cur.execute(
            "UPDATE users SET role = 'Admin', status = 'Active', is_bootstrap = 1 WHERE email = ?",
            (BOOTSTRAP_ADMIN_EMAIL,),
        )
        conn.commit()
        conn.close()
        return None

    # Fresh DB with no accounts at all — create the bootstrap admin
    # unverified with an invite token, same shape an admin-invited user gets
    # (see /api/admin/users), so first login goes through the same
    # accept-invite/set-password flow rather than a separate one-off path.
    invite_token = secrets.token_urlsafe(32)
    api_key = secrets.token_hex(32)
    placeholder_hash = pwd_context.hash(secrets.token_hex(32))
    cur.execute("""
        INSERT INTO users (email, password_hash, api_key, created_at, is_verified,
                            role, status, is_bootstrap, invite_token)
        VALUES (?, ?, ?, ?, 0, 'Admin', 'Active', 1, ?)
    """, (BOOTSTRAP_ADMIN_EMAIL, placeholder_hash, api_key, datetime.utcnow().isoformat(), invite_token))
    conn.commit()
    conn.close()
    return invite_token


def log_activity(user_id, event_type, details=None):
    """Record one activity_log row (see EVENT_TYPES). `details` must never
    contain a password (or any secret). For Account created/deleted, details
    should say who performed the action (e.g. "Self-signup", "Created by
    jane@x.com", "Self-deleted") — for deletions in particular this is the
    only durable record of who did it once the row moves on."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown activity event_type: {event_type}")
    init_activity_log_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO activity_log (user_id, event_type, details, timestamp) VALUES (?, ?, ?, ?)",
        (user_id, event_type, details, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
    )
    conn.commit()
    conn.close()