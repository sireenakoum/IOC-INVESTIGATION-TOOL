"""Disk-backed storage for auto-generated Word reports.

A report is written here once, right after an AI summary finishes
streaming (see web/app.py's POST /api/report/docx/generate), so the
frontend can show a persistent "report ready" notification and let the
user download it later via a token — independent of the original
request/response cycle. This is distinct from docx_export's existing
on-demand path (POST /api/report/docx), which stays fully in-memory and
is untouched by this module; manual Export-menu downloads never touch
disk.

Retention is enforced lazily — swept on every save rather than via a
background scheduler, since this app has none (see cache.py/output.py
for the same "no scheduler, just check on access" style used elsewhere).
"""

import os
import sqlite3
import secrets
import datetime

DB_PATH = os.environ.get("IOC_DB_PATH", "ioc_cache.db")
REPORTS_DIR = os.environ.get(
    "IOC_REPORTS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_reports"),
)
RETENTION_SECONDS = int(os.environ.get("IOC_REPORT_RETENTION_MINUTES", "120")) * 60


def init_reports_table():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS generated_reports (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            indicator  TEXT NOT NULL,
            filename   TEXT NOT NULL,
            path       TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _delete_file_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def cleanup_expired_reports():
    """Deletes every generated report past the retention window, both the
    file on disk and its row. Cheap to call often — a no-op scan when
    nothing has expired yet."""
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(seconds=RETENTION_SECONDS)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT token, path FROM generated_reports WHERE created_at < ?", (cutoff,)
    ).fetchall()
    for _token, path in rows:
        _delete_file_quietly(path)
    conn.execute("DELETE FROM generated_reports WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()


def save_generated_report(doc_bytes, indicator, user_id, safe_indicator):
    """Writes an already-fully-built .docx (in memory) to disk and
    registers it for download. Returns (token, filename).

    Written to a temp file and atomically renamed into place so a crash
    or error mid-write can never leave a half-written file registered —
    the DB row is only inserted after the rename succeeds, and any
    failure cleans up whatever partial file it left behind.
    """
    init_reports_table()
    cleanup_expired_reports()

    token = secrets.token_urlsafe(24)
    filename = f"{safe_indicator}-report.docx"
    final_path = os.path.join(REPORTS_DIR, f"{token}.docx")
    tmp_path = final_path + ".tmp"

    try:
        with open(tmp_path, "wb") as f:
            f.write(doc_bytes)
        os.replace(tmp_path, final_path)
    except Exception:
        _delete_file_quietly(tmp_path)
        _delete_file_quietly(final_path)
        raise

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO generated_reports (token, user_id, indicator, filename, path, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (token, user_id, indicator, filename, final_path, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        _delete_file_quietly(final_path)
        raise

    return token, filename


def get_generated_report(token, user_id):
    """Returns (path, filename) for a token owned by user_id, or None if
    it's missing, expired, or owned by someone else — 404 either way from
    the caller so ownership can't be probed. Re-checks the file still
    exists on disk in case it was swept between save and download."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT path, filename, user_id FROM generated_reports WHERE token = ?", (token,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    path, filename, owner_id = row
    if owner_id != user_id:
        return None
    if not os.path.exists(path):
        return None
    return path, filename
