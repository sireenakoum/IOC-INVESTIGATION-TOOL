import sqlite3
import json
import datetime
import os

DB_PATH = os.environ.get("IOC_DB_PATH", "ioc_cache.db")
SILENT = False

# Fixed identity for the shared server-wide API_KEY (web/app.py's admin/
# legacy fallback) — sireen.akoum@gmail.com, users.id=2 in the live db.
# Kept here (not just in web/app.py) so the migration below can assign
# pre-multi-tenancy cache rows to the same account.
ADMIN_USER_ID = 2

# Bucket for cache entries with no resolved web-app user — CLI runs (main.py
# has no user concept) and pivot-scan lookups on auto-discovered IOCs, which
# cache external-source data that's identical for every user regardless of
# who triggered the scan. Real users.id values start at 1 (AUTOINCREMENT),
# so 0 never collides with an actual account.
LOCAL_USER_ID = 0


def cache_history():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ioc, source, result, cached_at
        FROM cache
        ORDER BY cached_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            ioc         TEXT NOT NULL,
            source      TEXT NOT NULL,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL,
            user_id     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (ioc, source, user_id)
        )
    """)
    conn.commit()
    _migrate_cache_user_scoping(conn)
    conn.close()


def _migrate_cache_user_scoping(conn):
    """Older installs created `cache` with PRIMARY KEY (ioc, source), so every
    user shared one row per indicator/source — a second user's scan looked
    like an instant cache hit off the first user's lookup. Rebuilds onto
    PRIMARY KEY (ioc, source, user_id) so each user gets their own row.

    SQLite can't ALTER a primary key in place, so this recreates the table.
    Pre-existing rows (which predate any user scoping — a mix of CLI-only
    usage and pre-fix web traffic) are assigned to ADMIN_USER_ID rather than
    left NULL: SQLite treats every NULL in a PRIMARY KEY/UNIQUE column as
    distinct from every other NULL, so INSERT OR REPLACE would never see a
    real conflict for NULL user_id and rows would pile up unbounded instead
    of overwriting on refresh.

    Detected via user_id's position in the primary key (0 = not part of it,
    the old schema's ALTER-added plain column); once rebuilt, user_id is
    the 3rd PK column and this is a no-op on every subsequent call.
    """
    info = {row[1]: row for row in conn.execute("PRAGMA table_info(cache)").fetchall()}
    if "user_id" not in info:
        return  # brand-new table, already created with the new schema above
    if info["user_id"][5] != 0:
        return  # user_id already part of the primary key

    conn.execute("BEGIN")
    try:
        conn.execute("""
            CREATE TABLE cache_new (
                ioc         TEXT NOT NULL,
                source      TEXT NOT NULL,
                result      TEXT NOT NULL,
                cached_at   TEXT NOT NULL,
                user_id     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ioc, source, user_id)
            )
        """)
        conn.execute(f"""
            INSERT INTO cache_new (ioc, source, result, cached_at, user_id)
            SELECT ioc, source, result, cached_at, COALESCE(user_id, {ADMIN_USER_ID})
            FROM cache
        """)
        conn.execute("DROP TABLE cache")
        conn.execute("ALTER TABLE cache_new RENAME TO cache")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def cache_get(ioc, source, user_id=LOCAL_USER_ID):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT result, cached_at FROM cache WHERE ioc = ? AND source = ? AND user_id = ?",
        (ioc, source, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    cached_at = datetime.datetime.fromisoformat(row[1])
    age_days  = (datetime.datetime.now() - cached_at).days
    if not SILENT:
        print(f"  [CACHE HIT] {source} — cached {age_days} day(s) ago")
    return json.loads(row[0])


def clear_cache():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM cache")
    conn.commit()
    conn.close()


def clear_indicator_cache(ioc, user_id=LOCAL_USER_ID):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cache WHERE ioc = ? AND user_id = ?", (ioc, user_id))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def cache_set(ioc, source, result, user_id=LOCAL_USER_ID):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO cache (ioc, source, result, cached_at, user_id)
        VALUES (?, ?, ?, ?, ?)
    """, (
        ioc,
        source,
        json.dumps(result),
        datetime.datetime.utcnow().isoformat(),
        user_id,
    ))
    conn.commit()
    conn.close()
    if not SILENT:
        print(f"  [CACHE SET] {source} result saved for {ioc}")
