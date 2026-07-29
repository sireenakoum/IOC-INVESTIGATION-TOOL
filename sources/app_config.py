import sqlite3
import json
import os
from cache import DB_PATH

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SEED_PATH = os.path.join(_ROOT, "config.seed.json")


def init_config_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_config (
            key_path TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_config_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_path TEXT NOT NULL,
            old_value_json TEXT,
            new_value_json TEXT NOT NULL,
            changed_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _flatten(obj, prefix=""):
    """Flatten nested dict into dotted key paths: tier1.vendors,
    tag_weights.critical.c2, etc. Leaf values (including lists) stored
    as JSON strings."""
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            items.update(_flatten(v, path))
    else:
        items[prefix] = obj
    return items


def _unflatten(flat):
    """Reverse of _flatten — rebuild nested dict from dotted key paths."""
    result = {}
    for path, value in flat.items():
        parts = path.split(".")
        d = result
        for p in parts[:-1]:
            d = d.setdefault(p, {})
        d[parts[-1]] = value
    return result


def set_config_value(key_path, value):
    init_config_table()
    conn = sqlite3.connect(DB_PATH)
    old_row = conn.execute(
        "SELECT value_json FROM app_config WHERE key_path = ?", (key_path,)
    ).fetchone()
    old_value_json = old_row[0] if old_row else None
    new_value_json = json.dumps(value)
    conn.execute("""
        INSERT INTO app_config (key_path, value_json, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(key_path) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
    """, (key_path, new_value_json))
    conn.execute("""
        INSERT INTO app_config_history (key_path, old_value_json, new_value_json, changed_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (key_path, old_value_json, new_value_json))
    conn.commit()
    conn.close()


def load_config():
    """Rebuild the full nested config dict from the flat DB store —
    same shape as the original config.json, so existing consumers
    (scoring.py, google_intel.py, etc.) need minimal changes."""
    init_config_table()
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT key_path, value_json FROM app_config").fetchall()
    conn.close()
    flat = {key: json.loads(val) for key, val in rows}
    return _unflatten(flat)


def export_config_to_json(output_path):
    """Backup/diff helper — dumps current DB-backed config to a JSON file,
    so you can still version/diff it manually if you want to."""
    config = load_config()
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2, sort_keys=True)
    print(f"Exported current config to {output_path}")


def is_seeded():
    """True if the DB already has the config keys sources/scoring.py requires."""
    current = load_config()
    try:
        current["_meta"]["scoring"]
        current["tier1"]["vendors"]
        current["tier2"]["vendors"]
    except KeyError:
        return False
    return True


def ensure_seeded(seed_file=None, force=False):
    """Seed app_config from config.seed.json if it isn't already (or always,
    if force=True). Called on every app import (see web/app.py) so a wiped
    filesystem — e.g. Render's free tier, which resets on every redeploy —
    self-heals instead of crashing on the first request. Idempotent and
    cheap to no-op, so it's safe to call unconditionally at import time."""
    if not force and is_seeded():
        return False

    seed_file = seed_file or DEFAULT_SEED_PATH
    with open(seed_file, encoding="utf-8") as f:
        seed = json.load(f)

    flat = _flatten(seed)
    for key_path, value in flat.items():
        set_config_value(key_path, value)

    return True
