import sqlite3
import os

_TABLES = {
    "malware":    "known_malware",
    "apt_actor":  "known_apt_actors",
    "tool":       "known_tools",
}

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Deliberately separate from cache.py's DB_PATH (ioc_cache.db). These tables
# are shared reference data (known malware/APT-actor/tool names, seeded from
# MITRE/MISP plus live OTX/ThreatFox learning) — the same for every
# deployment, safe to commit. ioc_cache.db holds personal scan history and
# the per-lookup result cache, and stays gitignored. See README.md.
REFERENCE_DB_PATH = os.environ.get("IOC_REFERENCE_DB_PATH", os.path.join(_ROOT, "reference.db"))


def init_enrichment_tables():
    conn = sqlite3.connect(REFERENCE_DB_PATH)
    for table in _TABLES.values():
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                name TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                source TEXT
            )
        """)
    conn.commit()
    conn.close()


def _table_for(entity_type):
    table = _TABLES.get(entity_type)
    if not table:
        raise ValueError(f"Unknown entity type: {entity_type!r}. Valid: {list(_TABLES.keys())}")
    return table


def add_known_entity(name, entity_type, source=None):
    """entity_type: 'malware', 'apt_actor', or 'tool'. Case-insensitive dedup —
    always stores lowercase, since google_intel.py's matching is
    case-insensitive substring matching against lowercased page text.
    source: optional string noting where this came from (e.g. 'otx',
    'threatfox', 'mitre_attack', 'misp_galaxy') — useful for later
    auditing which entries came from where."""
    if not name or not name.strip():
        return
    name = name.strip().lower()
    table = _table_for(entity_type)
    init_enrichment_tables()
    conn = sqlite3.connect(REFERENCE_DB_PATH)
    conn.execute(
        f"INSERT OR IGNORE INTO {table} (name, first_seen, source) VALUES (?, datetime('now'), ?)",
        (name, source)
    )
    conn.commit()
    conn.close()


def get_known_entities(entity_type):
    table = _table_for(entity_type)
    init_enrichment_tables()
    conn = sqlite3.connect(REFERENCE_DB_PATH)
    rows = conn.execute(f"SELECT name FROM {table}").fetchall()
    conn.close()
    return {r[0] for r in rows}
