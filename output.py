import sqlite3
import json
import datetime

from cache import DB_PATH

def init_history_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            indicator   TEXT NOT NULL,
            vt_result   TEXT,
            otx_result  TEXT,
            verdict     TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_results(indicator, vt_result, otx_result, verdict):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (timestamp, indicator, vt_result, otx_result, verdict)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        indicator,
        json.dumps(vt_result),
        json.dumps(otx_result),
        verdict
    ))
    conn.commit()

    total = cursor.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()

    print(f"  Result saved to database ({total} total)")
