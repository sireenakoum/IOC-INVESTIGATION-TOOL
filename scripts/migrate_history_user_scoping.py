"""
One-time backfill: assign pre-existing history/cache rows (from before
per-user scoping existed) to a specific account.

Schema changes themselves (the user_id column, and rebuilding history's
UNIQUE constraint onto (indicator, user_id)) are handled automatically and
idempotently by output.init_history_table() / cache.init_db() on every
process start — this script only does the one-off data assignment, which
is NOT safe to bake into normal app startup since it hardcodes which
account existing rows belong to.

Usage:
    python scripts/migrate_history_user_scoping.py --user-id 2
    python scripts/migrate_history_user_scoping.py --user-id 2 --dry-run

Safe to re-run: only touches rows where user_id IS NULL.
"""
import argparse
import os
import sqlite3
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.environ.setdefault("IOC_DB_PATH", os.path.join(_ROOT, "ioc_cache.db"))

from output import init_history_table
from cache import init_db, DB_PATH


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user-id", type=int, required=True, help="users.id to assign existing NULL-owner rows to")
    parser.add_argument("--dry-run", action="store_true", help="Report counts without writing")
    args = parser.parse_args()

    # Ensures schema is current (adds user_id columns, rebuilds history's
    # UNIQUE constraint onto (indicator, user_id)) before touching data.
    init_history_table()
    init_db()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    user_row = cur.execute("SELECT email FROM users WHERE id = ?", (args.user_id,)).fetchone()
    if not user_row:
        print(f"No user with id={args.user_id} found. Aborting.")
        conn.close()
        sys.exit(1)
    print(f"Target account: id={args.user_id} ({user_row[0]})")

    history_orphans = cur.execute("SELECT COUNT(*) FROM history WHERE user_id IS NULL").fetchone()[0]
    cache_orphans = cur.execute("SELECT COUNT(*) FROM cache WHERE user_id IS NULL").fetchone()[0]
    print(f"history rows with no owner: {history_orphans}")
    print(f"cache rows with no owner:   {cache_orphans}")

    if args.dry_run:
        print("Dry run — no changes written.")
        conn.close()
        return

    cur.execute("UPDATE history SET user_id = ? WHERE user_id IS NULL", (args.user_id,))
    history_updated = cur.rowcount
    cur.execute("UPDATE cache SET user_id = ? WHERE user_id IS NULL", (args.user_id,))
    cache_updated = cur.rowcount
    conn.commit()
    conn.close()

    print(f"Assigned {history_updated} history row(s) and {cache_updated} cache row(s) to user_id={args.user_id}.")


if __name__ == "__main__":
    main()
