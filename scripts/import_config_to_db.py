"""
CLI wrapper around sources.app_config.ensure_seeded() — seeds app_config
from config.seed.json.

The app also calls ensure_seeded() itself on every startup (see web/app.py),
so this script isn't required for the app to boot. Use it to force a reseed
after editing config.seed.json, or to seed manually before running the CLI
(main.py doesn't auto-seed):

    python scripts/import_config_to_db.py --force

Note: known_malware / known_apt_actors / known_tools live in reference.db,
not ioc_cache.db — that file is committed to git as-is (see
sources/enrichment.py), so there's no separate seed step for it.
"""
import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from sources.app_config import ensure_seeded, DEFAULT_SEED_PATH


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Reseed even if the DB already has a config")
    parser.add_argument("--seed-file", default=DEFAULT_SEED_PATH, help="Path to the seed JSON file")
    args = parser.parse_args()

    seeded = ensure_seeded(seed_file=args.seed_file, force=args.force)
    if seeded:
        print(f"Seeded config from {args.seed_file} into the DB.")
    else:
        print("app_config already seeded — skipping (pass --force to reseed).")


if __name__ == "__main__":
    main()
