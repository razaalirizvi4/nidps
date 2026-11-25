"""CLI to seed the first (or an additional) admin_user row. Usage:
    python -m services.dashboard.create_admin <db_path> <username> <password>
No other service auto-creates admin_user rows -- the operator runs this once, during initial
device setup, outside the web flow (there is no "register" screen -- FR-9.1 only requires login,
not self-service account creation)."""
from __future__ import annotations

import argparse
import sys

from common.db.migrate import connect
from services.dashboard.auth import create_admin_user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a NIDPS dashboard admin user")
    parser.add_argument("db_path")
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()

    conn = connect(args.db_path)
    try:
        user_id = create_admin_user(conn, args.username, args.password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Created admin_user {args.username!r} with user_id={user_id}")


if __name__ == "__main__":
    main()
