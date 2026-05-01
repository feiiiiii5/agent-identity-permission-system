#!/usr/bin/env python3
"""Verify the integrity of the audit log chain."""
import sys
import sqlite3
import hashlib
import json
from pathlib import Path


def verify_chain(db_path: str) -> dict:
    if not Path(db_path).exists():
        return {"valid": False, "error": "Database not found", "total_records": 0}

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT log_id, prev_log_hash, log_hash, record_content FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        return {"valid": True, "total_records": 0, "message": "No records to verify"}

    GENESIS_HASH = "0" * 64
    prev_hash = GENESIS_HASH
    broken_at = None

    for i, row in enumerate(rows):
        if i == 0:
            if row["prev_log_hash"] != GENESIS_HASH:
                broken_at = i
                break
        else:
            if row["prev_log_hash"] != prev_hash:
                broken_at = i
                break

        computed = hashlib.sha256(
            (row["prev_log_hash"] + row["record_content"]).encode("utf-8")
        ).hexdigest()

        if row["log_hash"] != computed:
            broken_at = i
            break

        prev_hash = row["log_hash"]

    if broken_at is not None:
        return {
            "valid": False,
            "total_records": len(rows),
            "broken_at_record": broken_at,
            "broken_log_id": rows[broken_at]["log_id"],
            "expected_prev_hash": prev_hash,
            "actual_prev_hash": rows[broken_at]["prev_log_hash"],
        }

    return {
        "valid": True,
        "total_records": len(rows),
        "first_hash": rows[0]["log_hash"][:16],
        "last_hash": rows[-1]["log_hash"][:16],
    }


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/agentiam.db"
    result = verify_chain(db_path)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result["valid"] else 1)
