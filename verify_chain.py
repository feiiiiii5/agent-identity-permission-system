#!/usr/bin/env python3
import sys
import json
import hashlib
import sqlite3
from pathlib import Path


GENESIS_HASH = "0" * 64


def verify_chain(db_path: str) -> dict:
    if not Path(db_path).exists():
        return {"valid": False, "error": f"Database not found: {db_path}"}

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, log_id, prev_log_hash, log_hash, record_content, timestamp "
        "FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        return {"valid": True, "total_records": 0, "message": "No records to verify"}

    prev_hash = GENESIS_HASH
    broken_at = None

    for row in rows:
        row = dict(row)
        if row["prev_log_hash"] != prev_hash:
            broken_at = row
            break

        expected_hash = hashlib.sha256(
            (prev_hash + row["record_content"]).encode("utf-8")
        ).hexdigest()

        if row["log_hash"] != expected_hash:
            broken_at = row
            break

        prev_hash = row["log_hash"]

    if broken_at:
        return {
            "valid": False,
            "error_code": "CHAIN_BROKEN",
            "total_records": len(rows),
            "broken_at_id": broken_at["id"],
            "broken_at_timestamp": broken_at["timestamp"],
            "message": f"Chain broken at record {broken_at['id']}",
        }

    return {
        "valid": True,
        "total_records": len(rows),
        "last_hash": prev_hash,
        "message": f"All {len(rows)} records verified successfully",
    }


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/agentiam.db"
    result = verify_chain(db_path)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    if result["valid"]:
        print(f"\n✅ 审计链完整性验证通过! 共 {result.get('total_records', 0)} 条记录")
        sys.exit(0)
    else:
        print(f"\n❌ 审计链完整性验证失败!")
        print(f"   错误: {result.get('message', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
