import json
import time
import hashlib
import sqlite3
from typing import Optional


class BehaviorAnalyzer:

    BASELINE_SAMPLE_SIZE = 10
    BASELINE_UPDATE_INTERVAL_SECONDS = 86400
    ANOMALY_THRESHOLD_STD = 2.0
    CRITICAL_THRESHOLD_STD = 3.0

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS behavior_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                capabilities TEXT DEFAULT '[]',
                delegation_depth INTEGER DEFAULT 0,
                target_agent TEXT DEFAULT '',
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS behavior_baselines (
                agent_id TEXT PRIMARY KEY,
                avg_request_interval REAL DEFAULT 0.0,
                common_capability_combos TEXT DEFAULT '[]',
                typical_chain_depth REAL DEFAULT 0.0,
                peak_hours TEXT DEFAULT '[]',
                baseline_hash TEXT DEFAULT '',
                sample_count INTEGER DEFAULT 0,
                last_updated REAL DEFAULT 0,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_obs_agent ON behavior_observations(agent_id);
        """)
        conn.commit()
        conn.close()

    def record_observation(
        self,
        agent_id: str,
        capabilities: list,
        delegation_depth: int = 0,
        target_agent: str = "",
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO behavior_observations
            (agent_id, capabilities, delegation_depth, target_agent, timestamp)
            VALUES (?, ?, ?, ?, ?)""",
            (agent_id, json.dumps(capabilities), delegation_depth, target_agent, now),
        )

        obs_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM behavior_observations WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()["cnt"]

        if obs_count >= self.BASELINE_SAMPLE_SIZE:
            existing = conn.execute(
                "SELECT agent_id FROM behavior_baselines WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if not existing:
                self._build_baseline(conn, agent_id)
            else:
                last_updated = conn.execute(
                    "SELECT last_updated FROM behavior_baselines WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()["last_updated"]
                if now - last_updated > self.BASELINE_UPDATE_INTERVAL_SECONDS:
                    self._update_baseline(conn, agent_id)

        conn.commit()
        conn.close()

        return {"recorded": True, "agent_id": agent_id, "observation_count": obs_count}

    def _build_baseline(self, conn, agent_id: str):
        rows = conn.execute(
            "SELECT * FROM behavior_observations WHERE agent_id = ? ORDER BY timestamp ASC",
            (agent_id,),
        ).fetchall()

        if len(rows) < self.BASELINE_SAMPLE_SIZE:
            return

        timestamps = [r["timestamp"] for r in rows]
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i - 1])
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0

        cap_combos = {}
        for r in rows:
            try:
                caps = json.loads(r["capabilities"])
                key = ",".join(sorted(caps))
                cap_combos[key] = cap_combos.get(key, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass
        common_combos = sorted(cap_combos.items(), key=lambda x: -x[1])[:5]
        common_combos = [c[0] for c in common_combos]

        depths = [r["delegation_depth"] for r in rows]
        avg_depth = sum(depths) / len(depths) if depths else 0.0

        hours = [time.localtime(r["timestamp"]).tm_hour for r in rows]
        hour_counts = {}
        for h in hours:
            hour_counts[h] = hour_counts.get(h, 0) + 1
        peak_hours = sorted(hour_counts.items(), key=lambda x: -x[1])[:3]
        peak_hours = [h[0] for h in peak_hours]

        baseline_data = {
            "avg_interval": avg_interval,
            "common_combos": common_combos,
            "avg_depth": avg_depth,
            "peak_hours": peak_hours,
        }
        baseline_hash = hashlib.sha256(
            json.dumps(baseline_data, sort_keys=True).encode()
        ).hexdigest()

        now = time.time()
        conn.execute(
            """INSERT OR REPLACE INTO behavior_baselines
            (agent_id, avg_request_interval, common_capability_combos, typical_chain_depth,
             peak_hours, baseline_hash, sample_count, last_updated, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (agent_id, avg_interval, json.dumps(common_combos), avg_depth,
             json.dumps(peak_hours), baseline_hash, len(rows), now, now),
        )

    def _update_baseline(self, conn, agent_id: str):
        now = time.time()
        cutoff = now - self.BASELINE_UPDATE_INTERVAL_SECONDS
        conn.execute(
            "DELETE FROM behavior_observations WHERE agent_id = ? AND timestamp < ?",
            (agent_id, cutoff),
        )
        self._build_baseline(conn, agent_id)

    def check_anomaly(self, agent_id: str, capabilities: list = None, delegation_depth: int = 0) -> dict:
        conn = self._get_conn()
        baseline_row = conn.execute(
            "SELECT * FROM behavior_baselines WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        conn.close()

        if not baseline_row:
            return {"has_baseline": False, "is_anomaly": False, "anomaly_level": "none"}

        baseline = dict(baseline_row)
        avg_interval = baseline["avg_request_interval"]
        avg_depth = baseline["typical_chain_depth"]

        conn = self._get_conn()
        recent = conn.execute(
            "SELECT timestamp FROM behavior_observations WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 2",
            (agent_id,),
        ).fetchall()
        conn.close()

        current_interval = 0
        if len(recent) >= 2:
            current_interval = recent[0]["timestamp"] - recent[1]["timestamp"]

        interval_deviation = 0
        if avg_interval > 0:
            interval_deviation = abs(current_interval - avg_interval) / avg_interval

        depth_deviation = 0
        if avg_depth > 0:
            depth_deviation = abs(delegation_depth - avg_depth) / avg_depth

        total_deviation = (interval_deviation + depth_deviation) / 2

        if total_deviation >= self.CRITICAL_THRESHOLD_STD:
            return {
                "has_baseline": True,
                "is_anomaly": True,
                "anomaly_level": "critical",
                "deviation": total_deviation,
                "interval_deviation": interval_deviation,
                "depth_deviation": depth_deviation,
                "action": "revoke_token",
            }
        elif total_deviation >= self.ANOMALY_THRESHOLD_STD:
            return {
                "has_baseline": True,
                "is_anomaly": True,
                "anomaly_level": "warning",
                "deviation": total_deviation,
                "interval_deviation": interval_deviation,
                "depth_deviation": depth_deviation,
                "action": "alert",
            }

        return {
            "has_baseline": True,
            "is_anomaly": False,
            "anomaly_level": "none",
            "deviation": total_deviation,
        }

    def get_baseline_data(self, agent_id: str) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM behavior_baselines WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        conn.close()

        if not row:
            return {"has_baseline": False}

        baseline = dict(row)
        for field in ["common_capability_combos", "peak_hours"]:
            try:
                baseline[field] = json.loads(baseline[field])
            except (json.JSONDecodeError, TypeError):
                baseline[field] = []

        return {"has_baseline": True, "baseline": baseline}
