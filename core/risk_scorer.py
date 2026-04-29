import json
import time
import sqlite3


class RiskScorer:

    RISK_THRESHOLD_DOWNGRADE = 70
    RISK_THRESHOLD_FREEZE = 90
    RISK_THRESHOLD_REVOKE = 80
    FREEZE_DURATION_SECONDS = 300

    WEIGHT_REQUEST_FREQUENCY = 0.20
    WEIGHT_CHAIN_DEPTH = 0.20
    WEIGHT_TIME_PERIOD = 0.15
    WEIGHT_CAPABILITY_COMBO = 0.25
    WEIGHT_HISTORY_VIOLATIONS = 0.20

    DIMENSIONS = [
        "request_frequency",
        "chain_depth",
        "time_period",
        "capability_combo",
        "history_violations",
    ]

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def compute_risk_score(self, agent_id: str, capabilities: list) -> dict:
        conn = self._get_conn()

        agent_row = conn.execute(
            "SELECT trust_score FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        trust_score = agent_row["trust_score"] if agent_row else 50.0

        now = time.time()
        one_hour_ago = now - 3600
        freq_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE requesting_agent = ? AND timestamp > ?",
            (agent_id, one_hour_ago),
        ).fetchone()
        request_count = freq_row["cnt"] if freq_row else 0
        freq_risk = min(1.0, request_count / 50.0)

        depth_row = conn.execute(
            "SELECT MAX(attenuation_level) as max_depth FROM tokens WHERE agent_id = ? AND is_revoked = 0",
            (agent_id,),
        ).fetchone()
        max_depth = depth_row["max_depth"] if depth_row and depth_row["max_depth"] is not None else 0
        depth_risk = min(1.0, max_depth * 0.25)

        hour = time.localtime(now).tm_hour
        if hour < 6 or hour > 22:
            time_risk = 0.7
        elif hour < 8 or hour > 20:
            time_risk = 0.3
        else:
            time_risk = 0.1

        cap_count = len(capabilities)
        write_caps = [c for c in capabilities if ":write" in c or ":delete" in c]
        sensitive_caps = [c for c in capabilities if "contact" in c or "admin" in c]
        combo_risk = min(1.0, (cap_count * 0.08 + len(write_caps) * 0.15 + len(sensitive_caps) * 0.25))

        deny_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE requesting_agent = ? AND decision = 'DENY'",
            (agent_id,),
        ).fetchone()
        deny_count = deny_row["cnt"] if deny_row else 0
        inj_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE requesting_agent = ? AND injection_detected = 1",
            (agent_id,),
        ).fetchone()
        inj_count = inj_row["cnt"] if inj_row else 0
        history_risk = min(1.0, deny_count * 0.1 + inj_count * 0.25)

        conn.close()

        risk_score = (
            freq_risk * self.WEIGHT_REQUEST_FREQUENCY
            + depth_risk * self.WEIGHT_CHAIN_DEPTH
            + time_risk * self.WEIGHT_TIME_PERIOD
            + combo_risk * self.WEIGHT_CAPABILITY_COMBO
            + history_risk * self.WEIGHT_HISTORY_VIOLATIONS
        ) * 100

        trust_modifier = max(0, (100 - trust_score) / 200)
        risk_score = risk_score * (1 + trust_modifier)
        risk_score = round(min(risk_score, 100.0), 1)

        if risk_score >= self.RISK_THRESHOLD_FREEZE:
            action_taken = "freeze"
        elif risk_score >= self.RISK_THRESHOLD_REVOKE:
            action_taken = "revoke_tokens"
        elif risk_score >= self.RISK_THRESHOLD_DOWNGRADE:
            action_taken = "downgrade"
        elif risk_score >= 40:
            action_taken = "monitor"
        else:
            action_taken = "normal"

        return {
            "risk_score": risk_score,
            "action_taken": action_taken,
            "dimensions": {
                "request_frequency": round(freq_risk * 100, 1),
                "chain_depth": round(depth_risk * 100, 1),
                "time_period": round(time_risk * 100, 1),
                "capability_combo": round(combo_risk * 100, 1),
                "history_violations": round(history_risk * 100, 1),
            },
            "agent_id": agent_id,
            "thresholds": {
                "downgrade": self.RISK_THRESHOLD_DOWNGRADE,
                "freeze": self.RISK_THRESHOLD_FREEZE,
                "revoke": self.RISK_THRESHOLD_REVOKE,
            },
        }

    def update_trust_score(self, agent_id: str, delta: float) -> float:
        conn = self._get_conn()
        conn.execute(
            "UPDATE agents SET trust_score = MAX(0, MIN(100, trust_score + ?)) WHERE agent_id = ?",
            (delta, agent_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT trust_score FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        conn.close()
        return row["trust_score"] if row else 0.0
