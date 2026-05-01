import time
import json
import sqlite3
from typing import Optional


class SystemMonitor:

    ALERT_THRESHOLDS = {
        "token_active_count": {"warning": 50, "critical": 100},
        "deny_rate_1h": {"warning": 10, "critical": 30},
        "risk_score_avg": {"warning": 50, "critical": 70},
        "circuit_breaker_open_count": {"warning": 1, "critical": 2},
        "injection_attempts_1h": {"warning": 3, "critical": 10},
        "privilege_escalation_1h": {"warning": 1, "critical": 3},
        "audit_chain_broken": {"warning": 0, "critical": 0},
        "agent_frozen_count": {"warning": 1, "critical": 2},
        "approval_timeout_rate": {"warning": 0.3, "critical": 0.5},
    }

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
        self._start_time = time.time()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS monitor_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning',
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                threshold REAL NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monitor_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_type TEXT NOT NULL,
                snapshot_data TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    def get_system_health(self, auth_server) -> dict:
        now = time.time()
        uptime = now - self._start_time

        conn = self._get_conn()
        agents = conn.execute("SELECT agent_id, agent_name, trust_score, status, capabilities FROM agents").fetchall()
        active_tokens = conn.execute("SELECT COUNT(*) as cnt FROM tokens WHERE is_revoked = 0 AND expires_at > ?", (now,)).fetchone()["cnt"]
        revoked_tokens = conn.execute("SELECT COUNT(*) as cnt FROM tokens WHERE is_revoked = 1").fetchone()["cnt"]
        total_tokens = conn.execute("SELECT COUNT(*) as cnt FROM tokens").fetchone()["cnt"]

        one_hour_ago = now - 3600
        recent_denies = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs WHERE decision = 'DENY' AND timestamp > ?", (one_hour_ago,)).fetchone()["cnt"]
        recent_allows = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs WHERE decision = 'ALLOW' AND timestamp > ?", (one_hour_ago,)).fetchone()["cnt"]
        recent_injections = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs WHERE injection_detected = 1 AND timestamp > ?", (one_hour_ago,)).fetchone()["cnt"]
        recent_escalations = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs WHERE privilege_escalation_detected = 1 AND timestamp > ?", (one_hour_ago,)).fetchone()["cnt"]
        total_audit = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()["cnt"]
        conn.close()

        agent_health = []
        frozen_count = 0
        total_risk = 0
        for a in agents:
            caps = json.loads(a["capabilities"]) if a["capabilities"] else []
            risk = auth_server.risk_scorer.compute_risk_score(a["agent_id"], caps)
            is_frozen = risk["risk_score"] >= 90
            if is_frozen:
                frozen_count += 1
            total_risk += risk["risk_score"]
            agent_health.append({
                "agent_id": a["agent_id"],
                "agent_name": a["agent_name"],
                "trust_score": a["trust_score"],
                "status": a["status"],
                "risk_score": risk["risk_score"],
                "risk_action": risk["action_taken"],
                "is_frozen": is_frozen,
            })

        avg_risk = total_risk / len(agents) if agents else 0

        cb_states = auth_server.circuit_breaker.get_all_states()
        open_cbs = sum(1 for v in cb_states.values() if v.get("state") == "OPEN")

        audit_integrity = auth_server.audit_logger.verify_integrity()

        total_recent = recent_denies + recent_allows
        deny_rate = (recent_denies / total_recent * 100) if total_recent > 0 else 0

        health_score = 100
        if frozen_count > 0:
            health_score -= frozen_count * 15
        if open_cbs > 0:
            health_score -= open_cbs * 10
        if not audit_integrity.get("valid", False):
            health_score -= 20
        if deny_rate > 30:
            health_score -= 10
        if recent_injections > 5:
            health_score -= 10
        health_score = max(0, health_score)

        if health_score >= 80:
            overall_status = "healthy"
        elif health_score >= 50:
            overall_status = "degraded"
        else:
            overall_status = "critical"

        metrics = {
            "token_active_count": active_tokens,
            "deny_rate_1h": deny_rate,
            "risk_score_avg": avg_risk,
            "circuit_breaker_open_count": open_cbs,
            "injection_attempts_1h": recent_injections,
            "privilege_escalation_1h": recent_escalations,
            "audit_chain_broken": 0 if audit_integrity.get("valid", False) else 1,
            "agent_frozen_count": frozen_count,
        }

        alerts = self._check_thresholds(metrics)

        return {
            "overall_status": overall_status,
            "health_score": health_score,
            "uptime_seconds": uptime,
            "uptime_human": self._format_uptime(uptime),
            "metrics": metrics,
            "agent_health": agent_health,
            "token_stats": {
                "active": active_tokens,
                "revoked": revoked_tokens,
                "total": total_tokens,
            },
            "audit_stats": {
                "total_records": total_audit,
                "deny_last_1h": recent_denies,
                "allow_last_1h": recent_allows,
                "injection_last_1h": recent_injections,
                "escalation_last_1h": recent_escalations,
                "chain_valid": audit_integrity.get("valid", False),
            },
            "circuit_breakers": cb_states,
            "active_alerts": alerts,
            "alert_count": len(alerts),
        }

    def _check_thresholds(self, metrics: dict) -> list:
        alerts = []
        for metric_name, value in metrics.items():
            thresholds = self.ALERT_THRESHOLDS.get(metric_name)
            if not thresholds:
                continue

            severity = None
            if value >= thresholds.get("critical", float("inf")):
                severity = "critical"
            elif value >= thresholds.get("warning", float("inf")):
                severity = "warning"

            if severity:
                alerts.append({
                    "metric": metric_name,
                    "value": value,
                    "threshold": thresholds[severity],
                    "severity": severity,
                    "message": f"{metric_name} = {value} (threshold: {thresholds[severity]})",
                })
                self._record_alert(metric_name, severity, value, thresholds[severity])

        return alerts

    def _record_alert(self, metric_name: str, severity: str, value: float, threshold: float):
        try:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO monitor_alerts (alert_type, severity, metric_name, metric_value, threshold, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (metric_name, severity, metric_name, value, threshold, f"{metric_name} = {value}", time.time()),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_alert_history(self, limit: int = 50, severity: str = None) -> list:
        conn = self._get_conn()
        if severity:
            rows = conn.execute(
                "SELECT * FROM monitor_alerts WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM monitor_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def _format_uptime(self, seconds: float) -> str:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        if minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
