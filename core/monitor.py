import time
import json
import sqlite3
import threading
import logging
from typing import Optional
from collections import OrderedDict

from core.db_pool import get_pool

logger = logging.getLogger(__name__)


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

    MAX_PERF_HISTORY = 1000

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._start_time = time.time()
        self._perf_history = OrderedDict()
        self._optimization_log = []
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

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
        self._return_conn(conn)

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
        self._return_conn(conn)

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
            self._return_conn(conn)
        except Exception as e:
            logger.error("Failed to record alert: %s", e)

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
        self._return_conn(conn)
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

    def record_performance(self, operation: str, duration_ms: float, metadata: dict = None):
        entry = {
            "operation": operation,
            "duration_ms": duration_ms,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        key = f"{operation}:{time.time()}"
        self._perf_history[key] = entry
        while len(self._perf_history) > self.MAX_PERF_HISTORY:
            self._perf_history.popitem(last=False)

    def get_performance_summary(self) -> dict:
        if not self._perf_history:
            return {"operations": {}, "total_samples": 0}
        ops = {}
        for entry in self._perf_history.values():
            op = entry["operation"]
            if op not in ops:
                ops[op] = {"count": 0, "total_ms": 0, "min_ms": float("inf"), "max_ms": 0}
            ops[op]["count"] += 1
            ops[op]["total_ms"] += entry["duration_ms"]
            ops[op]["min_ms"] = min(ops[op]["min_ms"], entry["duration_ms"])
            ops[op]["max_ms"] = max(ops[op]["max_ms"], entry["duration_ms"])

        for op in ops:
            ops[op]["avg_ms"] = round(ops[op]["total_ms"] / ops[op]["count"], 2)
            ops[op]["p95_ms"] = self._compute_percentile(op, 95)

        return {"operations": ops, "total_samples": len(self._perf_history)}

    def _compute_percentile(self, operation: str, percentile: float) -> float:
        durations = sorted([
            e["duration_ms"] for e in self._perf_history.values()
            if e["operation"] == operation
        ])
        if not durations:
            return 0
        idx = int(len(durations) * percentile / 100)
        idx = min(idx, len(durations) - 1)
        return round(durations[idx], 2)

    def run_self_assessment(self, auth_server) -> dict:
        health = self.get_system_health(auth_server)
        perf = self.get_performance_summary()

        recommendations = []

        if health["health_score"] < 80:
            recommendations.append({
                "area": "system_health",
                "severity": "high" if health["health_score"] < 50 else "medium",
                "message": f"系统健康分 {health['health_score']}/100，需要关注",
                "action": "检查活跃告警并处理",
            })

        metrics = health.get("metrics", {})
        if metrics.get("injection_attempts_1h", 0) > 3:
            recommendations.append({
                "area": "security",
                "severity": "high",
                "message": f"过去1小时注入尝试 {metrics['injection_attempts_1h']} 次",
                "action": "审查注入来源，考虑加强输入过滤规则",
            })

        if metrics.get("deny_rate_1h", 0) > 20:
            recommendations.append({
                "area": "access_control",
                "severity": "medium",
                "message": f"拒绝率 {metrics['deny_rate_1h']:.1f}% 偏高",
                "action": "审查权限策略是否过于严格或Agent行为异常",
            })

        for op, stats in perf.get("operations", {}).items():
            if stats["avg_ms"] > 500:
                recommendations.append({
                    "area": "performance",
                    "severity": "medium",
                    "message": f"操作 {op} 平均耗时 {stats['avg_ms']}ms",
                    "action": "考虑添加缓存或优化查询",
                })

        pool_stats = self._pool.stats()
        if pool_stats.get("wait_count", 0) > 10:
            recommendations.append({
                "area": "resource",
                "severity": "medium",
                "message": f"连接池等待 {pool_stats['wait_count']} 次",
                "action": "考虑增加连接池大小",
            })

        assessment = {
            "timestamp": time.time(),
            "health_score": health["health_score"],
            "overall_status": health["overall_status"],
            "performance_summary": perf,
            "recommendations": recommendations,
            "recommendation_count": len(recommendations),
            "pool_stats": pool_stats,
        }

        self._optimization_log.append(assessment)
        if len(self._optimization_log) > 100:
            self._optimization_log = self._optimization_log[-50:]

        return assessment

    def get_optimization_history(self, limit: int = 10) -> list:
        return self._optimization_log[-limit:]
