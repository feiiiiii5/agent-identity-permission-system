import json
import time
import logging
import threading
from typing import Optional
from collections import OrderedDict
from core.db_pool import get_pool

logger = logging.getLogger(__name__)


class IncidentResponder:

    SEVERITY_LEVELS = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    AUTO_RESPONSE_RULES = [
        {
            "trigger_type": "privilege_escalation",
            "min_severity": "high",
            "action": "revoke_all_tokens",
            "cooldown_seconds": 60,
        },
        {
            "trigger_type": "injection_detected",
            "min_severity": "critical",
            "action": "freeze_agent",
            "cooldown_seconds": 120,
        },
        {
            "trigger_type": "risk_score_critical",
            "min_severity": "critical",
            "action": "freeze_agent",
            "cooldown_seconds": 300,
        },
        {
            "trigger_type": "circuit_breaker_open",
            "min_severity": "high",
            "action": "notify_admin",
            "cooldown_seconds": 60,
        },
        {
            "trigger_type": "session_hijack",
            "min_severity": "high",
            "action": "revoke_session_tokens",
            "cooldown_seconds": 30,
        },
        {
            "trigger_type": "svid_expired",
            "min_severity": "medium",
            "action": "rotate_svid",
            "cooldown_seconds": 0,
        },
    ]

    MAX_LAST_ACTION_ENTRIES = 5000

    def __init__(self, db_path: str = "", ws_notify=None):
        self.db_path = db_path
        self._pool = get_pool(db_path) if db_path else None
        if self._pool:
            self._init_db()
        self._ws_notify = ws_notify
        self._last_action_time = OrderedDict()
        self._lock = threading.Lock()

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                agent_id TEXT DEFAULT '',
                description TEXT DEFAULT '',
                auto_action TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                created_at REAL NOT NULL,
                resolved_at REAL DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(incident_type);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents(agent_id);
        """)
        conn.commit()
        self._return_conn(conn)

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        if conn and self._pool:
            self._pool.return_connection(conn)

    def set_ws_notify(self, func):
        self._ws_notify = func

    def _notify(self, event_type: str, data: dict):
        if self._ws_notify:
            try:
                self._ws_notify(event_type, data)
            except Exception as e:
                logger.warning("WebSocket notification failed: %s", e)

    def _check_cooldown(self, rule: dict, agent_id: str) -> bool:
        key = f"{rule['trigger_type']}:{agent_id}"
        last_time = self._last_action_time.get(key, 0)
        if time.time() - last_time < rule["cooldown_seconds"]:
            return False
        return True

    def process_event(self, event_type: str, severity: str, agent_id: str = "",
                      description: str = "", metadata: dict = None) -> dict:
        if metadata is None:
            metadata = {}

        conn = self._get_conn()
        now = time.time()
        conn.execute(
            """INSERT INTO incidents (incident_type, severity, agent_id, description, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (event_type, severity, agent_id, description, now, json.dumps(metadata)),
        )
        conn.commit()
        incident_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        self._return_conn(conn)

        auto_action = None
        for rule in self.AUTO_RESPONSE_RULES:
            if rule["trigger_type"] == event_type:
                if self.SEVERITY_LEVELS.get(severity, 0) >= self.SEVERITY_LEVELS.get(rule["min_severity"], 0):
                    if self._check_cooldown(rule, agent_id):
                        auto_action = rule["action"]
                        key = f"{rule['trigger_type']}:{agent_id}"
                        self._last_action_time[key] = now
                        while len(self._last_action_time) > self.MAX_LAST_ACTION_ENTRIES:
                            self._last_action_time.popitem(last=False)
                        break

        result = {
            "incident_id": incident_id,
            "event_type": event_type,
            "severity": severity,
            "agent_id": agent_id,
            "auto_action": auto_action,
        }

        self._notify("incident_created", result)

        return result

    def execute_auto_response(self, action: str, agent_id: str, auth_server) -> dict:
        if action == "revoke_all_tokens":
            result = auth_server.token_manager.revoke_all_agent_tokens(agent_id)
            auth_server.circuit_breaker.record_failure(agent_id, "AUTO_REVOKE")
            self._notify("auto_response", {"action": action, "agent_id": agent_id, "result": result})
            return {"action": "revoke_all_tokens", "agent_id": agent_id, "revoked_count": result.get("revoked_count", 0)}

        elif action == "freeze_agent":
            conn = self._get_conn()
            conn.execute("UPDATE agents SET status = 'frozen' WHERE agent_id = ?", (agent_id,))
            conn.commit()
            self._return_conn(conn)
            result = auth_server.token_manager.revoke_all_agent_tokens(agent_id)
            auth_server.circuit_breaker.record_failure(agent_id, "AUTO_FREEZE")
            self._notify("auto_response", {"action": action, "agent_id": agent_id})
            return {"action": "freeze_agent", "agent_id": agent_id, "revoked_count": result.get("revoked_count", 0)}

        elif action == "revoke_session_tokens":
            result = auth_server.token_manager.revoke_all_agent_tokens(agent_id)
            self._notify("auto_response", {"action": action, "agent_id": agent_id})
            return {"action": "revoke_session_tokens", "agent_id": agent_id, "revoked_count": result.get("revoked_count", 0)}

        elif action == "rotate_svid":
            try:
                new_svid = auth_server.svid_manager.rotate_svid(agent_id)
                self._notify("auto_response", {"action": action, "agent_id": agent_id})
                return {"action": "rotate_svid", "agent_id": agent_id, "new_spiffe_id": new_svid.spiffe_id}
            except Exception as e:
                return {"action": "rotate_svid", "agent_id": agent_id, "error": str(e)}

        elif action == "notify_admin":
            self._notify("admin_alert", {
                "action": "notify_admin",
                "agent_id": agent_id,
                "message": f"Security alert for agent {agent_id}",
            })
            return {"action": "notify_admin", "agent_id": agent_id}

        return {"action": action, "agent_id": agent_id, "status": "unknown_action"}

    def resolve_incident(self, incident_id: int, resolution: str = "") -> dict:
        conn = self._get_conn()
        now = time.time()
        cursor = conn.execute(
            "UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE id = ? AND status = 'open'",
            (now, incident_id),
        )
        conn.commit()
        resolved = cursor.rowcount > 0
        self._return_conn(conn)
        return {"incident_id": incident_id, "resolved": resolved}

    def get_open_incidents(self, agent_id: str = None, limit: int = 50) -> list:
        conn = self._get_conn()
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status = 'open' AND agent_id = ? ORDER BY created_at DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status = 'open' ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]

    def get_incident_stats(self) -> dict:
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()["cnt"]
        open_count = conn.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'open'").fetchone()["cnt"]
        resolved = conn.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'resolved'").fetchone()["cnt"]
        by_severity = {}
        for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity").fetchall():
            by_severity[row["severity"]] = row["cnt"]
        by_type = {}
        for row in conn.execute("SELECT incident_type, COUNT(*) as cnt FROM incidents GROUP BY incident_type").fetchall():
            by_type[row["incident_type"]] = row["cnt"]
        self._return_conn(conn)
        return {
            "total": total,
            "open": open_count,
            "resolved": resolved,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def generate_compliance_report(self) -> dict:
        conn = self._get_conn()
        now = time.time()
        last_24h = now - 86400
        last_7d = now - 86400 * 7

        total_agents = conn.execute("SELECT COUNT(*) as cnt FROM agents").fetchone()["cnt"]
        active_agents = conn.execute("SELECT COUNT(*) as cnt FROM agents WHERE status = 'active'").fetchone()["cnt"]
        frozen_agents = conn.execute("SELECT COUNT(*) as cnt FROM agents WHERE status = 'frozen'").fetchone()["cnt"]

        tokens_issued_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE action_type = 'token_issue' AND decision = 'ALLOW' AND timestamp > ?",
            (last_24h,),
        ).fetchone()["cnt"]
        tokens_denied_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE action_type = 'token_issue' AND decision = 'DENY' AND timestamp > ?",
            (last_24h,),
        ).fetchone()["cnt"]
        delegations_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE action_type = 'token_delegate' AND timestamp > ?",
            (last_24h,),
        ).fetchone()["cnt"]
        injections_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE injection_detected = 1 AND timestamp > ?",
            (last_24h,),
        ).fetchone()["cnt"]
        escalations_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE privilege_escalation_detected = 1 AND timestamp > ?",
            (last_24h,),
        ).fetchone()["cnt"]

        incidents_24h = conn.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE created_at > ?", (last_24h,)
        ).fetchone()["cnt"]
        incidents_7d = conn.execute(
            "SELECT COUNT(*) as cnt FROM incidents WHERE created_at > ?", (last_7d,)
        ).fetchone()["cnt"]

        audit_integrity = True
        try:
            from core.audit_logger import AuditLogger
            al = AuditLogger(self.db_path)
            integrity = al.verify_integrity()
            audit_integrity = integrity.get("valid", False)
        except Exception as e:
            logger.warning("Audit integrity check failed: %s", e)

        self._return_conn(conn)

        compliance_score = 100
        if frozen_agents > 0:
            compliance_score -= frozen_agents * 5
        if injections_24h > 0:
            compliance_score -= injections_24h * 10
        if escalations_24h > 0:
            compliance_score -= escalations_24h * 15
        if not audit_integrity:
            compliance_score -= 20
        if tokens_denied_24h > tokens_issued_24h * 0.1:
            compliance_score -= 10
        compliance_score = max(0, compliance_score)

        return {
            "report_timestamp": now,
            "compliance_score": compliance_score,
            "audit_chain_integrity": audit_integrity,
            "period": "24h",
            "agents": {
                "total": total_agents,
                "active": active_agents,
                "frozen": frozen_agents,
            },
            "tokens": {
                "issued_24h": tokens_issued_24h,
                "denied_24h": tokens_denied_24h,
                "delegations_24h": delegations_24h,
            },
            "security": {
                "injections_24h": injections_24h,
                "escalations_24h": escalations_24h,
                "incidents_24h": incidents_24h,
                "incidents_7d": incidents_7d,
            },
            "recommendations": self._generate_recommendations(
                compliance_score, frozen_agents, injections_24h, escalations_24h, audit_integrity
            ),
        }

    def _generate_recommendations(self, score, frozen, injections, escalations, integrity) -> list:
        recs = []
        if score < 80:
            recs.append("合规分数低于80，建议检查安全策略配置")
        if frozen > 0:
            recs.append(f"存在{frozen}个冻结Agent，建议审查并恢复或移除")
        if injections > 0:
            recs.append(f"过去24h检测到{injections}次注入攻击，建议加强输入过滤")
        if escalations > 0:
            recs.append(f"过去24h检测到{escalations}次权限升级，建议收紧能力分配")
        if not integrity:
            recs.append("审计链完整性验证失败，可能存在篡改，建议立即调查")
        if not recs:
            recs.append("系统运行正常，所有安全指标达标")
        return recs
