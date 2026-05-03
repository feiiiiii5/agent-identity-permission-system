import json
import time
import uuid
import logging
import threading
from collections import OrderedDict
from core.db_pool import get_pool

logger = logging.getLogger(__name__)


class AlertManager:

    CHANNELS = ["feishu_bot", "websocket", "audit_log"]

    ALERT_RULES = [
        {"name": "high_risk_agent", "condition": "risk_score >= 70", "severity": "high", "channels": CHANNELS},
        {"name": "injection_attack", "condition": "injection_detected", "severity": "critical", "channels": CHANNELS},
        {"name": "privilege_escalation", "condition": "escalation_detected", "severity": "critical", "channels": CHANNELS},
        {"name": "audit_chain_broken", "condition": "chain_integrity_failed", "severity": "critical", "channels": CHANNELS},
        {"name": "mass_token_revocation", "condition": "revoked_count > 5", "severity": "high", "channels": ["feishu_bot", "websocket"]},
        {"name": "approval_timeout", "condition": "approval_timeout", "severity": "medium", "channels": ["feishu_bot"]},
        {"name": "circuit_breaker_open", "condition": "circuit_breaker_state == OPEN", "severity": "high", "channels": ["websocket"]},
        {"name": "behavior_anomaly", "condition": "anomaly_level == critical", "severity": "high", "channels": CHANNELS},
    ]

    SEVERITY_EMOJI = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }

    MAX_ACTIVE_ALERTS = 5000

    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self._pool = get_pool(db_path) if db_path else None
        self._feishu_bot = None
        self._ws_notify = None
        self._audit_logger = None
        self._active_alerts = OrderedDict()
        self._lock = threading.Lock()
        if db_path:
            self._init_db()

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                agent_id TEXT DEFAULT '',
                details TEXT DEFAULT '{}',
                channels TEXT DEFAULT '[]',
                acknowledged INTEGER DEFAULT 0,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_name);
            CREATE INDEX IF NOT EXISTS idx_alert_events_ack ON alert_events(acknowledged);
        """)
        conn.commit()
        self._return_conn(conn)

    def _get_conn(self):
        if not self.db_path:
            return None
        return self._pool.get_connection()

    def _return_conn(self, conn):
        if conn and self._pool:
            self._pool.return_connection(conn)

    def set_feishu_bot(self, bot):
        self._feishu_bot = bot

    def set_ws_notify(self, func):
        self._ws_notify = func

    def set_audit_logger(self, audit_logger):
        self._audit_logger = audit_logger

    def trigger(self, rule_name: str, agent_id: str, details: dict) -> dict:
        rule = None
        for r in self.ALERT_RULES:
            if r["name"] == rule_name:
                rule = r
                break
        if not rule:
            logger.warning(f"Alert rule not found: {rule_name}")
            return {"triggered": False, "reason": "rule_not_found"}

        alert_id = uuid.uuid4().hex[:16]
        severity = rule["severity"]
        channels = rule["channels"]
        now = time.time()

        alert = {
            "alert_id": alert_id,
            "rule_name": rule_name,
            "severity": severity,
            "agent_id": agent_id,
            "details": details,
            "channels": channels,
            "created_at": now,
        }

        self._active_alerts[alert_id] = alert
        while len(self._active_alerts) > self.MAX_ACTIVE_ALERTS:
            self._active_alerts.popitem(last=False)

        conn = self._get_conn()
        if conn:
            try:
                conn.execute(
                    """INSERT INTO alert_events (alert_id, rule_name, severity, agent_id, details, channels, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (alert_id, rule_name, severity, agent_id, json.dumps(details, ensure_ascii=False),
                     json.dumps(channels), now),
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error("Failed to save alert event to DB: %s", e)
            finally:
                self._return_conn(conn)

        for channel in channels:
            try:
                if channel == "feishu_bot":
                    self.send_to_feishu(alert)
                elif channel == "websocket":
                    self._send_to_ws(alert)
                elif channel == "audit_log":
                    self._send_to_audit(alert)
            except Exception as e:
                logger.error(f"Alert channel {channel} failed: {e}")

        logger.info(f"Alert triggered: {rule_name} severity={severity} agent={agent_id}")
        return {"triggered": True, "alert_id": alert_id, "severity": severity}

    def send_to_feishu(self, alert: dict):
        if not self._feishu_bot:
            return
        severity = alert.get("severity", "medium")
        emoji = self.SEVERITY_EMOJI.get(severity, "⚠️")
        rule_name = alert.get("rule_name", "unknown")
        agent_id = alert.get("agent_id", "")
        details = alert.get("details", {})
        alert_id = alert.get("alert_id", "")

        text = f"{emoji} AgentPass安全告警\n\n"
        text += f"📋 告警ID: {alert_id}\n"
        text += f"⚡ 严重等级: {severity.upper()}\n"
        text += f"📌 规则: {rule_name}\n"
        if agent_id:
            text += f"🤖 Agent: {agent_id}\n"
        if details:
            for key, value in list(details.items())[:5]:
                text += f"  • {key}: {value}\n"
        text += f"\n─────────────────\n"
        text += f"📊 审计：已记录 | 🕐 {time.strftime('%H:%M:%S', time.localtime(alert.get('created_at', time.time())))}"

        try:
            chat_ids = getattr(self._feishu_bot, '_poll_chat_ids', [])
            p2p = getattr(self._feishu_bot, '_p2p_chat_id', '')
            user_open_id = getattr(self._feishu_bot, '_user_open_id', '')
            if p2p:
                self._feishu_bot.send_message(chat_id=p2p, text=text)
            elif chat_ids:
                self._feishu_bot.send_message(chat_id=chat_ids[0], text=text)
            elif user_open_id:
                self._feishu_bot.send_message(user_id=user_open_id, text=text)
        except Exception as e:
            logger.error(f"Failed to send alert to Feishu: {e}")

    def _send_to_ws(self, alert: dict):
        if self._ws_notify:
            try:
                self._ws_notify("security_alert", alert)
            except Exception as e:
                logger.warning("WebSocket notification failed: %s", e)

    def _send_to_audit(self, alert: dict):
        if self._audit_logger:
            try:
                self._audit_logger.create_security_alert(
                    alert_type=alert.get("rule_name", "unknown"),
                    severity=alert.get("severity", "medium"),
                    message=f"Alert: {alert.get('rule_name', '')} for agent {alert.get('agent_id', '')}",
                    agent_id=alert.get("agent_id", ""),
                    details=json.dumps(alert.get("details", {}), ensure_ascii=False),
                )
            except Exception as e:
                logger.warning("Failed to send alert to audit logger: %s", e)

    def get_active_alerts(self) -> list:
        conn = self._get_conn()
        if not conn:
            return list(self._active_alerts.values())
        try:
            rows = conn.execute(
                "SELECT * FROM alert_events WHERE acknowledged = 0 ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
            self._return_conn(conn)
            return [dict(r) for r in rows]
        except Exception as e:
            self._return_conn(conn)
            logger.warning("Failed to query active alerts: %s", e)
            return list(self._active_alerts.values())

    def acknowledge_alert(self, alert_id: str) -> dict:
        conn = self._get_conn()
        if conn:
            try:
                conn.execute(
                    "UPDATE alert_events SET acknowledged = 1 WHERE alert_id = ?",
                    (alert_id,),
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error("Failed to acknowledge alert: %s", e)
            finally:
                self._return_conn(conn)
        if alert_id in self._active_alerts:
            del self._active_alerts[alert_id]
        return {"alert_id": alert_id, "acknowledged": True}

    def check_and_trigger(self, event_type: str, agent_id: str, data: dict):
        rule_map = {
            "risk_score_high": "high_risk_agent",
            "injection_detected": "injection_attack",
            "privilege_escalation": "privilege_escalation",
            "chain_broken": "audit_chain_broken",
            "mass_revocation": "mass_token_revocation",
            "approval_timeout": "approval_timeout",
            "circuit_breaker_open": "circuit_breaker_open",
            "behavior_anomaly": "behavior_anomaly",
        }
        rule_name = rule_map.get(event_type)
        if rule_name:
            return self.trigger(rule_name, agent_id, data)
        return {"triggered": False}
