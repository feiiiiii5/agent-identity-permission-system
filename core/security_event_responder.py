import json
import time
import uuid
import threading
import logging
from typing import Optional
from collections import OrderedDict
from core.db_pool import get_pool

logger = logging.getLogger(__name__)


class SecurityEventResponder:

    RULE_INJECTION_BLOCK = {
        "name": "注入攻击拦截+会话标记",
        "trigger": "injection_detected",
        "min_confidence": 0.7,
        "actions": ["block_request", "mark_session_high_risk", "write_critical_audit", "send_alert"],
        "session_risk_bonus": 30,
    }

    RULE_RATE_LIMIT = {
        "name": "连续失败限速",
        "trigger": "consecutive_deny",
        "threshold": 3,
        "window_seconds": 300,
        "actions": ["apply_rate_limit", "write_high_audit", "notify_user"],
        "rate_limit_per_minute": 10,
    }

    RULE_BATCH_APPROVAL = {
        "name": "批量数据强制审批",
        "trigger": "batch_data_request",
        "threshold_count": 100,
        "keywords": ["全部", "所有", "全量"],
        "actions": ["pause_execution", "create_approval_task", "notify_user"],
        "approval_timeout_minutes": 30,
    }

    RULE_OFF_HOUR_DELAY = {
        "name": "非工作时间延迟执行",
        "trigger": "off_hour_sensitive",
        "off_hours": (22, 7),
        "min_risk_score": 50,
        "actions": ["delay_execution", "record_intent", "notify_user"],
    }

    RULE_PRIVILEGE_REVOKE = {
        "name": "特权升级撤销Token",
        "trigger": "privilege_escalation",
        "actions": ["revoke_all_tokens", "close_circuit_breaker", "send_alert", "freeze_agent"],
        "freeze_duration_seconds": 300,
    }

    MAX_SESSION_RISK_ENTRIES = 5000
    MAX_DENY_COUNTER_ENTRIES = 5000
    MAX_DELAYED_OPERATIONS = 1000

    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self._pool = get_pool(db_path) if db_path else None
        self._session_risk = OrderedDict()
        self._deny_counter = OrderedDict()
        self._delayed_operations = []
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        if not self.db_path:
            return
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT DEFAULT '',
                rule_name TEXT DEFAULT '',
                risk_score REAL DEFAULT 0,
                actions_taken TEXT DEFAULT '[]',
                details TEXT DEFAULT '{}',
                timestamp REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS delayed_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT UNIQUE NOT NULL,
                user_id TEXT DEFAULT '',
                original_text TEXT DEFAULT '',
                intent TEXT DEFAULT '{}',
                risk_score REAL DEFAULT 0,
                scheduled_time REAL NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE NOT NULL,
                user_id TEXT DEFAULT '',
                original_text TEXT DEFAULT '',
                data_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                resolved_at REAL DEFAULT 0,
                result TEXT DEFAULT ''
            );
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

    def process_injection(self, user_id: str, scan_result: dict,
                          detection: dict, trace_id: str) -> dict:
        event_id = uuid.uuid4().hex[:16]
        confidence = scan_result.get("confidence", 0) if scan_result else 0

        if confidence < self.RULE_INJECTION_BLOCK["min_confidence"]:
            return {"event_id": event_id, "action": "log_only", "reason": "confidence_below_threshold"}

        with self._lock:
            self._add_session_risk(user_id, self.RULE_INJECTION_BLOCK["session_risk_bonus"])

        actions_taken = []
        for action in self.RULE_INJECTION_BLOCK["actions"]:
            actions_taken.append(action)

        self._record_event(event_id, "injection_block", user_id,
                           self.RULE_INJECTION_BLOCK["name"],
                           detection.get("threat_score", 90) if detection else 90,
                           actions_taken, {
                               "trace_id": trace_id,
                               "confidence": confidence,
                               "threat_types": [t.get("type", "") for t in scan_result.get("threats", [])] if scan_result else [],
                           })

        return {
            "event_id": event_id,
            "action": "block",
            "rule": self.RULE_INJECTION_BLOCK["name"],
            "actions_taken": actions_taken,
            "session_risk_bonus": self.RULE_INJECTION_BLOCK["session_risk_bonus"],
            "session_marked_high_risk": True,
        }

    def process_consecutive_deny(self, user_id: str, trace_id: str) -> dict:
        event_id = uuid.uuid4().hex[:16]
        now = time.time()

        with self._lock:
            if user_id not in self._deny_counter:
                self._deny_counter[user_id] = []

            self._deny_counter[user_id] = [
                t for t in self._deny_counter[user_id]
                if now - t < self.RULE_RATE_LIMIT["window_seconds"]
            ]
            self._deny_counter[user_id].append(now)
            deny_count = len(self._deny_counter[user_id])

        if deny_count >= self.RULE_RATE_LIMIT["threshold"]:
            actions_taken = list(self.RULE_RATE_LIMIT["actions"])

            self._record_event(event_id, "rate_limit", user_id,
                               self.RULE_RATE_LIMIT["name"], 70,
                               actions_taken, {
                                   "trace_id": trace_id,
                                   "deny_count": deny_count,
                                   "rate_limit_per_minute": self.RULE_RATE_LIMIT["rate_limit_per_minute"],
                               })

            return {
                "event_id": event_id,
                "action": "rate_limit",
                "rule": self.RULE_RATE_LIMIT["name"],
                "deny_count": deny_count,
                "rate_limit_per_minute": self.RULE_RATE_LIMIT["rate_limit_per_minute"],
                "actions_taken": actions_taken,
            }

        return {
            "event_id": event_id,
            "action": "count_only",
            "deny_count": deny_count,
            "threshold": self.RULE_RATE_LIMIT["threshold"],
        }

    def process_batch_request(self, user_id: str, text: str, intent: dict,
                              trace_id: str) -> dict:
        event_id = uuid.uuid4().hex[:16]
        data_count = self._estimate_data_count(text, intent)
        is_batch = (
            data_count > self.RULE_BATCH_APPROVAL["threshold_count"] or
            any(kw in text for kw in self.RULE_BATCH_APPROVAL["keywords"])
        )

        if not is_batch:
            return {"event_id": event_id, "action": "allow", "data_count": data_count}

        task_id = uuid.uuid4().hex[:12]
        actions_taken = list(self.RULE_BATCH_APPROVAL["actions"])

        self._create_approval_task(task_id, user_id, text, data_count,
                                    intent.get("risk_score", 60))

        self._record_event(event_id, "batch_approval", user_id,
                           self.RULE_BATCH_APPROVAL["name"],
                           intent.get("risk_score", 60),
                           actions_taken, {
                               "trace_id": trace_id,
                               "task_id": task_id,
                               "data_count": data_count,
                               "approval_timeout_minutes": self.RULE_BATCH_APPROVAL["approval_timeout_minutes"],
                           })

        return {
            "event_id": event_id,
            "action": "require_approval",
            "rule": self.RULE_BATCH_APPROVAL["name"],
            "task_id": task_id,
            "data_count": data_count,
            "approval_timeout_minutes": self.RULE_BATCH_APPROVAL["approval_timeout_minutes"],
            "actions_taken": actions_taken,
        }

    def process_off_hour_request(self, user_id: str, text: str, intent: dict,
                                  trace_id: str) -> dict:
        event_id = uuid.uuid4().hex[:16]
        hour = time.localtime().tm_hour
        off_start, off_end = self.RULE_OFF_HOUR_DELAY["off_hours"]

        is_off_hour = hour >= off_start or hour < off_end
        risk_score = intent.get("risk_score", 0)

        if not is_off_hour or risk_score < self.RULE_OFF_HOUR_DELAY["min_risk_score"]:
            return {"event_id": event_id, "action": "allow", "is_off_hour": is_off_hour}

        operation_id = uuid.uuid4().hex[:12]
        scheduled_time = self._next_workday_start()

        self._delayed_operations.append({
            "operation_id": operation_id,
            "user_id": user_id,
            "original_text": text,
            "intent": intent,
            "risk_score": risk_score,
            "scheduled_time": scheduled_time,
        })
        while len(self._delayed_operations) > self.MAX_DELAYED_OPERATIONS:
            self._delayed_operations.pop(0)

        self._record_delayed_operation(operation_id, user_id, text, intent, risk_score, scheduled_time)

        actions_taken = list(self.RULE_OFF_HOUR_DELAY["actions"])

        self._record_event(event_id, "off_hour_delay", user_id,
                           self.RULE_OFF_HOUR_DELAY["name"],
                           risk_score, actions_taken, {
                               "trace_id": trace_id,
                               "operation_id": operation_id,
                               "scheduled_time": scheduled_time,
                               "current_hour": hour,
                           })

        return {
            "event_id": event_id,
            "action": "delay",
            "rule": self.RULE_OFF_HOUR_DELAY["name"],
            "operation_id": operation_id,
            "scheduled_time": scheduled_time,
            "current_hour": hour,
            "actions_taken": actions_taken,
        }

    def process_privilege_escalation(self, user_id: str, agent_id: str,
                                      trace_id: str, auth_server=None) -> dict:
        event_id = uuid.uuid4().hex[:16]
        actions_taken = []
        results = {}

        for action in self.RULE_PRIVILEGE_REVOKE["actions"]:
            actions_taken.append(action)
            if action == "revoke_all_tokens" and auth_server:
                try:
                    revoke_result = auth_server.token_manager.revoke_all_agent_tokens(agent_id)
                    results["revoke"] = revoke_result
                except Exception as e:
                    results["revoke_error"] = str(e)
            elif action == "close_circuit_breaker" and auth_server:
                try:
                    auth_server.circuit_breaker.record_failure(agent_id, "PRIVILEGE_ESCALATION")
                    results["circuit_breaker"] = "opened"
                except Exception as e:
                    results["cb_error"] = str(e)
            elif action == "freeze_agent" and auth_server:
                try:
                    auth_server.freeze_agent(agent_id)
                    results["freeze"] = True
                except Exception as e:
                    results["freeze_error"] = str(e)

        with self._lock:
            self._add_session_risk(user_id, 40)

        self._record_event(event_id, "privilege_escalation", user_id,
                           self.RULE_PRIVILEGE_REVOKE["name"], 95,
                           actions_taken, {
                               "trace_id": trace_id,
                               "agent_id": agent_id,
                               "results": results,
                           })

        return {
            "event_id": event_id,
            "action": "revoke_and_freeze",
            "rule": self.RULE_PRIVILEGE_REVOKE["name"],
            "agent_id": agent_id,
            "actions_taken": actions_taken,
            "results": results,
            "freeze_duration": self.RULE_PRIVILEGE_REVOKE["freeze_duration_seconds"],
        }

    def get_session_risk(self, user_id: str) -> int:
        with self._lock:
            return self._session_risk.get(user_id, 0)

    def is_session_high_risk(self, user_id: str) -> bool:
        with self._lock:
            return self._session_risk.get(user_id, 0) >= 30

    def check_rate_limited(self, user_id: str) -> bool:
        now = time.time()
        with self._lock:
            if user_id not in self._deny_counter:
                return False
            recent = [t for t in self._deny_counter[user_id] if now - t < 300]
            return len(recent) >= self.RULE_RATE_LIMIT["threshold"]

    def get_pending_approvals(self) -> list:
        conn = self._get_conn()
        if not conn:
            return []
        rows = conn.execute(
            "SELECT * FROM approval_tasks WHERE status = 'pending' ORDER BY created_at DESC"
        ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]

    def resolve_approval(self, task_id: str, approved: bool) -> dict:
        conn = self._get_conn()
        if not conn:
            return {"task_id": task_id, "status": "error", "reason": "no_db"}
        now = time.time()
        status = "approved" if approved else "rejected"
        conn.execute(
            "UPDATE approval_tasks SET status = ?, resolved_at = ?, result = ? WHERE task_id = ?",
            (status, now, status, task_id),
        )
        conn.commit()
        self._return_conn(conn)
        return {"task_id": task_id, "status": status}

    def get_delayed_operations(self) -> list:
        return self._delayed_operations

    def process_due_delayed_operations(self) -> list:
        now = time.time()
        due = [op for op in self._delayed_operations if op["scheduled_time"] <= now]
        self._delayed_operations = [op for op in self._delayed_operations if op["scheduled_time"] > now]
        return due

    def _add_session_risk(self, user_id: str, bonus: int):
        current = self._session_risk.get(user_id, 0)
        self._session_risk[user_id] = min(100, current + bonus)
        while len(self._session_risk) > self.MAX_SESSION_RISK_ENTRIES:
            self._session_risk.popitem(last=False)

    def _estimate_data_count(self, text: str, intent: dict) -> int:
        count = 1
        lower = text.lower()

        if any(w in lower for w in ["所有", "全部", "全量", "完整"]):
            count = 500
        elif any(w in lower for w in ["批量"]):
            count = 200

        scope = intent.get("scope", "self")
        if scope == "company":
            count = max(count, 500)
        elif scope == "cross_department":
            count = max(count, 100)

        return count

    def _next_workday_start(self) -> float:
        import datetime
        now = datetime.datetime.now()
        if now.hour >= 22:
            next_7 = now.replace(hour=7, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
        else:
            next_7 = now.replace(hour=7, minute=0, second=0, microsecond=0)
        return next_7.timestamp()

    def _record_event(self, event_id: str, event_type: str, user_id: str,
                      rule_name: str, risk_score: float, actions_taken: list,
                      details: dict):
        conn = self._get_conn()
        if not conn:
            return
        try:
            conn.execute(
                """INSERT INTO security_events (event_id, event_type, user_id, rule_name, risk_score, actions_taken, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, event_type, user_id, rule_name, risk_score,
                 json.dumps(actions_taken), json.dumps(details), time.time()),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to record event: %s", e)
        finally:
            self._return_conn(conn)

    def _create_approval_task(self, task_id: str, user_id: str, text: str,
                               data_count: int, risk_score: float):
        conn = self._get_conn()
        if not conn:
            return
        try:
            conn.execute(
                """INSERT INTO approval_tasks (task_id, user_id, original_text, data_count, risk_score, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                (task_id, user_id, text[:200], data_count, risk_score, time.time()),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to create approval task: %s", e)
        finally:
            self._return_conn(conn)

    def _record_delayed_operation(self, operation_id: str, user_id: str,
                                   text: str, intent: dict, risk_score: float,
                                   scheduled_time: float):
        conn = self._get_conn()
        if not conn:
            return
        try:
            conn.execute(
                """INSERT INTO delayed_operations (operation_id, user_id, original_text, intent, risk_score, scheduled_time, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (operation_id, user_id, text[:200], json.dumps(intent, default=str),
                 risk_score, scheduled_time, time.time()),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to record delayed operation: %s", e)
        finally:
            self._return_conn(conn)
