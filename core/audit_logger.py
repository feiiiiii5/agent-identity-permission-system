import json
import time
import uuid
import hashlib
import sqlite3
import logging
import threading
from typing import Optional

from core.db_pool import get_pool

logger = logging.getLogger(__name__)


GENESIS_HASH = "0" * 64


class AuditLogger:

    HUMAN_APPROVAL_TIMEOUT_SECONDS = 30

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._last_verified_id = 0
        self._last_verified_hash = GENESIS_HASH
        self._write_lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id TEXT UNIQUE NOT NULL,
                prev_log_hash TEXT NOT NULL,
                log_hash TEXT NOT NULL,
                record_content TEXT NOT NULL,
                timestamp REAL NOT NULL,
                action_type TEXT DEFAULT '',
                requesting_agent TEXT DEFAULT '',
                target_agent TEXT DEFAULT '',
                requested_capability TEXT DEFAULT '',
                granted_capabilities TEXT DEFAULT '[]',
                denied_capabilities TEXT DEFAULT '[]',
                delegated_user TEXT DEFAULT '',
                trust_chain_snapshot TEXT DEFAULT '[]',
                attenuation_chain TEXT DEFAULT '[]',
                decision TEXT DEFAULT '',
                deny_reason TEXT DEFAULT '',
                risk_score REAL DEFAULT 0.0,
                injection_detected INTEGER DEFAULT 0,
                privilege_escalation_detected INTEGER DEFAULT 0,
                session_fingerprint TEXT DEFAULT '',
                human_approval_required INTEGER DEFAULT 0,
                human_approval_result TEXT DEFAULT '',
                error_code TEXT DEFAULT '',
                trace_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                message TEXT DEFAULT '',
                agent_id TEXT DEFAULT '',
                details TEXT DEFAULT '',
                timestamp REAL NOT NULL,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS risk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                risk_score REAL DEFAULT 0.0,
                action_taken TEXT DEFAULT '',
                timestamp REAL NOT NULL,
                details TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS human_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE NOT NULL,
                requesting_agent TEXT DEFAULT '',
                target_agent TEXT DEFAULT '',
                requested_capability TEXT DEFAULT '',
                session_id TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                resolved_at REAL DEFAULT 0,
                result TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS delegation_edges (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                deny_count INTEGER DEFAULT 0,
                last_decision TEXT DEFAULT '',
                last_timestamp REAL DEFAULT 0,
                PRIMARY KEY (source, target)
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(requesting_agent);
            CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);
            CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_logs(trace_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_ack ON security_alerts(acknowledged);
            CREATE INDEX IF NOT EXISTS idx_risk_agent ON risk_events(agent_id);

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                subject_id TEXT DEFAULT '',
                action TEXT DEFAULT '',
                resource TEXT DEFAULT '',
                matched_policy TEXT DEFAULT '',
                effect TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                evaluation_trace TEXT DEFAULT '[]',
                context TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS svid_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                agent_id TEXT NOT NULL,
                event_type TEXT DEFAULT '',
                spiffe_id TEXT DEFAULT '',
                expires_at REAL DEFAULT 0
            );
        """)
        conn.commit()
        self._return_conn(conn)

    def _get_last_hash(self, conn) -> str:
        row = conn.execute(
            "SELECT log_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["log_hash"] if row else GENESIS_HASH

    def write_log(
        self,
        requesting_agent: str,
        action_type: str,
        decision: str,
        deny_reason: str = "",
        error_code: str = "",
        injection_detected: bool = False,
        prompt_injection_flag: bool = False,
        target_agent: str = "",
        requested_capability: str = "",
        granted_capabilities: list = None,
        denied_capabilities: list = None,
        delegated_user: str = "",
        trust_chain_snapshot: list = None,
        attenuation_chain: list = None,
        risk_score: float = 0.0,
        session_fingerprint: str = "",
        privilege_escalation_detected: bool = False,
        human_approval_required: bool = False,
        human_approval_result: str = "",
        trace_id: str = "",
        decision_reason: str = "",
    ) -> dict:
        now = time.time()
        log_id = uuid.uuid4().hex

        if granted_capabilities is None:
            granted_capabilities = []
        if denied_capabilities is None:
            denied_capabilities = []
        if trust_chain_snapshot is None:
            trust_chain_snapshot = []
        if attenuation_chain is None:
            attenuation_chain = []

        record = {
            "log_id": log_id,
            "timestamp": now,
            "action_type": action_type,
            "requesting_agent": requesting_agent,
            "target_agent": target_agent,
            "requested_capability": requested_capability,
            "granted_capabilities": granted_capabilities,
            "denied_capabilities": denied_capabilities,
            "delegated_user": delegated_user,
            "trust_chain_snapshot": trust_chain_snapshot,
            "attenuation_chain": attenuation_chain,
            "decision": decision,
            "deny_reason": deny_reason or decision_reason,
            "risk_score": risk_score,
            "injection_detected": injection_detected,
            "privilege_escalation_detected": privilege_escalation_detected,
            "session_fingerprint": session_fingerprint,
            "human_approval_required": human_approval_required,
            "human_approval_result": human_approval_result,
            "error_code": error_code,
            "trace_id": trace_id,
        }

        record_content = json.dumps(record, sort_keys=True, ensure_ascii=False)

        conn = self._get_conn()
        try:
            with self._write_lock:
                prev_hash = self._get_last_hash(conn)
                log_hash = hashlib.sha256(
                    (prev_hash + record_content).encode("utf-8")
                ).hexdigest()

                conn.execute(
                    """INSERT INTO audit_logs
                    (log_id, prev_log_hash, log_hash, record_content, timestamp,
                     action_type, requesting_agent, target_agent, requested_capability,
                     granted_capabilities, denied_capabilities, delegated_user,
                     trust_chain_snapshot, attenuation_chain, decision, deny_reason,
                     risk_score, injection_detected, privilege_escalation_detected,
                     session_fingerprint, human_approval_required, human_approval_result,
                     error_code, trace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        log_id, prev_hash, log_hash, record_content, now,
                        action_type, requesting_agent, target_agent, requested_capability,
                        json.dumps(granted_capabilities), json.dumps(denied_capabilities),
                        delegated_user, json.dumps(trust_chain_snapshot),
                        json.dumps(attenuation_chain), decision, deny_reason or decision_reason,
                        risk_score, int(injection_detected), int(privilege_escalation_detected),
                        session_fingerprint, int(human_approval_required), human_approval_result,
                        error_code, trace_id,
                    ),
                )
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to write audit log: %s", e)
            raise
        finally:
            self._return_conn(conn)

        return {"log_id": log_id, "log_hash": log_hash, "decision": decision}

    def query_logs(
        self,
        requesting_agent: Optional[str] = None,
        decision: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        trace_id: Optional[str] = None,
    ) -> list:
        conn = self._get_conn()
        conditions = []
        params = []

        if requesting_agent:
            conditions.append("requesting_agent = ?")
            params.append(requesting_agent)
        if decision:
            conditions.append("decision = ?")
            params.append(decision.upper())
        if trace_id:
            conditions.append("trace_id = ?")
            params.append(trace_id)
        if time_range:
            now = time.time()
            if time_range == "1h":
                conditions.append("timestamp > ?")
                params.append(now - 3600)
            elif time_range == "24h":
                conditions.append("timestamp > ?")
                params.append(now - 86400)
            elif time_range == "7d":
                conditions.append("timestamp > ?")
                params.append(now - 604800)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM audit_logs{where} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        self._return_conn(conn)

        results = []
        for row in rows:
            r = dict(row)
            for field in ["granted_capabilities", "denied_capabilities", "trust_chain_snapshot", "attenuation_chain"]:
                try:
                    r[field] = json.loads(r.get(field, "[]"))
                except (json.JSONDecodeError, TypeError):
                    r[field] = []
            results.append(r)

        return results

    def verify_integrity(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, log_id, prev_log_hash, log_hash, record_content, timestamp "
            "FROM audit_logs ORDER BY id ASC"
        ).fetchall()
        self._return_conn(conn)

        if not rows:
            return {"valid": True, "total_records": 0, "message": "No records to verify"}

        prev_hash = GENESIS_HASH
        for row in rows:
            row = dict(row)
            if row["prev_log_hash"] != prev_hash:
                self._last_verified_id = 0
                self._last_verified_hash = GENESIS_HASH
                return {
                    "valid": False,
                    "error_code": "CHAIN_BROKEN",
                    "total_records": len(rows),
                    "broken_at_id": row["id"],
                    "broken_at_timestamp": row["timestamp"],
                    "message": f"Chain broken at record {row['id']}",
                }
            expected_hash = hashlib.sha256(
                (prev_hash + row["record_content"]).encode("utf-8")
            ).hexdigest()
            if row["log_hash"] != expected_hash:
                self._last_verified_id = 0
                self._last_verified_hash = GENESIS_HASH
                return {
                    "valid": False,
                    "error_code": "CHAIN_BROKEN",
                    "total_records": len(rows),
                    "broken_at_id": row["id"],
                    "broken_at_timestamp": row["timestamp"],
                    "message": f"Hash mismatch at record {row['id']}",
                }
            prev_hash = row["log_hash"]

        self._last_verified_id = rows[-1]["id"]
        self._last_verified_hash = prev_hash
        return {"valid": True, "total_records": len(rows), "last_hash": prev_hash}

    def verify_integrity_incremental(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, log_id, prev_log_hash, log_hash, record_content, timestamp "
            "FROM audit_logs WHERE id > ? ORDER BY id ASC",
            (self._last_verified_id,),
        ).fetchall()
        total_count = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs").fetchone()["cnt"]
        self._return_conn(conn)

        if not rows:
            return {
                "valid": True,
                "total_records": total_count,
                "verified_increment": 0,
                "last_verified_id": self._last_verified_id,
                "message": "No new records since last verification",
            }

        prev_hash = self._last_verified_hash
        if self._last_verified_id == 0 and rows:
            prev_hash = GENESIS_HASH

        for row in rows:
            row = dict(row)
            if row["prev_log_hash"] != prev_hash:
                self._last_verified_id = 0
                self._last_verified_hash = GENESIS_HASH
                return {
                    "valid": False,
                    "error_code": "CHAIN_BROKEN",
                    "total_records": total_count,
                    "broken_at_id": row["id"],
                    "broken_at_timestamp": row["timestamp"],
                    "message": f"Chain broken at record {row['id']}",
                }
            expected_hash = hashlib.sha256(
                (prev_hash + row["record_content"]).encode("utf-8")
            ).hexdigest()
            if row["log_hash"] != expected_hash:
                self._last_verified_id = 0
                self._last_verified_hash = GENESIS_HASH
                return {
                    "valid": False,
                    "error_code": "CHAIN_BROKEN",
                    "total_records": total_count,
                    "broken_at_id": row["id"],
                    "broken_at_timestamp": row["timestamp"],
                    "message": f"Hash mismatch at record {row['id']}",
                }
            prev_hash = row["log_hash"]

        self._last_verified_id = rows[-1]["id"]
        self._last_verified_hash = prev_hash
        return {
            "valid": True,
            "total_records": total_count,
            "verified_increment": len(rows),
            "last_verified_id": self._last_verified_id,
            "last_hash": prev_hash,
        }

    def get_all_trace_ids(self, limit: int = 50) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT trace_id,
                MIN(timestamp) as started_at,
                COUNT(*) as step_count,
                GROUP_CONCAT(DISTINCT requesting_agent) as agents,
                MAX(CASE WHEN decision = 'DENY' THEN 1 ELSE 0 END) as has_deny
            FROM audit_logs
            WHERE trace_id != '' AND trace_id IS NOT NULL
            GROUP BY trace_id
            ORDER BY started_at DESC
            LIMIT ?""",
            (limit,),
        ).fetchall()
        self._return_conn(conn)

        results = []
        for row in rows:
            r = dict(row)
            r["has_deny"] = bool(r.get("has_deny", 0))
            results.append(r)
        return results

    def get_audit_by_trace(self, trace_id: str) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE trace_id = ? ORDER BY id ASC",
            (trace_id,),
        ).fetchall()
        self._return_conn(conn)

        steps = []
        for row in rows:
            r = dict(row)
            for field in ["granted_capabilities", "denied_capabilities"]:
                try:
                    r[field] = json.loads(r.get(field, "[]"))
                except (json.JSONDecodeError, TypeError):
                    r[field] = []
            steps.append(r)

        return {
            "trace_id": trace_id,
            "step_count": len(steps),
            "steps": steps,
        }

    def create_security_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        agent_id: str = "",
        details: str = "",
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO security_alerts
            (alert_type, severity, message, agent_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (alert_type, severity, message, agent_id, details, now),
        )
        conn.commit()
        alert_id = cursor.lastrowid
        self._return_conn(conn)

        return {"alert_id": alert_id, "alert_type": alert_type, "severity": severity}

    def get_security_alerts(self, limit: int = 50, unacknowledged_only: bool = False) -> list:
        conn = self._get_conn()
        if unacknowledged_only:
            rows = conn.execute(
                "SELECT * FROM security_alerts WHERE acknowledged = 0 ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]

    def get_risk_events(self, agent_id: str = None, limit: int = 100) -> list:
        conn = self._get_conn()
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM risk_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM risk_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]

    def create_risk_event(
        self, agent_id: str, risk_score: float, action_taken: str, details: str = ""
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO risk_events
            (agent_id, risk_score, action_taken, timestamp, details)
            VALUES (?, ?, ?, ?, ?)""",
            (agent_id, risk_score, action_taken, now, details),
        )
        conn.commit()
        event_id = cursor.lastrowid
        self._return_conn(conn)
        return {"event_id": event_id, "agent_id": agent_id, "risk_score": risk_score}

    def create_human_approval(
        self,
        task_id: str,
        requesting_agent: str,
        target_agent: str,
        requested_capability: str,
        session_id: str = "",
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO human_approvals
                (task_id, requesting_agent, target_agent, requested_capability, session_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (task_id, requesting_agent, target_agent, requested_capability, session_id, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            self._return_conn(conn)
            return {"task_id": task_id, "status": "already_exists"}
        self._return_conn(conn)
        return {
            "task_id": task_id,
            "status": "pending",
            "requesting_agent": requesting_agent,
            "target_agent": target_agent,
            "requested_capability": requested_capability,
        }

    def get_pending_approvals(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM human_approvals WHERE status = 'pending' ORDER BY created_at DESC"
        ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]

    def resolve_human_approval(self, task_id: str, approved: bool) -> dict:
        now = time.time()
        status = "approved" if approved else "rejected"
        conn = self._get_conn()
        conn.execute(
            "UPDATE human_approvals SET status = ?, resolved_at = ?, result = ? WHERE task_id = ?",
            (status, now, status, task_id),
        )
        conn.commit()
        self._return_conn(conn)

        if not approved:
            self.write_log(
                requesting_agent="system",
                action_type="human_approval_timeout",
                decision="DENY",
                deny_reason="Human approval timeout - auto rejected",
                error_code="ERR_TIMEOUT_REJECTION",
                human_approval_required=True,
                human_approval_result="TIMEOUT_REJECTION",
            )

        return {"task_id": task_id, "status": status, "resolved_at": now}

    def check_and_timeout_approvals(self) -> list:
        conn = self._get_conn()
        now = time.time()
        timeout = self.HUMAN_APPROVAL_TIMEOUT_SECONDS
        rows = conn.execute(
            "SELECT * FROM human_approvals WHERE status = 'pending' AND created_at < ?",
            (now - timeout,),
        ).fetchall()

        timed_out = []
        for row in rows:
            r = dict(row)
            conn.execute(
                "UPDATE human_approvals SET status = 'timeout_rejected', resolved_at = ?, result = 'TIMEOUT_REJECTION' WHERE task_id = ?",
                (now, r["task_id"]),
            )
            self.write_log(
                requesting_agent=r.get("requesting_agent", "system"),
                action_type="human_approval_timeout",
                decision="DENY",
                deny_reason=f"Human approval timed out after {timeout}s for task {r['task_id']}",
                error_code="ERR_TIMEOUT_REJECTION",
                human_approval_required=True,
                human_approval_result="TIMEOUT_REJECTION",
            )
            timed_out.append(r["task_id"])

        conn.commit()
        self._return_conn(conn)
        return timed_out

    def update_delegation_edge(
        self, source: str, target: str, decision: str
    ):
        conn = self._get_conn()
        now = time.time()
        row = conn.execute(
            "SELECT * FROM delegation_edges WHERE source = ? AND target = ?",
            (source, target),
        ).fetchone()

        if row:
            if decision == "ALLOW":
                conn.execute(
                    "UPDATE delegation_edges SET success_count = success_count + 1, last_decision = ?, last_timestamp = ? WHERE source = ? AND target = ?",
                    (decision, now, source, target),
                )
            else:
                conn.execute(
                    "UPDATE delegation_edges SET deny_count = deny_count + 1, last_decision = ?, last_timestamp = ? WHERE source = ? AND target = ?",
                    (decision, now, source, target),
                )
        else:
            success = 1 if decision == "ALLOW" else 0
            deny = 0 if decision == "ALLOW" else 1
            conn.execute(
                "INSERT INTO delegation_edges (source, target, success_count, deny_count, last_decision, last_timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (source, target, success, deny, decision, now),
            )
        conn.commit()
        self._return_conn(conn)

    def get_system_metrics(self) -> dict:
        conn = self._get_conn()
        now = time.time()

        agent_count = conn.execute("SELECT COUNT(*) as cnt FROM agents").fetchone()["cnt"]
        token_stats = conn.execute(
            "SELECT "
            "  SUM(CASE WHEN is_revoked = 0 AND expires_at > ? THEN 1 ELSE 0 END) as active, "
            "  SUM(CASE WHEN is_revoked = 1 THEN 1 ELSE 0 END) as revoked "
            "FROM tokens",
            (now,),
        ).fetchone()
        active_tokens = token_stats["active"] or 0
        revoked_tokens = token_stats["revoked"] or 0

        audit_stats = conn.execute(
            "SELECT "
            "  COUNT(*) as total_logs, "
            "  SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allow_count, "
            "  SUM(CASE WHEN decision = 'DENY' THEN 1 ELSE 0 END) as deny_count, "
            "  SUM(CASE WHEN decision = 'ALERT' THEN 1 ELSE 0 END) as alert_count, "
            "  SUM(CASE WHEN injection_detected = 1 THEN 1 ELSE 0 END) as injection_count "
            "FROM audit_logs"
        ).fetchone()

        unack_alerts = conn.execute(
            "SELECT COUNT(*) as cnt FROM security_alerts WHERE acknowledged = 0"
        ).fetchone()["cnt"]

        self._return_conn(conn)

        return {
            "agents": {"total": agent_count},
            "tokens": {
                "active": active_tokens,
                "revoked": revoked_tokens,
                "total": active_tokens + revoked_tokens,
            },
            "audit": {
                "total_logs": audit_stats["total_logs"] or 0,
                "allow_count": audit_stats["allow_count"] or 0,
                "deny_count": audit_stats["deny_count"] or 0,
                "alert_count": audit_stats["alert_count"] or 0,
                "injection_count": audit_stats["injection_count"] or 0,
            },
            "security": {
                "unacknowledged_alerts": unack_alerts,
            },
        }

    def write_policy_decision(
        self,
        subject_id: str,
        action: str,
        resource: str,
        matched_policy: str,
        effect: str,
        reason: str,
        evaluation_trace: list,
        context: dict,
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO policy_decisions
                (timestamp, subject_id, action, resource, matched_policy, effect, reason, evaluation_trace, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (now, subject_id, action, resource, matched_policy, effect, reason,
                 json.dumps(evaluation_trace), json.dumps(context)),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to record policy evaluation: %s", e)
        finally:
            self._return_conn(conn)
        return {"timestamp": now, "subject_id": subject_id, "effect": effect}

    def get_policy_decisions(self, limit: int = 50) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM policy_decisions ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        self._return_conn(conn)
        results = []
        for row in rows:
            r = dict(row)
            try:
                r["evaluation_trace"] = json.loads(r.get("evaluation_trace", "[]"))
            except (json.JSONDecodeError, TypeError):
                r["evaluation_trace"] = []
            try:
                r["context"] = json.loads(r.get("context", "{}"))
            except (json.JSONDecodeError, TypeError):
                r["context"] = {}
            results.append(r)
        return results

    def write_svid_event(
        self, agent_id: str, event_type: str, spiffe_id: str, expires_at: float
    ) -> dict:
        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO svid_events (timestamp, agent_id, event_type, spiffe_id, expires_at)
                VALUES (?, ?, ?, ?, ?)""",
                (now, agent_id, event_type, spiffe_id, expires_at),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to record SVID event: %s", e)
        finally:
            self._return_conn(conn)
        return {"timestamp": now, "agent_id": agent_id, "event_type": event_type}

    def get_threat_summary(self) -> dict:
        conn = self._get_conn()
        now = time.time()
        day_ago = now - 86400

        injection_events = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE injection_detected = 1 AND timestamp > ? ORDER BY timestamp DESC LIMIT 10",
            (day_ago,),
        ).fetchall()]

        privilege_events = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE privilege_escalation_detected = 1 AND timestamp > ? ORDER BY timestamp DESC LIMIT 10",
            (day_ago,),
        ).fetchall()]

        token_theft_events = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE error_code = 'ERR_IDENTITY_UNVERIFIABLE' AND timestamp > ? ORDER BY timestamp DESC LIMIT 10",
            (day_ago,),
        ).fetchall()]

        rate_limit_events = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE error_code = 'ERR_RATE_LIMITED' AND timestamp > ? ORDER BY timestamp DESC LIMIT 10",
            (day_ago,),
        ).fetchall()]

        circuit_breaker_events = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE action_type = 'circuit_breaker_open' AND timestamp > ? ORDER BY timestamp DESC LIMIT 10",
            (day_ago,),
        ).fetchall()]

        total_threats_24h = (
            len(injection_events) + len(privilege_events) +
            len(token_theft_events) + len(rate_limit_events) +
            len(circuit_breaker_events)
        )

        critical_count = len(privilege_events) + len(token_theft_events)
        high_count = len(injection_events) + len(rate_limit_events)

        self._return_conn(conn)

        return {
            "injection_events": injection_events,
            "privilege_escalation_events": privilege_events,
            "token_theft_events": token_theft_events,
            "rate_limit_events": rate_limit_events,
            "circuit_breaker_events": circuit_breaker_events,
            "summary": {
                "total_threats_24h": total_threats_24h,
                "critical_count": critical_count,
                "high_count": high_count,
            },
        }

    def get_global_timeline(self, limit: int = 100) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, timestamp, action_type, requesting_agent, target_agent, decision, error_code, trace_id, risk_score FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        events = []
        for row in rows:
            r = dict(row)
            r["source"] = "audit"
            events.append(r)

        pd_rows = conn.execute(
            "SELECT id, timestamp, subject_id, action, effect, matched_policy FROM policy_decisions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        for row in pd_rows:
            r = dict(row)
            r["source"] = "policy"
            r["requesting_agent"] = r.pop("subject_id", "")
            r["decision"] = r.pop("effect", "")
            events.append(r)

        svid_rows = conn.execute(
            "SELECT id, timestamp, agent_id, event_type, spiffe_id FROM svid_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        for row in svid_rows:
            r = dict(row)
            r["source"] = "svid"
            r["action_type"] = r.pop("event_type", "")
            r["requesting_agent"] = r.pop("agent_id", "")
            events.append(r)

        self._return_conn(conn)

        events.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return events[:limit]

    def get_capabilities_matrix(self, agents: list) -> dict:
        all_caps = set()
        agent_caps = {}
        for agent in agents:
            caps = agent.get("capabilities", [])
            agent_caps[agent["agent_id"]] = caps
            for c in caps:
                all_caps.add(c)

        sorted_caps = sorted(list(all_caps))
        sorted_agents = [a["agent_id"] for a in agents]

        matrix = []
        for aid in sorted_agents:
            row = []
            for cap in sorted_caps:
                row.append(cap in agent_caps.get(aid, []))
            matrix.append(row)

        return {
            "agents": sorted_agents,
            "capabilities": sorted_caps,
            "matrix": matrix,
        }

    def acknowledge_alert(self, alert_id: int) -> dict:
        conn = self._get_conn()
        conn.execute(
            "UPDATE security_alerts SET acknowledged = 1 WHERE id = ?",
            (alert_id,),
        )
        conn.commit()
        self._return_conn(conn)
        return {"alert_id": alert_id, "acknowledged": True}

    def get_risk_trend(self, agent_id: str, window_minutes: int = 60) -> list:
        now = time.time()
        window_start = now - window_minutes * 60
        bucket_size = 300
        buckets = {}
        num_buckets = (window_minutes * 60) // bucket_size
        for i in range(num_buckets):
            bucket_start = window_start + i * bucket_size
            bucket_end = bucket_start + bucket_size
            bucket_key = int(bucket_start)
            buckets[bucket_key] = {"start": bucket_start, "end": bucket_end, "scores": [], "count": 0}

        conn = self._get_conn()
        rows = conn.execute(
            "SELECT timestamp, risk_score FROM audit_logs WHERE requesting_agent = ? AND timestamp > ? AND risk_score > 0 ORDER BY timestamp ASC",
            (agent_id, window_start),
        ).fetchall()
        self._return_conn(conn)

        for row in rows:
            ts = row["timestamp"]
            score = row["risk_score"]
            bucket_key = int((ts - window_start) // bucket_size) * bucket_size + int(window_start)
            if bucket_key in buckets:
                buckets[bucket_key]["scores"].append(score)
                buckets[bucket_key]["count"] += 1

        trend = []
        for bucket_key in sorted(buckets.keys()):
            b = buckets[bucket_key]
            avg_score = sum(b["scores"]) / len(b["scores"]) if b["scores"] else 0
            trend.append({
                "timestamp": b["start"],
                "time_label": time.strftime("%H:%M", time.localtime(b["start"])),
                "avg_risk_score": round(avg_score, 1),
                "max_risk_score": max(b["scores"]) if b["scores"] else 0,
                "event_count": b["count"],
            })
        return trend
