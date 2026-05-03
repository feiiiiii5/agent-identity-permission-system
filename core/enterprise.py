import json
import time
import uuid
import hashlib
from core.db_pool import get_pool
import threading
from typing import Optional, List
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict


class PermissionTier(Enum):
    TIER_0 = "tier_0"
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


TIER_DESCRIPTIONS = {
    PermissionTier.TIER_0: "Read-only operations - Agents can perform freely",
    PermissionTier.TIER_1: "Low-risk write operations - Agents can perform with logging",
    PermissionTier.TIER_2: "Sensitive operations - Require human-in-the-loop approval",
    PermissionTier.TIER_3: "Privileged operations - Blocked for agents entirely",
}

CAPABILITY_TIER_MAP = {
    "lark:doc:read": PermissionTier.TIER_0,
    "lark:bitable:read": PermissionTier.TIER_0,
    "lark:contact:read": PermissionTier.TIER_0,
    "web:search": PermissionTier.TIER_0,
    "web:fetch": PermissionTier.TIER_0,
    "lark:doc:write": PermissionTier.TIER_1,
    "lark:bitable:write": PermissionTier.TIER_1,
    "lark:sheet:write": PermissionTier.TIER_1,
    "lark:calendar:write": PermissionTier.TIER_1,
    "lark:task:write": PermissionTier.TIER_1,
    "lark:mail:send": PermissionTier.TIER_1,
    "delegate:DataAgent:read": PermissionTier.TIER_1,
    "delegate:DocAgent:read": PermissionTier.TIER_1,
    "delegate:SearchAgent:read": PermissionTier.TIER_1,
    "delegate:DataAgent:write": PermissionTier.TIER_2,
    "delegate:DocAgent:write": PermissionTier.TIER_2,
    "lark:approval:submit": PermissionTier.TIER_2,
    "lark:approval:cancel": PermissionTier.TIER_2,
    "lark:admin:config": PermissionTier.TIER_3,
    "lark:iam:manage": PermissionTier.TIER_3,
    "lark:billing:access": PermissionTier.TIER_3,
    "system:shutdown": PermissionTier.TIER_3,
    "system:database:export": PermissionTier.TIER_3,
}


def get_capability_tier(capability: str) -> PermissionTier:
    if capability in CAPABILITY_TIER_MAP:
        return CAPABILITY_TIER_MAP[capability]
    if ":read" in capability or ":list" in capability or ":search" in capability:
        return PermissionTier.TIER_0
    if ":write" in capability or ":create" in capability or ":update" in capability:
        return PermissionTier.TIER_1
    if ":delete" in capability or ":admin" in capability or ":manage" in capability:
        return PermissionTier.TIER_2
    if capability.startswith("delegate:") and ":write" in capability:
        return PermissionTier.TIER_2
    return PermissionTier.TIER_1


class RevocationSet:
    MAX_JTI_ENTRIES = 10000

    def __init__(self):
        self._revoked_jtis: OrderedDict = OrderedDict()
        self._agent_revocations: dict = {}
        self._lock = threading.Lock()

    def add_jti(self, jti: str):
        with self._lock:
            self._revoked_jtis[jti] = True
            while len(self._revoked_jtis) > self.MAX_JTI_ENTRIES:
                self._revoked_jtis.popitem(last=False)

    def add_agent_revocation(self, agent_id: str, revoke_before_ts: int):
        with self._lock:
            current = self._agent_revocations.get(agent_id, 0)
            if revoke_before_ts > current:
                self._agent_revocations[agent_id] = revoke_before_ts

    def is_revoked(self, jti: str, agent_id: str = "", issued_at: float = 0) -> bool:
        with self._lock:
            if jti in self._revoked_jtis:
                return True
            if agent_id and agent_id in self._agent_revocations:
                revoke_before = self._agent_revocations[agent_id]
                if issued_at > 0 and issued_at < revoke_before:
                    return True
            return False

    def clear(self):
        with self._lock:
            self._revoked_jtis.clear()
            self._agent_revocations.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._revoked_jtis) + len(self._agent_revocations)


class TokenExchangeService:
    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
    SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

    def __init__(self, token_manager, auth_server, revocation_set: RevocationSet):
        self.token_manager = token_manager
        self.auth_server = auth_server
        self.revocation_set = revocation_set

    def exchange_token(
        self,
        subject_token: str,
        scope: List[str],
        agent_id: str,
        ttl_minutes: int = 15,
    ) -> dict:
        verify_result = self.token_manager.verify_token(subject_token)
        if not verify_result["valid"]:
            return {"error": "invalid_subject_token", "message": "Subject token is invalid or expired", "status": 401}

        payload = verify_result["payload"]
        token_agent_id = payload.get("agent_id", "")

        if token_agent_id != agent_id:
            return {"error": "agent_mismatch", "message": f"Token agent_id {token_agent_id} does not match path agent_id {agent_id}", "status": 403}

        parent_jti = payload.get("jti", "")
        if self.revocation_set.is_revoked(parent_jti, token_agent_id, payload.get("iat", 0)):
            return {"error": "token_revoked", "message": "Subject token has been revoked", "status": 401}

        agent = self.auth_server._get_agent(agent_id)
        if not agent:
            return {"error": "agent_not_found", "message": f"Agent {agent_id} not registered", "status": 404}

        if agent["status"] != "active":
            return {"error": "agent_suspended", "message": f"Agent {agent_id} is {agent['status']}", "status": 403}

        parent_caps = set(payload.get("capabilities", []))
        parent_max_scope = set(payload.get("max_scope", []))
        parent_expires = payload.get("expires_at", 0)
        parent_trust_chain = payload.get("trust_chain", [])
        parent_delegated_user = payload.get("delegated_user", "")

        requested_scope = set(scope)
        denied = []
        allowed = []

        for s in requested_scope:
            if ":" not in s:
                denied.append({"scope": s, "reason": "Invalid scope format"})
                continue

            if s in parent_caps or s in parent_max_scope:
                tier = get_capability_tier(s)
                if tier == PermissionTier.TIER_3:
                    denied.append({"scope": s, "reason": f"Tier 3 capability blocked for agents"})
                else:
                    allowed.append(s)
            else:
                denied.append({"scope": s, "reason": "Exceeds parent token scope"})

        if denied and not allowed:
            return {"error": "scope_denied", "message": "All requested scopes denied", "details": {"denied": denied}, "status": 403}

        if denied:
            pass

        now = time.time()
        requested_ttl = ttl_minutes * 60
        remaining_parent = parent_expires - now
        effective_ttl = min(requested_ttl, max(remaining_parent, 60))

        new_trust_chain = parent_trust_chain + [agent_id]
        new_attenuation = payload.get("attenuation_level", 0) + 1

        result = self.token_manager.issue_token(
            agent_id=agent_id,
            agent_type=agent["agent_type"],
            capabilities=sorted(allowed),
            max_capabilities=agent["capabilities"],
            scope=sorted(allowed),
            max_scope=sorted(allowed),
            delegated_user=parent_delegated_user,
            parent_agent=agent_id,
            parent_jti=parent_jti,
            trust_chain=new_trust_chain,
            attenuation_level=new_attenuation,
            ttl_seconds=int(effective_ttl),
            session_id=uuid.uuid4().hex[:16],
            risk_score=payload.get("risk_score_at_issuance", 0),
            task_id=payload.get("task_id", ""),
            trace_id=payload.get("trace_id", ""),
        )

        result["token_kind"] = "downscoped"
        result["scope"] = sorted(allowed)
        result["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"

        if denied:
            result["denied_scopes"] = denied

        self.auth_server.audit_logger.write_log(
            requesting_agent=agent_id,
            action_type="token_exchange",
            decision="ALLOW" if not denied else "PARTIAL",
            granted_capabilities=allowed,
            denied_capabilities=[d["scope"] for d in denied],
            trust_chain_snapshot=new_trust_chain,
            trace_id=payload.get("trace_id", ""),
        )

        return result

    def introspect_token(self, token: str) -> dict:
        verify_result = self.token_manager.verify_token(token)
        if not verify_result["valid"]:
            return {"active": False, "error": verify_result.get("error", "invalid")}

        payload = verify_result["payload"]
        jti = payload.get("jti", "")
        agent_id = payload.get("agent_id", "")

        if self.revocation_set.is_revoked(jti, agent_id, payload.get("iat", 0)):
            return {"active": False, "error": "token_revoked"}

        caps = payload.get("capabilities", [])
        tier_info = {}
        for cap in caps:
            tier = get_capability_tier(cap)
            tier_info[cap] = {"tier": tier.value, "description": TIER_DESCRIPTIONS[tier]}

        return {
            "active": True,
            "jti": jti,
            "agent_id": agent_id,
            "agent_type": payload.get("agent_type", ""),
            "scope": caps,
            "max_scope": payload.get("max_scope", []),
            "attenuation_level": payload.get("attenuation_level", 0),
            "trust_chain": payload.get("trust_chain", []),
            "delegated_user": payload.get("delegated_user", ""),
            "token_type": payload.get("token_type", "Bearer"),
            "exp": payload.get("expires_at", 0),
            "iat": payload.get("iat", 0),
            "session_id": payload.get("session_id", ""),
            "risk_score": payload.get("risk_score_at_issuance", 0),
            "capability_tiers": tier_info,
            "parent_jti": payload.get("parent_jti", ""),
        }


class LifecycleService:
    def __init__(self, db_path: str, auth_server, revocation_set: RevocationSet):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self.auth_server = auth_server
        self.revocation_set = revocation_set
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                status TEXT DEFAULT 'processed',
                agents_affected INTEGER DEFAULT 0,
                error_message TEXT DEFAULT '',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_suspension_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                previous_state TEXT DEFAULT 'active',
                suspended_by_event INTEGER,
                reactivated_at REAL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_lifecycle_user ON lifecycle_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_lifecycle_type ON lifecycle_events(event_type);
        """)
        conn.commit()
        self._return_conn(conn)

    VALID_EVENT_TYPES = ["user.suspended", "user.reactivated", "user.departed", "user.role_changed"]

    def process_event(self, event_type: str, user_id: str, payload: dict = None) -> dict:
        if event_type not in self.VALID_EVENT_TYPES:
            return {"error": "invalid_event_type", "message": f"Event type must be one of {self.VALID_EVENT_TYPES}", "status": 422}

        if not user_id:
            return {"error": "missing_user_id", "message": "userId is required", "status": 422}

        try:
            if event_type == "user.suspended":
                result = self._handle_user_suspended(user_id)
            elif event_type == "user.reactivated":
                result = self._handle_user_reactivated(user_id)
            elif event_type == "user.departed":
                result = self._handle_user_departed(user_id)
            elif event_type == "user.role_changed":
                result = self._handle_user_role_changed(user_id)
            else:
                result = {"agents_affected": 0}

            conn = self._get_conn()
            conn.execute(
                "INSERT INTO lifecycle_events (event_type, user_id, payload, status, agents_affected, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (event_type, user_id, json.dumps(payload or {}), "processed", result.get("agents_affected", 0), time.time()),
            )
            conn.commit()
            last_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
            self._return_conn(conn)

            return {
                "status": "processed",
                "event_id": last_id,
                "event_type": event_type,
                "user_id": user_id,
                "agents_affected": result.get("agents_affected", 0),
                "processed_at": time.time(),
                "details": result,
            }
        except Exception as e:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO lifecycle_events (event_type, user_id, payload, status, agents_affected, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event_type, user_id, json.dumps(payload or {}), "failed", 0, str(e)[:500], time.time()),
            )
            conn.commit()
            self._return_conn(conn)
            return {"status": "failed", "error": str(e), "event_type": event_type}

    def _handle_user_suspended(self, user_id: str) -> dict:
        agents = self.auth_server.list_agents()
        affected = []
        for agent in agents:
            if agent.get("status") == "active":
                conn = self._get_conn()
                conn.execute("UPDATE agents SET status = 'suspended' WHERE agent_id = ?", (agent["agent_id"],))
                conn.commit()
                self._return_conn(conn)

                self.auth_server.token_manager.revoke_all_agent_tokens(agent["agent_id"])
                revoke_ts = int(time.time()) + 1
                self.revocation_set.add_agent_revocation(agent["agent_id"], revoke_ts)

                conn = self._get_conn()
                conn.execute(
                    "INSERT INTO agent_suspension_records (agent_id, previous_state, suspended_by_event) VALUES (?, ?, ?)",
                    (agent["agent_id"], "active", 0),
                )
                conn.commit()
                self._return_conn(conn)

                affected.append(agent["agent_id"])
                self.auth_server.audit_logger.write_log(
                    requesting_agent=agent["agent_id"],
                    action_type="lifecycle_user_suspended",
                    decision="DENY",
                    deny_reason=f"Owner user {user_id} suspended, agent auto-suspended",
                    trace_id=uuid.uuid4().hex[:16],
                )

        return {"agents_affected": len(affected), "suspended_agent_ids": affected}

    def _handle_user_reactivated(self, user_id: str) -> dict:
        conn = self._get_conn()
        records = conn.execute(
            "SELECT * FROM agent_suspension_records WHERE reactivated_at = 0"
        ).fetchall()
        self._return_conn(conn)

        agents = self.auth_server.list_agents()
        agent_map = {a["agent_id"]: a for a in agents}
        reactivated = []

        for record in records:
            agent_id = record["agent_id"]
            if agent_id in agent_map and agent_map[agent_id]["status"] == "suspended":
                conn = self._get_conn()
                conn.execute("UPDATE agents SET status = 'active' WHERE agent_id = ?", (agent_id,))
                conn.execute(
                    "UPDATE agent_suspension_records SET reactivated_at = ? WHERE id = ?",
                    (time.time(), record["id"]),
                )
                conn.commit()
                self._return_conn(conn)
                reactivated.append(agent_id)
                self.auth_server.audit_logger.write_log(
                    requesting_agent=agent_id,
                    action_type="lifecycle_user_reactivated",
                    decision="ALLOW",
                    trace_id=uuid.uuid4().hex[:16],
                )

        return {"agents_affected": len(reactivated), "reactivated_agent_ids": reactivated}

    def _handle_user_departed(self, user_id: str) -> dict:
        agents = self.auth_server.list_agents()
        affected = []
        for agent in agents:
            conn = self._get_conn()
            conn.execute("UPDATE agents SET status = 'deprovisioned' WHERE agent_id = ?", (agent["agent_id"],))
            conn.commit()
            self._return_conn(conn)

            self.auth_server.token_manager.revoke_all_agent_tokens(agent["agent_id"])
            revoke_ts = int(time.time()) + 1
            self.revocation_set.add_agent_revocation(agent["agent_id"], revoke_ts)
            affected.append(agent["agent_id"])

            self.auth_server.audit_logger.write_log(
                requesting_agent=agent["agent_id"],
                action_type="lifecycle_user_departed",
                decision="DENY",
                deny_reason=f"Owner user {user_id} departed, agent deprovisioned",
                trace_id=uuid.uuid4().hex[:16],
            )

        return {"agents_affected": len(affected), "deprovisioned_agent_ids": affected}

    def _handle_user_role_changed(self, user_id: str) -> dict:
        agents = self.auth_server.list_agents()
        active_agents = [a for a in agents if a.get("status") == "active"]

        for agent in active_agents:
            self.auth_server.audit_logger.write_log(
                requesting_agent=agent["agent_id"],
                action_type="lifecycle_role_changed",
                decision="ALERT",
                deny_reason=f"User {user_id} role changed, agent access should be reviewed",
                trace_id=uuid.uuid4().hex[:16],
            )

        return {"agents_affected": len(active_agents), "review_required_agents": [a["agent_id"] for a in active_agents]}

    def get_events(self, user_id: str = None, event_type: str = None, limit: int = 50) -> list:
        conn = self._get_conn()
        query = "SELECT * FROM lifecycle_events WHERE 1=1"
        params = []
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]


class ConsentService:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                granted_capabilities TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                expires_at REAL DEFAULT 0,
                created_at REAL NOT NULL,
                revoked_at REAL DEFAULT 0,
                revoked_by TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_consents_agent ON consents(agent_id);
            CREATE INDEX IF NOT EXISTS idx_consents_user ON consents(user_id);
            CREATE INDEX IF NOT EXISTS idx_consents_status ON consents(status);
        """)
        conn.commit()
        self._return_conn(conn)

    def grant_consent(self, agent_id: str, user_id: str, capabilities: list, ttl_seconds: int = 86400) -> dict:
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO consents (agent_id, user_id, granted_capabilities, status, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, user_id, json.dumps(capabilities), "active", now + ttl_seconds, now),
        )
        conn.commit()
        last_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        self._return_conn(conn)
        return {"id": last_id, "agent_id": agent_id, "user_id": user_id, "status": "active", "capabilities": capabilities}

    def revoke_consent(self, consent_id: int, revoked_by: str = "") -> dict:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM consents WHERE id = ?", (consent_id,)).fetchone()
        if not row:
            self._return_conn(conn)
            return {"error": "not_found", "message": f"Consent {consent_id} not found"}
        conn.execute(
            "UPDATE consents SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE id = ?",
            (time.time(), revoked_by, consent_id),
        )
        conn.commit()
        self._return_conn(conn)
        return {"id": consent_id, "status": "revoked", "revoked_by": revoked_by}

    def revoke_all_for_user(self, user_id: str, revoked_by: str = "") -> dict:
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE consents SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE user_id = ? AND status = 'active'",
            (time.time(), revoked_by, user_id),
        )
        conn.commit()
        affected = cursor.rowcount
        self._return_conn(conn)
        return {"revoked_count": affected, "user_id": user_id}

    def check_consent(self, agent_id: str, user_id: str, capability: str) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM consents WHERE agent_id = ? AND user_id = ? AND status = 'active' AND expires_at > ?",
            (agent_id, user_id, time.time()),
        ).fetchall()
        self._return_conn(conn)

        for row in rows:
            caps = json.loads(row["granted_capabilities"])
            if capability in caps:
                return {"has_consent": True, "consent_id": row["id"], "expires_at": row["expires_at"]}

        return {"has_consent": False, "reason": "No active consent found"}

    def list_consents(self, agent_id: str = None, user_id: str = None, status: str = None) -> list:
        conn = self._get_conn()
        query = "SELECT * FROM consents WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT 100"
        rows = conn.execute(query, params).fetchall()
        self._return_conn(conn)
        results = []
        for row in rows:
            r = dict(row)
            try:
                r["granted_capabilities"] = json.loads(r["granted_capabilities"])
            except (json.JSONDecodeError, TypeError):
                r["granted_capabilities"] = []
            results.append(r)
        return results


class DriftDetectionService:
    def __init__(self, db_path: str, auth_server):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self.auth_server = auth_server
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS permission_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                permission_snapshot TEXT DEFAULT '[]',
                attested_at REAL NOT NULL,
                attested_by TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_baselines_agent ON permission_baselines(agent_id);
        """)
        conn.commit()
        self._return_conn(conn)

    def set_baseline(self, agent_id: str, attested_by: str = "system") -> dict:
        agent = self.auth_server._get_agent(agent_id)
        if not agent:
            return {"error": "agent_not_found", "message": f"Agent {agent_id} not found"}

        snapshot = agent["capabilities"]
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO permission_baselines (agent_id, permission_snapshot, attested_at, attested_by) VALUES (?, ?, ?, ?)",
            (agent_id, json.dumps(snapshot), time.time(), attested_by),
        )
        conn.commit()
        self._return_conn(conn)
        return {"agent_id": agent_id, "baseline_set": True, "snapshot": snapshot}

    def detect_drift(self, agent_id: str) -> dict:
        agent = self.auth_server._get_agent(agent_id)
        if not agent:
            return {"error": "agent_not_found", "agent_id": agent_id}

        current_caps = set(agent["capabilities"])

        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM permission_baselines WHERE agent_id = ? ORDER BY attested_at DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        self._return_conn(conn)

        if not row:
            return {
                "agent_id": agent_id,
                "has_drift": False,
                "drifts": [],
                "baseline_exists": False,
                "message": "No baseline found, set baseline first",
            }

        baseline_caps = set(json.loads(row["permission_snapshot"]))
        added = current_caps - baseline_caps
        removed = baseline_caps - current_caps

        drifts = []
        for cap in added:
            tier = get_capability_tier(cap)
            drifts.append({"capability": cap, "drift_type": "added", "tier": tier.value})
        for cap in removed:
            tier = get_capability_tier(cap)
            drifts.append({"capability": cap, "drift_type": "removed", "tier": tier.value})

        has_drift = len(drifts) > 0

        if has_drift:
            self.auth_server.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="drift_detected",
                decision="ALERT",
                deny_reason=f"Permission drift detected: {len(drifts)} changes",
                trace_id=uuid.uuid4().hex[:16],
            )

        return {
            "agent_id": agent_id,
            "has_drift": has_drift,
            "drifts": drifts,
            "baseline_exists": True,
            "baseline_attested_at": row["attested_at"],
            "current_capabilities": sorted(list(current_caps)),
            "baseline_capabilities": sorted(list(baseline_caps)),
        }

    def detect_drift_batch(self) -> list:
        agents = self.auth_server.list_agents()
        results = []
        for agent in agents:
            drift = self.detect_drift(agent["agent_id"])
            results.append(drift)
        return results


class AccessReviewService:
    def __init__(self, db_path: str, auth_server):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self.auth_server = auth_server
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS access_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                review_type TEXT DEFAULT 'periodic',
                status TEXT DEFAULT 'pending',
                capabilities_reviewed TEXT DEFAULT '[]',
                decision TEXT DEFAULT '',
                comment TEXT DEFAULT '',
                created_at REAL NOT NULL,
                reviewed_at REAL DEFAULT 0,
                due_at REAL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_reviews_agent ON access_reviews(agent_id);
            CREATE INDEX IF NOT EXISTS idx_reviews_status ON access_reviews(status);
        """)
        conn.commit()
        self._return_conn(conn)

    def create_review(self, agent_id: str, reviewer_id: str, review_type: str = "periodic", due_days: int = 7) -> dict:
        agent = self.auth_server._get_agent(agent_id)
        if not agent:
            return {"error": "agent_not_found", "message": f"Agent {agent_id} not found"}

        now = time.time()
        due_at = now + (due_days * 86400)

        conn = self._get_conn()
        conn.execute(
            "INSERT INTO access_reviews (agent_id, reviewer_id, review_type, status, capabilities_reviewed, created_at, due_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (agent_id, reviewer_id, review_type, "pending", json.dumps(agent["capabilities"]), now, due_at),
        )
        conn.commit()
        last_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        self._return_conn(conn)
        return {"id": last_id, "agent_id": agent_id, "reviewer_id": reviewer_id, "status": "pending", "due_at": due_at}

    def resolve_review(self, review_id: int, decision: str, comment: str = "") -> dict:
        if decision not in ("approve", "revoke", "modify"):
            return {"error": "invalid_decision", "message": "Decision must be approve, revoke, or modify"}

        conn = self._get_conn()
        row = conn.execute("SELECT * FROM access_reviews WHERE id = ?", (review_id,)).fetchone()
        if not row:
            self._return_conn(conn)
            return {"error": "not_found", "message": f"Review {review_id} not found"}

        conn.execute(
            "UPDATE access_reviews SET status = 'completed', decision = ?, comment = ?, reviewed_at = ? WHERE id = ?",
            (decision, comment, time.time(), review_id),
        )
        conn.commit()
        self._return_conn(conn)

        if decision == "revoke":
            self.auth_server.token_manager.revoke_all_agent_tokens(row["agent_id"])
            conn = self._get_conn()
            conn.execute("UPDATE agents SET status = 'suspended' WHERE agent_id = ?", (row["agent_id"],))
            conn.commit()
            self._return_conn(conn)

        return {"id": review_id, "status": "completed", "decision": decision}

    def list_reviews(self, agent_id: str = None, status: str = None, limit: int = 50) -> list:
        conn = self._get_conn()
        query = "SELECT * FROM access_reviews WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        self._return_conn(conn)
        results = []
        for row in rows:
            r = dict(row)
            try:
                r["capabilities_reviewed"] = json.loads(r["capabilities_reviewed"])
            except (json.JSONDecodeError, TypeError):
                r["capabilities_reviewed"] = []
            results.append(r)
        return results

    def get_overdue_reviews(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM access_reviews WHERE status = 'pending' AND due_at < ?",
            (time.time(),),
        ).fetchall()
        self._return_conn(conn)
        return [dict(r) for r in rows]
