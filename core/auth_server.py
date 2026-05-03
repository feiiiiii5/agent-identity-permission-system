import json
import time
import uuid
import hashlib
import hmac
import secrets
import sqlite3
import threading
from typing import Optional
from collections import OrderedDict
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

from core.token_manager import TokenManager
from core.audit_logger import AuditLogger
from core.injection_scanner import InjectionScanner
from core.capability_engine import CapabilityEngine
from core.risk_scorer import RiskScorer
from core.behavior_analyzer import BehaviorAnalyzer
from core.session_verifier import SessionVerifier
from core.privilege_detector import PrivilegeDetector
from core.svid_manager import SVIDManager
from core.policy_engine import PolicyEngine
from core.dpop_verifier import DPoPVerifier
from core.rate_limiter import SlidingWindowRateLimiter
from core.circuit_breaker import CircuitBreaker
from core.nonce_manager import NonceManager
from core.incident_responder import IncidentResponder
from core.alerting import AlertManager
from core.db_pool import get_pool


class RiskDecisionEngine:

    RISK_ACTIONS = [
        (90, 100, "freeze_and_revoke"),
        (80, 90, "revoke_and_alert"),
        (70, 80, "downgrade_readonly"),
        (40, 70, "monitor_and_log"),
        (0, 40, "allow"),
    ]

    def __init__(self, auth_server):
        self._auth_server = auth_server

    def evaluate_and_act(self, agent_id: str, risk_score: float, trace_id: str = "") -> dict:
        action_name = "allow"
        for low, high, action in self.RISK_ACTIONS:
            if low <= risk_score < high:
                action_name = action
                break
        if risk_score >= 100:
            action_name = "freeze_and_revoke"

        result = {"agent_id": agent_id, "risk_score": risk_score, "action": action_name, "trace_id": trace_id}

        if action_name == "freeze_and_revoke":
            self._auth_server.freeze_agent(agent_id)
            revoked = self._auth_server.token_manager.revoke_all_agent_tokens(agent_id)
            result["revoked_count"] = revoked.get("revoked_count", 0)
            result["frozen"] = True
            self._auth_server.audit_logger.write_log(
                requesting_agent=agent_id, action_type="risk_decision_freeze",
                decision="DENY", deny_reason=f"Risk score {risk_score} >= 90, agent frozen and tokens revoked",
                risk_score=risk_score, trace_id=trace_id,
            )
        elif action_name == "revoke_and_alert":
            revoked = self._auth_server.token_manager.revoke_all_agent_tokens(agent_id)
            result["revoked_count"] = revoked.get("revoked_count", 0)
            self._auth_server.audit_logger.write_log(
                requesting_agent=agent_id, action_type="risk_decision_revoke",
                decision="ALERT", deny_reason=f"Risk score {risk_score} >= 80, tokens revoked",
                risk_score=risk_score, trace_id=trace_id,
            )
        elif action_name == "downgrade_readonly":
            self._auth_server.audit_logger.write_log(
                requesting_agent=agent_id, action_type="risk_decision_downgrade",
                decision="ALERT", deny_reason=f"Risk score {risk_score} >= 70, downgraded to read-only",
                risk_score=risk_score, trace_id=trace_id,
            )
        elif action_name == "monitor_and_log":
            self._auth_server.audit_logger.write_log(
                requesting_agent=agent_id, action_type="risk_decision_monitor",
                decision="ALLOW", risk_score=risk_score, trace_id=trace_id,
            )

        if self._auth_server._ws_notify and action_name != "allow":
            self._auth_server._notify("risk_decision", result)

        return result


class AuthServer:

    SENSITIVE_CAPABILITIES = ["lark:contact:read", "lark:bitable:write"]
    SENSITIVE_READ_THRESHOLD = 100
    HUMAN_APPROVAL_TOKEN_TTL = 300
    HUMAN_APPROVAL_TIMEOUT = 30

    MAX_PENDING_APPROVALS = 1000

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._init_db()

        self.token_manager = TokenManager(db_path)
        self.audit_logger = AuditLogger(db_path)
        self.capability_engine = CapabilityEngine()
        self.risk_scorer = RiskScorer(db_path)
        self.behavior_analyzer = BehaviorAnalyzer(db_path)
        self.session_verifier = SessionVerifier()
        self.privilege_detector = PrivilegeDetector(db_path)
        self.injection_scanner = InjectionScanner()
        self.svid_manager = SVIDManager()
        self.policy_engine = PolicyEngine()
        self.dpop_verifier = DPoPVerifier()
        self.rate_limiter = SlidingWindowRateLimiter(db_path)
        self.circuit_breaker = CircuitBreaker()
        self.nonce_manager = NonceManager(db_path)
        self.incident_responder = IncidentResponder(db_path)
        self.alert_manager = AlertManager(db_path)
        self.risk_decision_engine = RiskDecisionEngine(self)

        self._ws_notify = None
        self._agent_key_pairs = {}
        self._pending_approvals = OrderedDict()
        self._approvals_lock = threading.Lock()

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                agent_name TEXT NOT NULL,
                agent_type TEXT DEFAULT '',
                capabilities TEXT DEFAULT '[]',
                client_secret TEXT NOT NULL,
                trust_score REAL DEFAULT 100.0,
                status TEXT DEFAULT 'active',
                encryption_public_key TEXT DEFAULT '',
                endpoint_url TEXT DEFAULT '',
                authentication_schemes TEXT DEFAULT '[]',
                skill_descriptions TEXT DEFAULT '[]',
                baseline_capabilities TEXT DEFAULT '[]',
                spiffe_id TEXT DEFAULT '',
                svid_expires_at REAL DEFAULT 0,
                created_at REAL NOT NULL
            );
        """)
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN spiffe_id TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE agents ADD COLUMN svid_expires_at REAL DEFAULT 0")
        except Exception:
            pass
        conn.commit()
        self._return_conn(conn)

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def set_ws_notify(self, func):
        self._ws_notify = func

    def _notify(self, event_type: str, data: dict):
        if self._ws_notify:
            try:
                self._ws_notify(event_type, data)
            except Exception as e:
                logger.warning("WebSocket notification failed: %s", e)

    def _generate_secret(self, agent_id: str) -> str:
        return secrets.token_hex(32)

    def _generate_agent_keypair(self, agent_id: str) -> tuple:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        self._agent_key_pairs[agent_id] = private_key
        return (private_key, pub_pem)

    def health(self) -> dict:
        return {
            "status": "healthy",
            "version": "2.0.0",
            "timestamp": time.time(),
        }

    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        capabilities: list,
        encryption_public_key: str = None,
        endpoint_url: str = "",
        authentication_schemes: list = None,
        skill_descriptions: list = None,
    ) -> dict:
        conn = self._get_conn()

        if encryption_public_key is None:
            _, pub_pem = self._generate_agent_keypair(agent_id)
            encryption_public_key = pub_pem

        if agent_id not in self._agent_key_pairs:
            self._generate_agent_keypair(agent_id)

        if authentication_schemes is None:
            authentication_schemes = ["mTLS", "Bearer"]
        if skill_descriptions is None:
            skill_descriptions = []

        existing = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

        svid = self.svid_manager.issue_svid(agent_id, agent_type)
        self.audit_logger.write_svid_event(agent_id, "svid_issued", svid.spiffe_id, svid.expires_at)

        if existing:
            conn.execute(
                """UPDATE agents SET agent_name = ?, agent_type = ?, capabilities = ?,
                   encryption_public_key = ?, endpoint_url = ?,
                   authentication_schemes = ?, skill_descriptions = ?,
                   baseline_capabilities = ?, spiffe_id = ?, svid_expires_at = ? WHERE agent_id = ?""",
                (agent_name, agent_type, json.dumps(capabilities),
                 encryption_public_key, endpoint_url,
                 json.dumps(authentication_schemes), json.dumps(skill_descriptions),
                 json.dumps(capabilities), svid.spiffe_id, svid.expires_at, agent_id),
            )
            conn.commit()
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            self._return_conn(conn)
            return dict(agent)
        else:
            client_secret = self._generate_secret(agent_id)
            now = time.time()
            conn.execute(
                """INSERT INTO agents
                (agent_id, agent_name, agent_type, capabilities, client_secret, trust_score,
                 status, encryption_public_key, endpoint_url, authentication_schemes,
                 skill_descriptions, baseline_capabilities, spiffe_id, svid_expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, 100.0, 'active', ?, ?, ?, ?, ?, ?, ?, ?)""",
                (agent_id, agent_name, agent_type, json.dumps(capabilities),
                 client_secret, encryption_public_key, endpoint_url,
                 json.dumps(authentication_schemes), json.dumps(skill_descriptions),
                 json.dumps(capabilities), svid.spiffe_id, svid.expires_at, now),
            )
            conn.commit()
            self._return_conn(conn)

            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="agent_register",
                decision="ALLOW",
                granted_capabilities=capabilities,
                trace_id=uuid.uuid4().hex[:16],
            )

            self._notify("agent_registered", {"agent_id": agent_id, "agent_name": agent_name})

            return {
                "agent_id": agent_id,
                "agent_name": agent_name,
                "agent_type": agent_type,
                "capabilities": capabilities,
                "client_secret": client_secret,
                "trust_score": 100.0,
                "status": "active",
                "encryption_public_key": encryption_public_key,
                "spiffe_id": svid.spiffe_id,
                "svid_expires_at": svid.expires_at,
            }

    def _deserialize_agent(self, row: dict) -> dict:
        agent = dict(row)
        for field in ["capabilities", "authentication_schemes", "skill_descriptions", "baseline_capabilities"]:
            try:
                agent[field] = json.loads(agent[field])
            except (json.JSONDecodeError, TypeError):
                agent[field] = []
        return agent

    def _get_agent(self, agent_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        self._return_conn(conn)
        if not row:
            return None
        return self._deserialize_agent(row)

    def list_agents(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents ORDER BY created_at ASC").fetchall()
        self._return_conn(conn)
        return [self._deserialize_agent(row) for row in rows]

    def generate_agent_card(self, agent_id: str) -> Optional[dict]:
        agent = self._get_agent(agent_id)
        if not agent:
            return None

        caps = agent["capabilities"]
        trust = agent["trust_score"]

        if trust >= 80:
            trust_level = "high"
        elif trust >= 50:
            trust_level = "medium"
        else:
            trust_level = "low"

        skill_descriptions = agent.get("skill_descriptions", [])
        if not skill_descriptions:
            skill_descriptions = [
                {"name": c, "description": f"Capability: {c}"} for c in caps
            ]

        return {
            "agent_id": agent_id,
            "display_name": agent["agent_name"],
            "supported_capabilities": caps,
            "trust_level": trust_level,
            "trust_score": trust,
            "endpoint_url": agent.get("endpoint_url", ""),
            "authentication_schemes": agent.get("authentication_schemes", ["mTLS", "Bearer"]),
            "encryption_public_key": agent.get("encryption_public_key", ""),
            "skill_descriptions": skill_descriptions,
            "agent_type": agent["agent_type"],
            "status": agent["status"],
            "created_at": agent["created_at"],
        }

    def _check_agent_card_capability_match(
        self, target_agent_id: str, requested_capabilities: list
    ) -> dict:
        target_card = self.generate_agent_card(target_agent_id)
        if not target_card:
            return {"match": False, "reason": "Target agent not found", "missing": requested_capabilities}

        target_caps = set(target_card["supported_capabilities"])
        requested_set = set(requested_capabilities)
        missing = requested_set - target_caps

        if missing:
            return {
                "match": False,
                "reason": f"Target agent lacks capabilities: {', '.join(missing)}",
                "missing": sorted(list(missing)),
                "target_capabilities": sorted(list(target_caps)),
            }

        return {"match": True, "missing": [], "target_capabilities": sorted(list(target_caps))}

    def issue_token(
        self,
        agent_id: str,
        client_secret: str,
        capabilities: list,
        delegated_user: str = None,
        max_uses: int = None,
        task_id: str = None,
        trace_id: str = None,
        task_description: str = None,
        nonce: str = None,
    ) -> dict:
        rl_result = self.rate_limiter.check_rate_limit(agent_id, "token_issue")
        if not rl_result.allowed:
            self.rate_limiter.record_request(agent_id, "token_issue")
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason=f"Rate limit exceeded: {rl_result.current_count}/{rl_result.limit} in {rl_result.window_seconds}s",
                error_code="ERR_RATE_LIMITED",
                trace_id=trace_id,
            )
            raise PermissionError(
                f"Rate limit exceeded for {agent_id}: {rl_result.current_count}/{rl_result.limit} requests in {rl_result.window_seconds}s "
                f"[ERR_RATE_LIMITED]"
            )

        cb_result = self.circuit_breaker.can_proceed(agent_id)
        if not cb_result["allowed"]:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason=f"Circuit breaker open for agent {agent_id}",
                error_code="ERR_CIRCUIT_OPEN",
                trace_id=trace_id,
            )
            raise PermissionError(
                f"Circuit breaker is OPEN for {agent_id}, retry after {cb_result.get('recovery_at', 0):.0f} "
                f"[ERR_CIRCUIT_OPEN]"
            )

        self.rate_limiter.record_request(agent_id, "token_issue")

        agent = self._get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not registered")

        if not hmac.compare_digest(agent["client_secret"], client_secret):
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason="Invalid client_secret",
                error_code="ERR_AUTH_FAILED",
            )
            self.circuit_breaker.record_failure(agent_id, "ERR_AUTH_FAILED")
            raise PermissionError("Invalid client_secret [ERR_AUTH_FAILED]")

        if agent["status"] != "active":
            raise PermissionError(f"Agent {agent_id} is not active [ERR_AGENT_INACTIVE]")

        if nonce:
            nonce_result = self.nonce_manager.consume_nonce(nonce, agent_id)
            if not nonce_result.valid:
                self.audit_logger.write_log(
                    requesting_agent=agent_id,
                    action_type="token_issue",
                    decision="DENY",
                    deny_reason=f"Nonce invalid: {nonce_result.error_code}",
                    error_code=nonce_result.error_code,
                    trace_id=trace_id,
                )
                raise PermissionError(f"Nonce verification failed: {nonce_result.error_code} [{nonce_result.error_code}]")

        svid = self.svid_manager.get_svid(agent_id)
        if svid and svid.expires_at < time.time():
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="svid_expired",
                decision="ALERT",
                deny_reason="SVID expired, auto-rotating",
                trace_id=trace_id,
            )
            self.svid_manager.rotate_svid(agent_id)

        registered_caps = agent["capabilities"]

        delegate_caps_in_request = [c for c in capabilities if c.startswith("delegate:")]
        non_delegate_caps = [c for c in capabilities if not c.startswith("delegate:")]

        if task_description and non_delegate_caps:
            privilege_result = self.capability_engine.compute_dynamic_least_privilege(
                user_permissions=non_delegate_caps,
                agent_capabilities=[c for c in registered_caps if not c.startswith("delegate:")],
                task_description=task_description,
            )
            granted_caps = privilege_result["granted_capabilities"]
            denied_caps = privilege_result["denied_capabilities"]
        else:
            granted_caps = [c for c in non_delegate_caps if c in registered_caps]
            denied_caps = [c for c in non_delegate_caps if c not in registered_caps]

        valid_delegate_caps = [c for c in delegate_caps_in_request if c in registered_caps]
        granted_caps = granted_caps + valid_delegate_caps
        denied_caps = denied_caps + [c for c in delegate_caps_in_request if c not in registered_caps]

        if not granted_caps:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason="No valid capabilities granted",
                denied_capabilities=denied_caps,
                error_code="ERR_NO_CAPABILITY",
                trace_id=trace_id,
            )
            self.circuit_breaker.record_failure(agent_id, "ERR_NO_CAPABILITY")
            raise PermissionError("No valid capabilities can be granted [ERR_NO_CAPABILITY]")

        escalation = self.privilege_detector.detect_escalation(
            agent_id, capabilities, registered_caps
        )
        if escalation["is_escalation"]:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="privilege_escalation_detected",
                decision="ALERT",
                deny_reason="Privilege escalation attempt detected",
                denied_capabilities=escalation["escalated_capabilities"],
                privilege_escalation_detected=True,
                error_code="ERR_PRIVILEGE_ESCALATION",
                trace_id=trace_id,
            )
            self.token_manager.revoke_all_agent_tokens(agent_id)
            self._notify("privilege_escalation", {
                "agent_id": agent_id,
                "escalated": escalation["escalated_capabilities"],
                "action": "all_tokens_revoked",
            })
            self.circuit_breaker.record_failure(agent_id, "ERR_PRIVILEGE_ESCALATION")
            raise PermissionError(
                f"Privilege escalation detected. All active tokens for {agent_id} have been revoked. "
                f"[ERR_PRIVILEGE_ESCALATION]"
            )

        policy_context = {
            "hour": time.localtime().tm_hour,
            "risk_score": 0,
            "delegated_user": delegated_user or "",
            "agent_capabilities": registered_caps,
            "circuit_breaker_open": not self.circuit_breaker.can_proceed(agent_id)["allowed"],
        }
        for cap in list(granted_caps):
            policy_decision = self.policy_engine.evaluate(
                subject_id=agent_id,
                action=cap,
                resource=cap,
                context=policy_context,
            )
            if not policy_decision.allowed:
                granted_caps.remove(cap)
                denied_caps.append(cap)
                self.audit_logger.write_policy_decision(
                    subject_id=agent_id,
                    action=cap,
                    resource=cap,
                    matched_policy=policy_decision.matched_policy,
                    effect="deny",
                    reason=policy_decision.reason,
                    evaluation_trace=policy_decision.evaluation_trace,
                    context=policy_context,
                )

        if not granted_caps:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason="All capabilities denied by policy engine",
                denied_capabilities=denied_caps,
                error_code="ERR_POLICY_DENIED",
                trace_id=trace_id,
            )
            raise PermissionError("All requested capabilities denied by policy [ERR_POLICY_DENIED]")

        risk = self.risk_scorer.compute_risk_score(agent_id, granted_caps)
        risk_score = risk["risk_score"]

        if risk_score >= 90:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason=f"Risk score too high: {risk_score}",
                error_code="ERR_RISK_TOO_HIGH",
                risk_score=risk_score,
                trace_id=trace_id,
            )
            self.token_manager.revoke_all_agent_tokens(agent_id)
            self.circuit_breaker.record_failure(agent_id, "ERR_RISK_TOO_HIGH")
            raise PermissionError(f"Risk score {risk_score} exceeds threshold. Agent frozen. [ERR_RISK_TOO_HIGH]")

        if risk_score >= 70:
            granted_caps = [c for c in granted_caps if ":read" in c or c.startswith("delegate:")]
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="risk_downgrade",
                decision="ALERT",
                deny_reason=f"Risk score {risk_score} >= 70, downgraded to read-only",
                risk_score=risk_score,
                trace_id=trace_id,
            )

        session_id = uuid.uuid4().hex[:16]
        self.session_verifier.create_session(session_id, agent_id)

        if not trace_id:
            trace_id = uuid.uuid4().hex[:16]

        jti = uuid.uuid4().hex

        baseline_hash = ""
        baseline = self.behavior_analyzer.get_baseline_data(agent_id)
        if baseline.get("has_baseline"):
            baseline_hash = baseline["baseline"].get("baseline_hash", "")

        signature = ""
        if agent_id in self._agent_key_pairs:
            private_key = self._agent_key_pairs[agent_id]
            sign_data = f"{agent_id}:{','.join(granted_caps)}:{jti}".encode()
            signature = private_key.sign(
                sign_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            ).hex()

        result = self.token_manager.issue_token(
            agent_id=agent_id,
            agent_type=agent["agent_type"],
            capabilities=granted_caps,
            max_capabilities=registered_caps,
            scope=granted_caps,
            max_scope=granted_caps,
            delegated_user=delegated_user or "",
            trust_chain=[agent_id],
            attenuation_level=0,
            ttl_seconds=3600,
            session_id=session_id,
            behavior_baseline_hash=baseline_hash,
            risk_score=risk_score,
            max_uses=max_uses or 0,
            task_id=task_id or "",
            trace_id=trace_id,
            signature=signature,
            jti=jti,
        )

        self.dpop_verifier.bind_token_to_key(
            jti,
            hashlib.sha256(agent.get("encryption_public_key", "").encode()).hexdigest()[:32]
        )

        self.audit_logger.write_log(
            requesting_agent=agent_id,
            action_type="token_issue",
            decision="ALLOW",
            granted_capabilities=granted_caps,
            denied_capabilities=denied_caps,
            delegated_user=delegated_user or "",
            trust_chain_snapshot=[agent_id],
            attenuation_chain=[0],
            risk_score=risk_score,
            session_fingerprint=session_id,
            trace_id=trace_id,
        )

        self.behavior_analyzer.record_observation(
            agent_id, granted_caps, delegation_depth=0, action_type="token_issue"
        )

        self._notify("token_issued", {
            "agent_id": agent_id,
            "jti": result["jti"],
            "scope": granted_caps,
            "trace_id": trace_id,
            "risk_score": risk_score,
        })

        self.circuit_breaker.record_success(agent_id)

        result["trace_id"] = trace_id
        result["risk_score"] = risk_score
        return result

    def delegate_token(
        self,
        parent_token: str,
        target_agent_id: str,
        requested_capabilities: list,
        delegated_user: str = None,
        one_time: bool = False,
        task_id: str = None,
        trace_id: str = None,
    ) -> dict:
        verify_result = self.token_manager.verify_token(parent_token)
        if not verify_result["valid"]:
            self.audit_logger.write_log(
                requesting_agent="unknown",
                action_type="token_delegate",
                decision="DENY",
                deny_reason=f"Parent token invalid: {verify_result.get('error', '')}",
                error_code="ERR_TOKEN_INVALID",
                target_agent=target_agent_id,
                requested_capability=",".join(requested_capabilities),
            )
            raise PermissionError(f"Parent token invalid: {verify_result.get('error', '')} [ERR_TOKEN_INVALID]")

        parent_payload = verify_result["payload"]
        parent_agent_id = parent_payload["agent_id"]
        parent_caps = parent_payload.get("capabilities", [])
        parent_max_scope = parent_payload.get("max_scope", [])
        parent_trust_chain = parent_payload.get("trust_chain", [])
        parent_attenuation = parent_payload.get("attenuation_level", 0)
        parent_delegated_user = parent_payload.get("delegated_user", "")
        parent_trace_id = trace_id or parent_payload.get("trace_id", "")

        target_agent = self._get_agent(target_agent_id)
        if not target_agent:
            raise ValueError(f"Target agent {target_agent_id} not registered")

        card_check = self._check_agent_card_capability_match(target_agent_id, requested_capabilities)
        if not card_check["match"]:
            self.audit_logger.write_log(
                requesting_agent=parent_agent_id,
                action_type="token_delegate",
                decision="DENY",
                target_agent=target_agent_id,
                requested_capability=",".join(requested_capabilities),
                deny_reason=f"Agent Card capability mismatch: {card_check['reason']}",
                error_code="ERR_CAPABILITY_MISMATCH",
                trust_chain_snapshot=parent_trust_chain,
                trace_id=parent_trace_id,
            )
            self.audit_logger.update_delegation_edge(parent_agent_id, target_agent_id, "DENY")
            raise PermissionError(
                f"Target agent card does not support requested capabilities: {card_check['missing']} "
                f"[ERR_CAPABILITY_MISMATCH]"
            )

        target_name = target_agent["agent_name"]
        delegation_check = self.capability_engine.check_delegation_permission(
            parent_caps, target_name, requested_capabilities
        )

        if not delegation_check["allowed"]:
            self.audit_logger.write_log(
                requesting_agent=parent_agent_id,
                action_type="token_delegate",
                decision="DENY",
                target_agent=target_agent_id,
                requested_capability=",".join(requested_capabilities),
                deny_reason=f"No delegation permission for {target_name}",
                error_code="ERR_DELEGATION_DENIED",
                trust_chain_snapshot=parent_trust_chain,
                trace_id=parent_trace_id,
            )
            self.risk_scorer.update_trust_score(parent_agent_id, -10)
            self.audit_logger.update_delegation_edge(parent_agent_id, target_agent_id, "DENY")
            self._notify("delegation_denied", {
                "from": parent_agent_id,
                "to": target_agent_id,
                "requested": requested_capabilities,
            })
            raise PermissionError(
                f"[ERR_DELEGATION_DENIED] Agent {parent_agent_id} has no delegation permission for {target_name}. "
                f"Required: {delegation_check['delegate_read_perm']} or {delegation_check['delegate_write_perm']}"
            )

        target_registered = target_agent["capabilities"]
        effective_requested = [c for c in requested_capabilities if c in delegation_check["allowed"]]
        delegated_caps = [c for c in effective_requested if c in target_registered]

        delegation_perm_expanded = set()
        for dc in delegation_check["allowed"]:
            if dc.startswith("delegate:"):
                parts = dc.split(":")
                if len(parts) >= 3:
                    perm_type = parts[-1]
                    if perm_type == "read":
                        delegation_perm_expanded.update(c for c in target_registered if ":read" in c)
                    elif perm_type == "write":
                        delegation_perm_expanded.update(c for c in target_registered)
            else:
                delegation_perm_expanded.add(dc)

        agent_caps = set(target_registered)
        delegated_set = set(delegated_caps)
        three_way = delegation_perm_expanded & agent_caps & delegated_set
        if parent_max_scope:
            delegate_max = set()
            for ms in parent_max_scope:
                if ms.startswith("delegate:"):
                    parts = ms.split(":")
                    if len(parts) >= 3:
                        perm_type = parts[-1]
                        if perm_type == "read":
                            delegate_max.update(c for c in target_registered if ":read" in c)
                        elif perm_type == "write":
                            delegate_max.update(c for c in target_registered)
                else:
                    delegate_max.add(ms)
            three_way = three_way & delegate_max
        delegated_caps = sorted(list(three_way))

        for cap in delegated_caps:
            if cap not in parent_max_scope and cap not in delegation_check["allowed"]:
                self.audit_logger.write_log(
                    requesting_agent=parent_agent_id,
                    action_type="token_delegate",
                    decision="DENY",
                    target_agent=target_agent_id,
                    requested_capability=cap,
                    deny_reason=f"Capability {cap} exceeds parent max_scope",
                    error_code="ERR_SCOPE_EXCEEDS_MAX",
                    trust_chain_snapshot=parent_trust_chain,
                    trace_id=parent_trace_id,
                )
                raise PermissionError(f"Capability {cap} exceeds parent max_scope [ERR_SCOPE_EXCEEDS_MAX]")

        if not delegated_caps:
            self.audit_logger.write_log(
                requesting_agent=parent_agent_id,
                action_type="token_delegate",
                decision="DENY",
                target_agent=target_agent_id,
                requested_capability=",".join(requested_capabilities),
                deny_reason="No effective capabilities after intersection",
                error_code="ERR_NO_EFFECTIVE_CAPABILITY",
                trust_chain_snapshot=parent_trust_chain,
                trace_id=parent_trace_id,
            )
            raise PermissionError("No effective capabilities after intersection [ERR_NO_EFFECTIVE_CAPABILITY]")

        escalation = self.privilege_detector.check_delegation_escalation(
            parent_caps, delegated_caps
        )
        if escalation["is_escalation"]:
            self.audit_logger.write_log(
                requesting_agent=parent_agent_id,
                action_type="delegation_escalation",
                decision="ALERT",
                target_agent=target_agent_id,
                privilege_escalation_detected=True,
                deny_reason="Delegation privilege escalation detected",
                error_code="ERR_DELEGATION_ESCALATION",
                trace_id=parent_trace_id,
            )
            self.token_manager.revoke_all_agent_tokens(parent_agent_id)
            self._notify("privilege_escalation", {
                "agent_id": parent_agent_id,
                "type": "delegation_escalation",
                "action": "all_tokens_revoked",
            })

        new_trust_chain = parent_trust_chain + [target_agent_id]
        new_attenuation = parent_attenuation + 1
        new_max_scope = delegated_caps

        risk = self.risk_scorer.compute_risk_score(target_agent_id, delegated_caps)

        session_id = uuid.uuid4().hex[:16]
        self.session_verifier.create_session(session_id, target_agent_id)

        is_sensitive = any(c in self.SENSITIVE_CAPABILITIES for c in delegated_caps)
        human_approval_required = is_sensitive

        if human_approval_required:
            with self._approvals_lock:
                while len(self._pending_approvals) >= self.MAX_PENDING_APPROVALS:
                    self._pending_approvals.popitem(last=False)
                task_id_val = task_id or f"human_approval_{int(time.time())}"
                self._pending_approvals[task_id_val] = {
                    "task_id": task_id_val,
                    "requesting_agent": parent_agent_id,
                    "target_agent": target_agent_id,
                    "requested_capability": ",".join(delegated_caps),
                    "session_id": session_id,
                    "created_at": time.time(),
                    "status": "PENDING_HUMAN_APPROVAL",
                }
            self.audit_logger.write_log(
                requesting_agent=parent_agent_id,
                action_type="human_approval_required",
                decision="ALERT",
                target_agent=target_agent_id,
                requested_capability=",".join(delegated_caps),
                human_approval_required=True,
                trace_id=parent_trace_id,
            )
            self._notify("human_approval_required", {
                "task_id": task_id_val,
                "requesting_agent": parent_agent_id,
                "target_agent": target_agent_id,
                "requested_capability": ",".join(delegated_caps),
                "timeout_seconds": self.HUMAN_APPROVAL_TIMEOUT,
            })

        ttl = self.HUMAN_APPROVAL_TOKEN_TTL if (one_time or human_approval_required) else 3600

        result = self.token_manager.issue_token(
            agent_id=target_agent_id,
            agent_type=target_agent["agent_type"],
            capabilities=delegated_caps,
            max_capabilities=target_registered,
            scope=delegated_caps,
            max_scope=new_max_scope,
            delegated_user=delegated_user or parent_delegated_user,
            parent_agent=parent_agent_id,
            parent_jti=parent_payload.get("jti", ""),
            trust_chain=new_trust_chain,
            attenuation_level=new_attenuation,
            ttl_seconds=ttl,
            session_id=session_id,
            risk_score=risk["risk_score"],
            max_uses=1 if (one_time or human_approval_required) else 0,
            task_id=task_id or "",
            trace_id=parent_trace_id,
        )

        self.audit_logger.write_log(
            requesting_agent=parent_agent_id,
            action_type="token_delegate",
            decision="ALLOW",
            target_agent=target_agent_id,
            requested_capability=",".join(requested_capabilities),
            granted_capabilities=delegated_caps,
            denied_capabilities=[c for c in requested_capabilities if c not in delegated_caps],
            delegated_user=delegated_user or parent_delegated_user,
            trust_chain_snapshot=new_trust_chain,
            attenuation_chain=list(range(new_attenuation + 1)),
            risk_score=risk["risk_score"],
            session_fingerprint=session_id,
            trace_id=parent_trace_id,
            human_approval_required=human_approval_required,
        )

        self.behavior_analyzer.record_observation(
            target_agent_id, delegated_caps, delegation_depth=new_attenuation, target_agent=target_agent_id
        )

        self.audit_logger.update_delegation_edge(parent_agent_id, target_agent_id, "ALLOW")

        self._notify("delegation_success", {
            "from": parent_agent_id,
            "to": target_agent_id,
            "capabilities": delegated_caps,
            "attenuation": new_attenuation,
        })

        result["delegated_capabilities"] = delegated_caps
        result["trace_id"] = parent_trace_id
        result["human_approval_required"] = human_approval_required
        if human_approval_required:
            result["task_id"] = task_id_val
        return result

    def verify_token(
        self,
        token: str,
        verifier_agent_id: str,
        verifier_secret: str,
        required_capability: str = None,
        dpop_proof: str = None,
    ) -> dict:
        verifier = self._get_agent(verifier_agent_id)
        if not verifier:
            raise ValueError(f"Verifier agent {verifier_agent_id} not registered")
        if not hmac.compare_digest(verifier["client_secret"], verifier_secret):
            raise PermissionError("Invalid verifier secret [ERR_AUTH_FAILED]")

        verify_result = self.token_manager.verify_token(token)
        if not verify_result["valid"]:
            error = verify_result.get("error", "Token invalid")
            if error in ("TOKEN_EXPIRED",):
                error_code = "ERR_TOKEN_EXPIRED"
            elif error == "TOKEN_REVOKED":
                error_code = "ERR_TOKEN_REVOKED"
            elif error == "TOKEN_MAX_USES_EXCEEDED":
                error_code = "ERR_TOKEN_MAX_USES"
            elif error == "TOKEN_NOT_FOUND":
                error_code = "ERR_IDENTITY_UNVERIFIABLE"
            else:
                error_code = "ERR_IDENTITY_UNVERIFIABLE"
            self.audit_logger.write_log(
                requesting_agent=verifier_agent_id,
                action_type="token_verify",
                decision="DENY",
                deny_reason=error,
                error_code=error_code,
            )
            raise PermissionError(f"Token invalid: {error} [{error_code}]")

        payload = verify_result["payload"]
        token_caps = payload.get("capabilities", [])

        session_id = payload.get("session_id", "")
        if session_id:
            session_result = self.session_verifier.verify_session(session_id)
            if not session_result["valid"]:
                self.token_manager.revoke_token(jti=payload.get("jti"))
                self.audit_logger.write_log(
                    requesting_agent=verifier_agent_id,
                    action_type="token_verify",
                    decision="DENY",
                    deny_reason=f"Session invalid: {session_result.get('error', '')}",
                    error_code="ERR_SESSION_INVALID",
                    session_fingerprint=session_id,
                )
                raise PermissionError(f"Session invalid: {session_result.get('error', '')} [ERR_SESSION_INVALID]")

        if required_capability:
            if required_capability not in token_caps:
                self.audit_logger.write_log(
                    requesting_agent=verifier_agent_id,
                    action_type="token_verify",
                    decision="DENY",
                    deny_reason=f"Missing required capability: {required_capability}",
                    requested_capability=required_capability,
                    error_code="ERR_CAPABILITY_INSUFFICIENT",
                    trace_id=payload.get("trace_id", ""),
                )
                raise PermissionError(f"Token lacks required capability: {required_capability} [ERR_CAPABILITY_INSUFFICIENT]")

        if dpop_proof:
            agent = self._get_agent(payload.get("agent_id", ""))
            if agent and agent.get("encryption_public_key"):
                dpop_result = self.dpop_verifier.verify_dpop_proof(
                    dpop_proof_jwt=dpop_proof,
                    public_key_pem=agent["encryption_public_key"],
                    htm="POST",
                    htu="/api/tokens/verify",
                    access_token=token,
                )
                if not dpop_result.valid:
                    self.audit_logger.write_log(
                        requesting_agent=verifier_agent_id,
                        action_type="token_verify",
                        decision="DENY",
                        deny_reason=f"DPoP proof invalid: {dpop_result.error_message}",
                        error_code=f"ERR_{dpop_result.error_code}",
                        trace_id=payload.get("trace_id", ""),
                    )
                    raise PermissionError(f"DPoP proof verification failed: {dpop_result.error_message} [ERR_{dpop_result.error_code}]")
            else:
                self.audit_logger.write_log(
                    requesting_agent=verifier_agent_id,
                    action_type="token_verify",
                    decision="DENY",
                    deny_reason="DPoP proof provided but no public key for token holder",
                    error_code="ERR_DPOP_NO_KEY",
                    trace_id=payload.get("trace_id", ""),
                )
                raise PermissionError("DPoP proof provided but no public key available [ERR_DPOP_NO_KEY]")

        token_agent_id = payload.get("agent_id", "")
        if token_agent_id:
            svid = self.svid_manager.get_svid(token_agent_id)
            if svid and svid.expires_at < time.time():
                self.audit_logger.write_log(
                    requesting_agent=verifier_agent_id,
                    action_type="token_verify",
                    decision="DENY",
                    deny_reason="Token holder SVID expired",
                    error_code="ERR_SVID_EXPIRED",
                    trace_id=payload.get("trace_id", ""),
                )
                raise PermissionError("Token holder SVID has expired [ERR_SVID_EXPIRED]")

        agent_id = payload.get("agent_id", "")
        signature_hex = payload.get("signature", "")
        if signature_hex and agent_id in self._agent_key_pairs:
            try:
                server_private_key = self._agent_key_pairs[agent_id]
                server_public_key = server_private_key.public_key()
                sign_data = f"{agent_id}:{','.join(token_caps)}:{payload.get('jti', '')}".encode()
                server_public_key.verify(
                    bytes.fromhex(signature_hex),
                    sign_data,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except Exception:
                self.audit_logger.write_log(
                    requesting_agent=verifier_agent_id,
                    action_type="token_verify",
                    decision="DENY",
                    deny_reason="mTLS signature verification failed",
                    error_code="ERR_IDENTITY_UNVERIFIABLE",
                    trace_id=payload.get("trace_id", ""),
                )
                raise PermissionError("mTLS signature verification failed [ERR_IDENTITY_UNVERIFIABLE]")
        elif signature_hex:
            self.audit_logger.write_log(
                requesting_agent=verifier_agent_id,
                action_type="token_verify",
                decision="DENY",
                deny_reason="mTLS signing key not found for agent",
                error_code="ERR_IDENTITY_UNVERIFIABLE",
                trace_id=payload.get("trace_id", ""),
            )
            raise PermissionError("mTLS signing key not found [ERR_IDENTITY_UNVERIFIABLE]")

        self.audit_logger.write_log(
            requesting_agent=verifier_agent_id,
            action_type="token_verify",
            decision="ALLOW",
            requested_capability=required_capability or "",
            granted_capabilities=token_caps,
            trust_chain_snapshot=payload.get("trust_chain", []),
            risk_score=payload.get("risk_score_at_issuance", 0),
            session_fingerprint=session_id,
            trace_id=payload.get("trace_id", ""),
        )

        return {
            "valid": True,
            "jti": payload.get("jti"),
            "agent_id": payload.get("agent_id"),
            "capabilities": token_caps,
            "max_scope": payload.get("max_scope", []),
            "attenuation_level": payload.get("attenuation_level", 0),
            "trust_chain": payload.get("trust_chain", []),
            "delegated_user": payload.get("delegated_user", ""),
            "session_id": session_id,
            "expires_at": payload.get("expires_at"),
            "risk_score": payload.get("risk_score_at_issuance", 0),
        }

    def revoke_token(self, jti: str = None, token: str = None, cascade: bool = True) -> dict:
        result = self.token_manager.revoke_token(jti=jti, token_str=token, cascade=cascade)

        if result.get("revoked"):
            cascade_info = ""
            if result.get("cascade_count", 0) > 0:
                cascade_info = f" (cascade: {result['cascade_count']} child tokens)"
            self.audit_logger.write_log(
                requesting_agent="system",
                action_type="token_revoke",
                decision="ALLOW",
                deny_reason=f"Token revoked{cascade_info}",
            )
            self._notify("token_revoked", {"jti": result.get("jti"), "cascade_count": result.get("cascade_count", 0)})

        return result

    def get_delegation_graph(self) -> dict:
        conn = self._get_conn()
        agents = conn.execute("SELECT agent_id, agent_name, trust_score, status FROM agents").fetchall()

        edges_rows = conn.execute(
            "SELECT source, target, success_count, deny_count, last_decision FROM delegation_edges ORDER BY last_timestamp DESC"
        ).fetchall()
        self._return_conn(conn)

        nodes = []
        for a in agents:
            nodes.append({
                "id": a["agent_id"],
                "name": a["agent_name"],
                "trust_score": a["trust_score"],
                "status": a["status"],
            })

        edges = []
        for e in edges_rows:
            edges.append({
                "source": e["source"],
                "target": e["target"],
                "success_count": e["success_count"],
                "deny_count": e["deny_count"],
                "last_decision": e["last_decision"],
            })

        return {"nodes": nodes, "edges": edges}

    def resolve_approval(self, task_id: str, approved: bool) -> dict:
        with self._approvals_lock:
            if task_id in self._pending_approvals:
                approval = self._pending_approvals[task_id]
                if approved:
                    approval["status"] = "approved"
                    self.audit_logger.write_log(
                        requesting_agent=approval["requesting_agent"],
                        action_type="human_approval_result",
                        decision="ALLOW",
                        target_agent=approval["target_agent"],
                        human_approval_required=True,
                        human_approval_result="APPROVED",
                    )
                else:
                    approval["status"] = "rejected"
                    session_id = approval.get("session_id", "")
                    if session_id:
                        token_record = self.token_manager.get_token_by_session(session_id)
                        if token_record:
                            self.token_manager.revoke_token(jti=token_record["jti"])
                    self.audit_logger.write_log(
                        requesting_agent=approval["requesting_agent"],
                        action_type="human_approval_result",
                        decision="DENY",
                        deny_reason="Human approval rejected",
                        error_code="ERR_HUMAN_REJECTED",
                        human_approval_required=True,
                        human_approval_result="REJECTED",
                    )
                del self._pending_approvals[task_id]
                self._notify("human_approval_result", {"task_id": task_id, "approved": approved})
                return {"task_id": task_id, "status": approval["status"]}

        return {"task_id": task_id, "status": "not_found"}

    def check_approval_timeouts(self) -> list:
        now = time.time()
        timed_out = []
        with self._approvals_lock:
            for task_id, approval in list(self._pending_approvals.items()):
                if now - approval["created_at"] > self.HUMAN_APPROVAL_TIMEOUT:
                    approval["status"] = "timeout_rejected"
                    self.audit_logger.write_log(
                        requesting_agent=approval["requesting_agent"],
                        action_type="human_approval_timeout",
                        decision="DENY",
                        deny_reason=f"Human approval timed out after {self.HUMAN_APPROVAL_TIMEOUT}s",
                        error_code="ERR_TIMEOUT_REJECTION",
                        human_approval_required=True,
                        human_approval_result="TIMEOUT_REJECTION",
                    )
                    timed_out.append(task_id)
                    del self._pending_approvals[task_id]
                    self._notify("human_approval_result", {"task_id": task_id, "approved": False, "timeout": True})
        return timed_out

    def get_pending_approvals(self) -> list:
        with self._approvals_lock:
            return list(self._pending_approvals.values())

    def get_svid(self, agent_id: str) -> dict:
        svid = self.svid_manager.get_svid(agent_id)
        if not svid:
            return {"error": "SVID not found", "agent_id": agent_id}
        return {
            "spiffe_id": svid.spiffe_id,
            "agent_id": svid.agent_id,
            "trust_domain": svid.trust_domain,
            "issued_at": svid.issued_at,
            "expires_at": svid.expires_at,
            "serial_number": svid.serial_number,
        }

    def rotate_svid(self, agent_id: str) -> dict:
        agent = self._get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not registered")
        new_svid = self.svid_manager.rotate_svid(agent_id)
        self.audit_logger.write_svid_event(agent_id, "svid_rotated", new_svid.spiffe_id, new_svid.expires_at)
        self._notify("svid_rotated", {"agent_id": agent_id, "spiffe_id": new_svid.spiffe_id})
        return {
            "spiffe_id": new_svid.spiffe_id,
            "agent_id": new_svid.agent_id,
            "trust_domain": new_svid.trust_domain,
            "issued_at": new_svid.issued_at,
            "expires_at": new_svid.expires_at,
            "serial_number": new_svid.serial_number,
        }

    def get_trust_bundle(self) -> dict:
        return self.svid_manager.get_trust_bundle()

    def evaluate_policy(self, subject_id: str, action: str, resource: str, context: dict = None) -> dict:
        decision = self.policy_engine.evaluate(subject_id, action, resource, context)
        self.audit_logger.write_policy_decision(
            subject_id=subject_id,
            action=action,
            resource=resource,
            matched_policy=decision.matched_policy,
            effect="allow" if decision.allowed else "deny",
            reason=decision.reason,
            evaluation_trace=decision.evaluation_trace,
            context=context or {},
        )
        return {
            "allowed": decision.allowed,
            "matched_policy": decision.matched_policy,
            "reason": decision.reason,
            "applicable_policies": decision.applicable_policies,
            "evaluation_trace": decision.evaluation_trace,
        }

    def get_all_policies(self) -> dict:
        return {"policies": self.policy_engine.get_all_policies()}

    def reload_policies(self) -> dict:
        return self.policy_engine.reload_policies()

    def get_rate_limit_stats(self) -> dict:
        agents = self.list_agents()
        stats = {}
        for agent in agents:
            agent_stats = self.rate_limiter.get_agent_rate_stats(agent["agent_id"])
            if any(v["current_count"] > 0 for v in agent_stats.values()):
                stats[agent["agent_id"]] = agent_stats
        return stats

    def get_circuit_breaker_states(self) -> dict:
        return self.circuit_breaker.get_all_states()

    def get_threat_summary(self) -> dict:
        return self.audit_logger.get_threat_summary()

    def get_capabilities_matrix(self) -> dict:
        agents = self.list_agents()
        return self.audit_logger.get_capabilities_matrix(agents)

    def get_global_timeline(self, limit: int = 100) -> list:
        return self.audit_logger.get_global_timeline(limit)

    def get_compliance_report(self) -> dict:
        return self.incident_responder.generate_compliance_report()

    def get_incidents(self, agent_id: str = None, limit: int = 50) -> list:
        return self.incident_responder.get_open_incidents(agent_id, limit)

    def get_incident_stats(self) -> dict:
        return self.incident_responder.get_incident_stats()

    def resolve_incident(self, incident_id: int) -> dict:
        return self.incident_responder.resolve_incident(incident_id)

    def issue_nonce(self, agent_id: str) -> str:
        return self.nonce_manager.issue_nonce(agent_id)

    def cleanup_expired_data(self) -> dict:
        token_cleanup = self.token_manager.cleanup_expired()
        nonce_cleanup = self.nonce_manager.cleanup_expired()
        return {"tokens": token_cleanup, "nonces": nonce_cleanup}

    def freeze_agent(self, agent_id: str) -> dict:
        conn = self._get_conn()
        agent = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent:
            self._return_conn(conn)
            return {"error": f"Agent {agent_id} not found", "frozen": False}
        conn.execute("UPDATE agents SET status = 'frozen' WHERE agent_id = ?", (agent_id,))
        conn.commit()
        self._return_conn(conn)
        revoked = self.token_manager.revoke_all_agent_tokens(agent_id)
        self.audit_logger.write_log(
            requesting_agent=agent_id, action_type="agent_frozen",
            decision="DENY", deny_reason="Agent manually frozen",
            trace_id=uuid.uuid4().hex[:16],
        )
        self._notify("agent_frozen", {"agent_id": agent_id, "revoked_count": revoked.get("revoked_count", 0)})
        return {"agent_id": agent_id, "status": "frozen", "revoked_tokens": revoked.get("revoked_count", 0)}

    def unfreeze_agent(self, agent_id: str) -> dict:
        conn = self._get_conn()
        agent = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent:
            self._return_conn(conn)
            return {"error": f"Agent {agent_id} not found", "unfrozen": False}
        conn.execute("UPDATE agents SET status = 'active' WHERE agent_id = ?", (agent_id,))
        conn.commit()
        self._return_conn(conn)
        self.audit_logger.write_log(
            requesting_agent=agent_id, action_type="agent_unfrozen",
            decision="ALLOW", trace_id=uuid.uuid4().hex[:16],
        )
        self._notify("agent_unfrozen", {"agent_id": agent_id})
        return {"agent_id": agent_id, "status": "active"}

    def get_risk_trend(self, agent_id: str, window_minutes: int = 60) -> list:
        return self.audit_logger.get_risk_trend(agent_id, window_minutes)
