import json
import time
import uuid
import hashlib
import sqlite3
from typing import Optional
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


class AuthServer:

    SENSITIVE_CAPABILITIES = ["lark:contact:read", "lark:bitable:write"]
    SENSITIVE_READ_THRESHOLD = 100
    HUMAN_APPROVAL_TOKEN_TTL = 300

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

        self.token_manager = TokenManager(db_path)
        self.audit_logger = AuditLogger(db_path)
        self.capability_engine = CapabilityEngine()
        self.risk_scorer = RiskScorer(db_path)
        self.behavior_analyzer = BehaviorAnalyzer(db_path)
        self.session_verifier = SessionVerifier()
        self.privilege_detector = PrivilegeDetector(db_path)
        self.injection_scanner = InjectionScanner()

        self._ws_notify = None
        self._agent_key_pairs = {}

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
                created_at REAL NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def set_ws_notify(self, func):
        self._ws_notify = func

    def _notify(self, event_type: str, data: dict):
        if self._ws_notify:
            try:
                self._ws_notify(event_type, data)
            except Exception:
                pass

    def _generate_secret(self, agent_id: str) -> str:
        raw = f"{agent_id}:{time.time()}:{uuid.uuid4().hex}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

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

        if authentication_schemes is None:
            authentication_schemes = ["mTLS", "Bearer"]
        if skill_descriptions is None:
            skill_descriptions = []

        existing = conn.execute(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

        if existing:
            conn.execute(
                """UPDATE agents SET agent_name = ?, agent_type = ?, capabilities = ?,
                   encryption_public_key = ?, endpoint_url = ?,
                   authentication_schemes = ?, skill_descriptions = ?,
                   baseline_capabilities = ? WHERE agent_id = ?""",
                (agent_name, agent_type, json.dumps(capabilities),
                 encryption_public_key, endpoint_url,
                 json.dumps(authentication_schemes), json.dumps(skill_descriptions),
                 json.dumps(capabilities), agent_id),
            )
            conn.commit()
            agent = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            conn.close()
            return dict(agent)
        else:
            client_secret = self._generate_secret(agent_id)
            now = time.time()
            conn.execute(
                """INSERT INTO agents
                (agent_id, agent_name, agent_type, capabilities, client_secret, trust_score,
                 status, encryption_public_key, endpoint_url, authentication_schemes,
                 skill_descriptions, baseline_capabilities, created_at)
                VALUES (?, ?, ?, ?, ?, 100.0, 'active', ?, ?, ?, ?, ?, ?)""",
                (agent_id, agent_name, agent_type, json.dumps(capabilities),
                 client_secret, encryption_public_key, endpoint_url,
                 json.dumps(authentication_schemes), json.dumps(skill_descriptions),
                 json.dumps(capabilities), now),
            )
            conn.commit()
            conn.close()

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
            }

    def _get_agent(self, agent_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        agent = dict(row)
        for field in ["capabilities", "authentication_schemes", "skill_descriptions", "baseline_capabilities"]:
            try:
                agent[field] = json.loads(agent[field])
            except (json.JSONDecodeError, TypeError):
                agent[field] = []
        return agent

    def list_agents(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents ORDER BY created_at ASC").fetchall()
        conn.close()
        results = []
        for row in rows:
            agent = dict(row)
            for field in ["capabilities", "authentication_schemes", "skill_descriptions", "baseline_capabilities"]:
                try:
                    agent[field] = json.loads(agent[field])
                except (json.JSONDecodeError, TypeError):
                    agent[field] = []
            results.append(agent)
        return results

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
            "skill_descriptions": skill_descriptions,
            "agent_type": agent["agent_type"],
            "status": agent["status"],
            "created_at": agent["created_at"],
        }

    def get_trust_history(self, agent_id: str, limit: int = 100) -> list:
        return self.audit_logger.query_logs(
            requesting_agent=agent_id, limit=limit
        )

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
    ) -> dict:
        agent = self._get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not registered")

        if agent["client_secret"] != client_secret:
            self.audit_logger.write_log(
                requesting_agent=agent_id,
                action_type="token_issue",
                decision="DENY",
                deny_reason="Invalid client_secret",
                error_code="ERR_AUTH_FAILED",
            )
            raise PermissionError("Invalid client_secret [ERR_AUTH_FAILED]")

        if agent["status"] != "active":
            raise PermissionError(f"Agent {agent_id} is not active [ERR_AGENT_INACTIVE]")

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
            raise PermissionError(
                f"Privilege escalation detected. All active tokens for {agent_id} have been revoked. "
                f"[ERR_PRIVILEGE_ESCALATION]"
            )

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
            raise PermissionError(f"Risk score {risk_score} exceeds threshold. Agent frozen. [ERR_RISK_TOO_HIGH]")

        if risk_score >= 70:
            granted_caps = [c for c in granted_caps if ":read" in c or c.startswith("delegate:")]
            self.audit_logger.create_risk_event(
                agent_id, risk_score, "downgrade_to_readonly",
                json.dumps({"original_caps": capabilities, "downgraded_to": granted_caps}),
            )

        session_id = uuid.uuid4().hex[:16]
        self.session_verifier.create_session(session_id, agent_id)

        if not trace_id:
            trace_id = uuid.uuid4().hex[:16]

        baseline_hash = ""
        baseline = self.behavior_analyzer.get_baseline_data(agent_id)
        if baseline.get("has_baseline"):
            baseline_hash = baseline["baseline"].get("baseline_hash", "")

        signature = ""
        if agent_id in self._agent_key_pairs:
            private_key = self._agent_key_pairs[agent_id]
            sign_data = f"{agent_id}:{','.join(granted_caps)}:{time.time()}".encode()
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
            agent_id, granted_caps, delegation_depth=0
        )

        self.audit_logger.update_delegation_edge(agent_id, agent_id, "ALLOW")

        self._notify("token_issued", {
            "agent_id": agent_id,
            "jti": result["jti"],
            "scope": granted_caps,
            "trace_id": trace_id,
            "risk_score": risk_score,
        })

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
        resource: str = None,
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
            raise PermissionError(
                f"Target agent card does not support requested capabilities: {card_check['missing']} "
                f"[ERR_CAPABILITY_MISMATCH]"
            )

        target_name = target_agent["agent_name"]
        delegation_check = self.capability_engine.check_delegation_permission(
            parent_caps, target_name, requested_capabilities
        )

        if not delegation_check["allowed"] and not delegation_check["has_delegate_read"] and not delegation_check["has_delegate_write"]:
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
            self.audit_logger.create_risk_event(
                parent_agent_id, 50.0, "delegation_denied",
                json.dumps({"target": target_agent_id, "requested": requested_capabilities}),
            )

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

        if parent_max_scope:
            delegatable_scope = set(parent_max_scope)
            for cap in delegation_check["allowed"]:
                delegatable_scope.add(cap)
            delegated_caps = [c for c in delegated_caps if c in delegatable_scope]

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
            task_id_val = task_id or f"human_approval_{int(time.time())}"
            self.audit_logger.create_human_approval(
                task_id=task_id_val,
                requesting_agent=parent_agent_id,
                target_agent=target_agent_id,
                requested_capability=",".join(delegated_caps),
                session_id=session_id,
            )
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
                "timeout_seconds": 30,
            })

        ttl = self.HUMAN_APPROVAL_TOKEN_TTL if (one_time or human_approval_required) else 1800 if one_time else 3600

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
        return result

    def verify_token(
        self,
        token: str,
        verifier_agent_id: str,
        verifier_secret: str,
        required_capability: str = None,
        resource: str = None,
        context: dict = None,
    ) -> dict:
        verifier = self._get_agent(verifier_agent_id)
        if not verifier:
            raise ValueError(f"Verifier agent {verifier_agent_id} not registered")
        if verifier["client_secret"] != verifier_secret:
            raise PermissionError("Invalid verifier secret [ERR_AUTH_FAILED]")

        verify_result = self.token_manager.verify_token(token)
        if not verify_result["valid"]:
            self.audit_logger.write_log(
                requesting_agent=verifier_agent_id,
                action_type="token_verify",
                decision="DENY",
                deny_reason=verify_result.get("error", "Token invalid"),
                error_code="ERR_TOKEN_INVALID",
            )
            raise PermissionError(f"Token invalid: {verify_result.get('error', '')} [ERR_TOKEN_INVALID]")

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

        agent_id = payload.get("agent_id", "")
        agent = self._get_agent(agent_id)
        if agent and agent.get("encryption_public_key"):
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                pub_key = load_pem_public_key(agent["encryption_public_key"].encode())
                signature_hex = payload.get("signature", "")
                if signature_hex:
                    sign_data = f"{agent_id}:{','.join(token_caps)}:{payload.get('issued_at', 0)}".encode()
                    pub_key.verify(
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

    def revoke_token(self, jti: str = None, token: str = None) -> dict:
        result = self.token_manager.revoke_token(jti=jti, token_str=token)

        if result.get("revoked"):
            self.audit_logger.write_log(
                requesting_agent="system",
                action_type="token_revoke",
                decision="ALLOW",
                deny_reason="Token revoked",
            )
            self._notify("token_revoked", {"jti": result.get("jti")})

        return result

    def get_delegation_graph(self) -> dict:
        conn = self._get_conn()
        agents = conn.execute("SELECT agent_id, agent_name, trust_score, status FROM agents").fetchall()
        edges = conn.execute("SELECT * FROM delegation_edges").fetchall()
        conn.close()

        nodes = []
        for a in agents:
            nodes.append({
                "id": a["agent_id"],
                "name": a["agent_name"],
                "trust_score": a["trust_score"],
                "status": a["status"],
            })

        edge_list = []
        for e in edges:
            edge_list.append({
                "source": e["source"],
                "target": e["target"],
                "success_count": e["success_count"],
                "deny_count": e["deny_count"],
                "last_decision": e["last_decision"],
            })

        return {"nodes": nodes, "edges": edge_list}
