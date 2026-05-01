import json
import os
import time
import uuid
import hashlib
import sqlite3
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import jwt


class TokenManager:

    TOKEN_VERSION = "1.0"

    def __init__(self, db_path: str, key_dir: str = None):
        self.db_path = db_path
        if key_dir is None:
            key_dir = os.path.join(os.path.dirname(db_path), "keys")
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)
        self._init_db()
        self._ensure_rsa_key()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tokens (
                jti TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                agent_type TEXT DEFAULT '',
                capabilities TEXT DEFAULT '[]',
                max_capabilities TEXT DEFAULT '[]',
                scope TEXT DEFAULT '[]',
                max_scope TEXT DEFAULT '[]',
                delegated_user TEXT DEFAULT '',
                parent_agent TEXT DEFAULT '',
                parent_jti TEXT DEFAULT '',
                trust_chain TEXT DEFAULT '[]',
                attenuation_level INTEGER DEFAULT 0,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                session_id TEXT DEFAULT '',
                behavior_baseline_hash TEXT DEFAULT '',
                risk_score_at_issuance REAL DEFAULT 0.0,
                signature TEXT DEFAULT '',
                prev_token_hash TEXT DEFAULT '',
                is_revoked INTEGER DEFAULT 0,
                revoked_at REAL DEFAULT 0,
                max_uses INTEGER DEFAULT 0,
                use_count INTEGER DEFAULT 0,
                token_data TEXT DEFAULT '{}',
                task_id TEXT DEFAULT '',
                trace_id TEXT DEFAULT '',
                created_at REAL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_agent ON tokens(agent_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(is_revoked);
        """)
        conn.commit()
        conn.close()

    def _ensure_rsa_key(self):
        priv_path = os.path.join(self.key_dir, "token_private.pem")
        pub_path = os.path.join(self.key_dir, "token_public.pem")
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            try:
                with open(priv_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(pub_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                return
            except Exception:
                pass
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        try:
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
        except Exception:
            pass

    def sign_token(self, payload: dict) -> str:
        now = time.time()
        payload["iat"] = int(now)
        payload["jti"] = payload.get("jti", uuid.uuid4().hex)
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def verify_signature(self, token_str: str) -> dict:
        try:
            payload = jwt.decode(token_str, self.public_key, algorithms=["RS256"])
            return {"valid": True, "payload": payload}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "TOKEN_EXPIRED"}
        except jwt.InvalidTokenError as e:
            return {"valid": False, "error": str(e)}

    def issue_token(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: list,
        max_capabilities: list,
        scope: list,
        max_scope: list,
        delegated_user: str = "",
        parent_agent: str = "",
        parent_jti: str = "",
        trust_chain: list = None,
        attenuation_level: int = 0,
        ttl_seconds: int = 3600,
        session_id: str = "",
        behavior_baseline_hash: str = "",
        risk_score: float = 0.0,
        max_uses: int = 0,
        task_id: str = "",
        trace_id: str = "",
        signature: str = "",
        jti: str = "",
    ) -> dict:
        now = time.time()
        if not jti:
            jti = uuid.uuid4().hex
        expires_at = now + ttl_seconds

        if trust_chain is None:
            trust_chain = [agent_id]

        prev_hash = ""
        if parent_jti:
            parent_token = self.get_token(parent_jti)
            if parent_token:
                prev_hash = hashlib.sha256(
                    parent_token["token_data"].encode()
                ).hexdigest()

        token_payload = {
            "jti": jti,
            "version": self.TOKEN_VERSION,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "capabilities": capabilities,
            "max_capabilities": max_capabilities,
            "scope": scope,
            "max_scope": max_scope,
            "delegated_user": delegated_user,
            "parent_agent": parent_agent,
            "trust_chain": trust_chain,
            "attenuation_level": attenuation_level,
            "issued_at": now,
            "expires_at": expires_at,
            "session_id": session_id,
            "behavior_baseline_hash": behavior_baseline_hash,
            "risk_score_at_issuance": risk_score,
            "signature": signature,
            "prev_token_hash": prev_hash,
            "task_id": task_id,
            "trace_id": trace_id,
        }

        token_str = self.sign_token(token_payload)

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO tokens
            (jti, agent_id, agent_type, capabilities, max_capabilities, scope, max_scope,
             delegated_user, parent_agent, parent_jti, trust_chain, attenuation_level,
             issued_at, expires_at, session_id, behavior_baseline_hash, risk_score_at_issuance,
             signature, prev_token_hash, max_uses, use_count, token_data, task_id, trace_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                jti, agent_id, agent_type,
                json.dumps(capabilities), json.dumps(max_capabilities),
                json.dumps(scope), json.dumps(max_scope),
                delegated_user, parent_agent, parent_jti,
                json.dumps(trust_chain), attenuation_level,
                now, expires_at, session_id, behavior_baseline_hash, risk_score,
                signature, prev_hash,
                max_uses, 0, token_str, task_id, trace_id, now,
            ),
        )
        conn.commit()
        conn.close()

        return {
            "jti": jti,
            "access_token": token_str,
            "token_type": "Bearer",
            "expires_in": ttl_seconds,
            "scope": scope,
            "max_scope": max_scope,
            "attenuation_level": attenuation_level,
            "trust_chain": trust_chain,
            "session_id": session_id,
            "trace_id": trace_id,
            "prev_token_hash": prev_hash,
        }

    def get_token(self, jti: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM tokens WHERE jti = ?", (jti,)).fetchone()
        conn.close()
        if not row:
            return None
        return dict(row)

    def verify_token(self, token_str: str) -> dict:
        sig_result = self.verify_signature(token_str)
        if not sig_result["valid"]:
            return sig_result

        payload = sig_result["payload"]
        jti = payload.get("jti", "")

        token_record = self.get_token(jti)
        if not token_record:
            return {"valid": False, "error": "TOKEN_NOT_FOUND"}

        if token_record["is_revoked"]:
            return {"valid": False, "error": "TOKEN_REVOKED", "revoked_at": token_record["revoked_at"]}

        if time.time() > token_record["expires_at"]:
            return {"valid": False, "error": "TOKEN_EXPIRED"}

        max_uses = token_record["max_uses"]
        if max_uses > 0 and token_record["use_count"] >= max_uses:
            return {"valid": False, "error": "TOKEN_MAX_USES_EXCEEDED"}

        conn = self._get_conn()
        conn.execute(
            "UPDATE tokens SET use_count = use_count + 1 WHERE jti = ?", (jti,)
        )
        conn.commit()
        conn.close()

        return {
            "valid": True,
            "payload": payload,
            "jti": jti,
            "agent_id": payload.get("agent_id"),
            "capabilities": payload.get("capabilities", []),
            "max_scope": payload.get("max_scope", []),
            "attenuation_level": payload.get("attenuation_level", 0),
            "trust_chain": payload.get("trust_chain", []),
            "delegated_user": payload.get("delegated_user", ""),
            "session_id": payload.get("session_id", ""),
            "risk_score_at_issuance": payload.get("risk_score_at_issuance", 0.0),
        }

    def revoke_token(self, jti: str = None, token_str: str = None) -> dict:
        if token_str and not jti:
            sig_result = self.verify_signature(token_str)
            if sig_result["valid"]:
                jti = sig_result["payload"].get("jti")
            else:
                return {"revoked": False, "error": "Invalid token"}

        if not jti:
            return {"revoked": False, "error": "No jti provided"}

        conn = self._get_conn()
        now = time.time()
        cursor = conn.execute(
            "UPDATE tokens SET is_revoked = 1, revoked_at = ? WHERE jti = ?",
            (now, jti),
        )
        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return {"revoked": affected > 0, "jti": jti, "revoked_at": now}

    def revoke_all_agent_tokens(self, agent_id: str) -> dict:
        conn = self._get_conn()
        now = time.time()
        cursor = conn.execute(
            "UPDATE tokens SET is_revoked = 1, revoked_at = ? WHERE agent_id = ? AND is_revoked = 0",
            (now, agent_id),
        )
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return {"revoked_count": affected, "agent_id": agent_id}

    def get_active_tokens_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tokens WHERE is_revoked = 0 AND expires_at > ?",
            (time.time(),),
        ).fetchone()
        conn.close()
        return row["cnt"] if row else 0

    def get_revoked_tokens_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tokens WHERE is_revoked = 1"
        ).fetchone()
        conn.close()
        return row["cnt"] if row else 0

    def get_total_tokens_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM tokens").fetchone()
        conn.close()
        return row["cnt"] if row else 0

    def get_token_by_session(self, session_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM tokens WHERE session_id = ? AND is_revoked = 0 AND expires_at > ? ORDER BY issued_at DESC LIMIT 1",
            (session_id, time.time()),
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def cleanup_expired(self, max_age_days: int = 7) -> dict:
        now = time.time()
        cutoff = now - (max_age_days * 86400)
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM tokens WHERE (is_revoked = 1 OR expires_at < ?) AND created_at < ?",
            (now, cutoff),
        )
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        return {"deleted": deleted, "cutoff_days": max_age_days}

    def refresh_token(self, jti: str, ttl_seconds: int = 3600) -> dict:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM tokens WHERE jti = ? AND is_revoked = 0", (jti,)).fetchone()
        if not row:
            conn.close()
            return {"refreshed": False, "error": "Token not found or revoked"}
        token = dict(row)
        new_expires = time.time() + ttl_seconds
        conn.execute(
            "UPDATE tokens SET expires_at = ? WHERE jti = ?",
            (new_expires, jti),
        )
        conn.commit()
        conn.close()
        return {"refreshed": True, "jti": jti, "new_expires_at": new_expires}

    def get_agent_tokens(self, agent_id: str, active_only: bool = True) -> list:
        conn = self._get_conn()
        if active_only:
            rows = conn.execute(
                "SELECT * FROM tokens WHERE agent_id = ? AND is_revoked = 0 AND expires_at > ? ORDER BY issued_at DESC",
                (agent_id, time.time()),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tokens WHERE agent_id = ? ORDER BY issued_at DESC LIMIT 50",
                (agent_id,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
