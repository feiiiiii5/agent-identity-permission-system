import hashlib
import time
import uuid


class SessionVerifier:

    SESSION_TIMEOUT_SECONDS = 1800

    def __init__(self):
        self._sessions = {}

    def create_session(self, session_id: str, agent_id: str, fingerprint: str = "") -> dict:
        now = time.time()
        fp = fingerprint or self._generate_fingerprint(agent_id, session_id)
        self._sessions[session_id] = {
            "session_id": session_id,
            "agent_id": agent_id,
            "fingerprint": fp,
            "created_at": now,
            "last_activity": now,
            "is_active": True,
            "request_count": 0,
            "expected_sequence": 0,
        }
        return self._sessions[session_id]

    def verify_session(self, session_id: str, fingerprint: str = "") -> dict:
        if session_id not in self._sessions:
            return {"valid": False, "error": "SESSION_NOT_FOUND"}

        session = self._sessions[session_id]

        if not session["is_active"]:
            return {"valid": False, "error": "SESSION_TERMINATED"}

        if time.time() - session["last_activity"] > self.SESSION_TIMEOUT_SECONDS:
            session["is_active"] = False
            return {"valid": False, "error": "SESSION_EXPIRED"}

        if fingerprint and fingerprint != session["fingerprint"]:
            session["is_active"] = False
            return {"valid": False, "error": "FINGERPRINT_MISMATCH", "possible_theft": True}

        session["last_activity"] = time.time()
        session["request_count"] += 1
        session["expected_sequence"] += 1

        return {"valid": True, "session": session}

    def is_session_active(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        session = self._sessions[session_id]
        if not session["is_active"]:
            return False
        if time.time() - session["last_activity"] > self.SESSION_TIMEOUT_SECONDS:
            session["is_active"] = False
            return False
        return True

    def terminate_session(self, session_id: str):
        if session_id in self._sessions:
            self._sessions[session_id]["is_active"] = False

    def _generate_fingerprint(self, agent_id: str, session_id: str) -> str:
        timestamp = str(time.time())
        chain_hash = hashlib.sha256(f"{agent_id}:{session_id}".encode()).hexdigest()[:16]
        nonce = uuid.uuid4().hex[:16]
        raw = f"{timestamp}:{chain_hash}:{nonce}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def get_session(self, session_id: str) -> dict:
        return self._sessions.get(session_id)

    def cleanup_expired(self):
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if not s["is_active"] or now - s["last_activity"] > self.SESSION_TIMEOUT_SECONDS
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)
