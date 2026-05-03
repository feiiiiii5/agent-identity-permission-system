import time
import uuid
import hashlib
import threading
import jwt as pyjwt
from dataclasses import dataclass
from typing import Optional
from collections import OrderedDict
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding


@dataclass
class DPoPResult:
    valid: bool
    agent_id: str = ""
    jti: str = ""
    error_code: str = ""
    error_message: str = ""


class DPoPVerifier:

    MAX_USED_JTIS = 10000
    MAX_KEY_BINDINGS = 5000

    def __init__(self):
        self._used_jti = OrderedDict()
        self._token_key_bindings = OrderedDict()
        self._cleanup_interval = 300
        self._last_cleanup = time.time()
        self._lock = threading.Lock()

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        expired = [jti for jti, ts in self._used_jti.items() if now - ts > 300]
        for jti in expired:
            del self._used_jti[jti]
        self._last_cleanup = now

    def create_dpop_proof(self, private_key_pem: str, htm: str, htu: str, access_token: str = None) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
        )

        jti = uuid.uuid4().hex
        now = time.time()

        payload = {
            "jti": jti,
            "htm": htm,
            "htu": htu,
            "iat": int(now),
        }

        if access_token:
            ath = hashlib.sha256(access_token.encode()).hexdigest()
            payload["ath"] = ath

        proof = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"typ": "dpop+jwt"})
        return proof

    def verify_dpop_proof(
        self,
        dpop_proof_jwt: str,
        public_key_pem: str,
        htm: str,
        htu: str,
        access_token: str = None,
        max_age_seconds: int = 60,
    ) -> DPoPResult:
        with self._lock:
            self._cleanup()

        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            return DPoPResult(valid=False, error_code="DPOP_INVALID_KEY", error_message=str(e))

        try:
            header = pyjwt.get_unverified_header(dpop_proof_jwt)
            if header.get("typ") != "dpop+jwt":
                return DPoPResult(valid=False, error_code="DPOP_INVALID_TYPE",
                                  error_message="Proof JWT typ must be dpop+jwt")
        except Exception as e:
            return DPoPResult(valid=False, error_code="DPOP_MALFORMED", error_message=str(e))

        try:
            payload = pyjwt.decode(dpop_proof_jwt, public_key, algorithms=["RS256"],
                                   options={"verify_exp": False})
        except pyjwt.InvalidTokenError as e:
            return DPoPResult(valid=False, error_code="DPOP_INVALID_SIGNATURE", error_message=str(e))

        jti = payload.get("jti", "")
        if not jti:
            return DPoPResult(valid=False, error_code="DPOP_MISSING_JTI",
                              error_message="Proof must contain jti")

        with self._lock:
            if jti in self._used_jti:
                return DPoPResult(valid=False, error_code="DPOP_REPLAY_DETECTED",
                                  error_message=f"jti {jti[:8]}... already used")

        proof_htm = payload.get("htm", "")
        if proof_htm.upper() != htm.upper():
            return DPoPResult(valid=False, error_code="DPOP_HTM_MISMATCH",
                              error_message=f"htm mismatch: expected {htm}, got {proof_htm}")

        proof_htu = payload.get("htu", "")
        if proof_htu != htu:
            return DPoPResult(valid=False, error_code="DPOP_HTU_MISMATCH",
                              error_message=f"htu mismatch: expected {htu}, got {proof_htu}")

        iat = payload.get("iat", 0)
        if time.time() - iat > max_age_seconds:
            return DPoPResult(valid=False, error_code="DPOP_EXPIRED",
                              error_message=f"Proof too old: {time.time() - iat:.0f}s")

        if access_token:
            expected_ath = hashlib.sha256(access_token.encode()).hexdigest()
            actual_ath = payload.get("ath", "")
            if actual_ath != expected_ath:
                return DPoPResult(valid=False, error_code="DPOP_ATH_MISMATCH",
                                  error_message="Token hash mismatch")

        with self._lock:
            self._used_jti[jti] = time.time()
            while len(self._used_jti) > self.MAX_USED_JTIS:
                self._used_jti.popitem(last=False)

        return DPoPResult(valid=True, jti=jti)

    def bind_token_to_key(self, jti: str, public_key_thumbprint: str) -> bool:
        with self._lock:
            self._token_key_bindings[jti] = public_key_thumbprint
            while len(self._token_key_bindings) > self.MAX_KEY_BINDINGS:
                self._token_key_bindings.popitem(last=False)
        return True

    def verify_token_binding(self, jti: str, public_key_pem: str) -> bool:
        thumbprint = hashlib.sha256(public_key_pem.encode()).hexdigest()[:32]
        with self._lock:
            bound = self._token_key_bindings.get(jti)
        if not bound:
            return True
        return bound == thumbprint
