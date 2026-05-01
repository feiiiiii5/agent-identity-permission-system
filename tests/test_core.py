import pytest
import sys
import os
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPolicyEngine:
    def setup_method(self):
        from core.policy_engine import PolicyEngine
        self.engine = PolicyEngine("policies/")

    def test_evaluate_no_policies_default_deny(self):
        from core.policy_engine import PolicyEngine
        e = PolicyEngine("/nonexistent/")
        result = e.evaluate("agent_test", "lark:doc:read", "feishu_internal")
        assert result.allowed is False

    def test_policy_reload(self):
        result = self.engine.reload_policies()
        assert result["reloaded"] is True

    def test_get_all_policies(self):
        policies = self.engine.get_all_policies()
        assert isinstance(policies, list)


class TestSVIDManager:
    def setup_method(self):
        from core.svid_manager import SVIDManager
        self.manager = SVIDManager(trust_domain="test.local")

    def test_issue_svid(self):
        svid = self.manager.issue_svid("agent_test", "DocAgent")
        assert svid.spiffe_id == "spiffe://test.local/ns/prod/agent/agent_test"
        assert svid.agent_id == "agent_test"
        assert svid.cert_pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_verify_svid(self):
        svid = self.manager.issue_svid("agent_test", "DocAgent")
        result = self.manager.verify_svid(svid.cert_pem)
        assert result.valid is True
        assert result.spiffe_id == svid.spiffe_id

    def test_rotate_svid(self):
        self.manager.issue_svid("agent_test", "DocAgent")
        new_svid = self.manager.rotate_svid("agent_test")
        assert new_svid.spiffe_id == "spiffe://test.local/ns/prod/agent/agent_test"

    def test_trust_bundle(self):
        bundle = self.manager.get_trust_bundle()
        assert bundle["trust_domain"] == "test.local"
        assert len(bundle["x509_authorities"]) > 0


class TestDPoPVerifier:
    def setup_method(self):
        from core.dpop_verifier import DPoPVerifier
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        self.verifier = DPoPVerifier()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self.public_pem = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def test_create_and_verify_proof(self):
        proof = self.verifier.create_dpop_proof(self.private_pem, "POST", "https://api.example.com/data")
        result = self.verifier.verify_dpop_proof(proof, self.public_pem, "POST", "https://api.example.com/data")
        assert result.valid is True

    def test_replay_detection(self):
        proof = self.verifier.create_dpop_proof(self.private_pem, "POST", "https://api.example.com/data")
        self.verifier.verify_dpop_proof(proof, self.public_pem, "POST", "https://api.example.com/data")
        result = self.verifier.verify_dpop_proof(proof, self.public_pem, "POST", "https://api.example.com/data")
        assert result.valid is False
        assert result.error_code == "DPOP_REPLAY_DETECTED"

    def test_htm_mismatch(self):
        proof = self.verifier.create_dpop_proof(self.private_pem, "POST", "https://api.example.com/data")
        result = self.verifier.verify_dpop_proof(proof, self.public_pem, "GET", "https://api.example.com/data")
        assert result.valid is False
        assert result.error_code == "DPOP_HTM_MISMATCH"


class TestRateLimiter:
    def setup_method(self):
        from core.rate_limiter import SlidingWindowRateLimiter
        self.tmp = tempfile.mktemp(suffix=".db")
        self.limiter = SlidingWindowRateLimiter(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_within_limit(self):
        result = self.limiter.check_rate_limit("agent_test", "token_issue")
        assert result.allowed is True

    def test_exceed_limit(self):
        for _ in range(25):
            self.limiter.record_request("agent_test", "token_issue")
        result = self.limiter.check_rate_limit("agent_test", "token_issue")
        assert result.allowed is False

    def test_agent_stats(self):
        self.limiter.record_request("agent_test", "token_issue")
        stats = self.limiter.get_agent_rate_stats("agent_test")
        assert "token_issue" in stats


class TestCircuitBreaker:
    def setup_method(self):
        from core.circuit_breaker import CircuitBreaker
        self.cb = CircuitBreaker()
        self.cb.failure_threshold = 3

    def test_closed_state(self):
        result = self.cb.can_proceed("agent_test")
        assert result["allowed"] is True
        assert result["state"] == "CLOSED"

    def test_opens_after_failures(self):
        for _ in range(3):
            self.cb.record_failure("agent_test", "timeout")
        result = self.cb.can_proceed("agent_test")
        assert result["state"] == "OPEN"
        assert result["allowed"] is False

    def test_reset(self):
        for _ in range(3):
            self.cb.record_failure("agent_test", "timeout")
        self.cb.reset("agent_test")
        result = self.cb.can_proceed("agent_test")
        assert result["state"] == "CLOSED"


class TestNonceManager:
    def setup_method(self):
        from core.nonce_manager import NonceManager
        NonceManager.reset_instance()
        self.tmp = tempfile.mktemp(suffix=".db")
        self.nm = NonceManager(self.tmp)

    def teardown_method(self):
        from core.nonce_manager import NonceManager
        NonceManager.reset_instance()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_issue_and_consume(self):
        nonce = self.nm.issue_nonce("agent_test")
        result = self.nm.consume_nonce(nonce, "agent_test")
        assert result.valid is True

    def test_double_consume(self):
        nonce = self.nm.issue_nonce("agent_test")
        self.nm.consume_nonce(nonce, "agent_test")
        result = self.nm.consume_nonce(nonce, "agent_test")
        assert result.valid is False
        assert result.error_code == "ERR_NONCE_ALREADY_USED"

    def test_agent_mismatch(self):
        nonce = self.nm.issue_nonce("agent_test")
        result = self.nm.consume_nonce(nonce, "agent_other")
        assert result.valid is False
        assert result.error_code == "ERR_NONCE_AGENT_MISMATCH"
