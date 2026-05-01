import pytest
import sys
import os
import time
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.auth_server import AuthServer


class TestAuthServerE2E:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.server = AuthServer(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def _register_agent(self, agent_id, name, agent_type, capabilities):
        return self.server.register_agent(
            agent_id=agent_id,
            agent_name=name,
            agent_type=agent_type,
            capabilities=capabilities,
        )

    def test_normal_delegation_flow(self):
        doc = self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"],
        )
        data = self._register_agent(
            "agent_data_001", "DataAgent", "DataAgent",
            ["lark:bitable:read", "lark:contact:read"],
        )
        assert "client_secret" in doc
        assert doc.get("spiffe_id", "").startswith("spiffe://")

        current_hour = time.localtime().tm_hour
        if 9 <= current_hour < 18:
            caps = ["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"]
        else:
            caps = ["lark:doc:read", "delegate:DataAgent:read"]

        token = self.server.issue_token(
            agent_id="agent_doc_001",
            client_secret=doc["client_secret"],
            capabilities=caps,
            delegated_user="demo_user",
        )
        assert "access_token" in token
        assert token["attenuation_level"] == 0

        delegation = self.server.delegate_token(
            parent_token=token["access_token"],
            target_agent_id="agent_data_001",
            requested_capabilities=["lark:bitable:read"],
        )
        assert "access_token" in delegation
        assert delegation["attenuation_level"] == 1

    def test_capability_mismatch_denied(self):
        search = self._register_agent(
            "agent_search_001", "SearchAgent", "SearchAgent",
            ["web:search", "web:fetch"],
        )
        data = self._register_agent(
            "agent_data_001", "DataAgent", "DataAgent",
            ["lark:bitable:read", "lark:contact:read"],
        )
        token = self.server.issue_token(
            agent_id="agent_search_001",
            client_secret=search["client_secret"],
            capabilities=["web:search", "web:fetch"],
        )
        with pytest.raises(PermissionError):
            self.server.delegate_token(
                parent_token=token["access_token"],
                target_agent_id="agent_data_001",
                requested_capabilities=["lark:bitable:read"],
            )

    def test_token_theft_detection(self):
        data = self._register_agent(
            "agent_data_001", "DataAgent", "DataAgent",
            ["lark:bitable:read"],
        )
        fake_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmYWtlIiwiYWdlbnRfaWQiOiJhZ2VudF9kYXRhXzAwMSJ9.fake"
        with pytest.raises(PermissionError):
            self.server.verify_token(
                token=fake_token,
                verifier_agent_id="agent_data_001",
                verifier_secret=data["client_secret"],
            )

    def test_privilege_escalation_blocked(self):
        search = self._register_agent(
            "agent_search_001", "SearchAgent", "SearchAgent",
            ["web:search", "web:fetch"],
        )
        with pytest.raises(PermissionError) as exc_info:
            self.server.issue_token(
                agent_id="agent_search_001",
                client_secret=search["client_secret"],
                capabilities=["web:search", "lark:bitable:write", "lark:contact:read"],
            )
        assert "PRIVILEGE_ESCALATION" in str(exc_info.value)

    def test_svid_issued_on_registration(self):
        agent = self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read"],
        )
        assert "spiffe_id" in agent
        assert "svid_expires_at" in agent
        svid_info = self.server.get_svid("agent_doc_001")
        assert "spiffe_id" in svid_info

    def test_svid_rotation(self):
        self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read"],
        )
        result = self.server.rotate_svid("agent_doc_001")
        assert "spiffe_id" in result
        assert "issued_at" in result

    def test_rate_limiting_on_token_issue(self):
        agent = self._register_agent(
            "agent_test", "TestAgent", "TestAgent",
            ["lark:doc:read"],
        )
        for _ in range(25):
            try:
                self.server.issue_token(
                    agent_id="agent_test",
                    client_secret=agent["client_secret"],
                    capabilities=["lark:doc:read"],
                )
            except PermissionError:
                break
        with pytest.raises(PermissionError) as exc_info:
            self.server.issue_token(
                agent_id="agent_test",
                client_secret=agent["client_secret"],
                capabilities=["lark:doc:read"],
            )
        assert "RATE_LIMITED" in str(exc_info.value) or "RATE" in str(exc_info.value).upper()

    def test_circuit_breaker_integration(self):
        doc = self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read", "delegate:DataAgent:read"],
        )
        data = self._register_agent(
            "agent_data_001", "DataAgent", "DataAgent",
            ["lark:bitable:read"],
        )
        states = self.server.circuit_breaker.get_all_states()
        assert isinstance(states, dict)

    def test_nonce_flow(self):
        agent = self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read"],
        )
        nonce = self.server.nonce_manager.issue_nonce("agent_doc_001")
        assert len(nonce) > 0
        result = self.server.nonce_manager.consume_nonce(nonce, "agent_doc_001")
        assert result.valid is True

    def test_health_check(self):
        health = self.server.health()
        assert health["status"] == "healthy"

    def test_delegation_graph(self):
        self._register_agent(
            "agent_doc_001", "DocAgent", "DocAgent",
            ["lark:doc:read"],
        )
        self._register_agent(
            "agent_data_001", "DataAgent", "DataAgent",
            ["lark:bitable:read"],
        )
        graph = self.server.get_delegation_graph()
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) == 2
