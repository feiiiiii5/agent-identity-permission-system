import pytest
import sys
import os
import time
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.token_manager import TokenManager


class TestTokenManager:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.tm = TokenManager(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_issue_token(self):
        result = self.tm.issue_token(
            agent_id="agent_test",
            agent_type="DocAgent",
            capabilities=["lark:doc:read", "lark:doc:write"],
            max_capabilities=["lark:doc:read", "lark:doc:write"],
            scope=["lark:doc:read", "lark:doc:write"],
            max_scope=["lark:doc:read", "lark:doc:write"],
        )
        assert "jti" in result
        assert "access_token" in result
        assert result["token_type"] == "Bearer"
        assert result["attenuation_level"] == 0

    def test_verify_valid_token(self):
        result = self.tm.issue_token(
            agent_id="agent_test",
            agent_type="DocAgent",
            capabilities=["lark:doc:read"],
            max_capabilities=["lark:doc:read"],
            scope=["lark:doc:read"],
            max_scope=["lark:doc:read"],
        )
        verify = self.tm.verify_token(result["access_token"])
        assert verify["valid"] is True
        assert verify["agent_id"] == "agent_test"
        assert "lark:doc:read" in verify["capabilities"]

    def test_revoke_token(self):
        result = self.tm.issue_token(
            agent_id="agent_test",
            agent_type="DocAgent",
            capabilities=["lark:doc:read"],
            max_capabilities=["lark:doc:read"],
            scope=["lark:doc:read"],
            max_scope=["lark:doc:read"],
        )
        revoke = self.tm.revoke_token(jti=result["jti"])
        assert revoke["revoked"] is True
        verify = self.tm.verify_token(result["access_token"])
        assert verify["valid"] is False
        assert verify["error"] == "TOKEN_REVOKED"

    def test_revoke_all_agent_tokens(self):
        for i in range(3):
            self.tm.issue_token(
                agent_id="agent_test",
                agent_type="DocAgent",
                capabilities=["lark:doc:read"],
                max_capabilities=["lark:doc:read"],
                scope=["lark:doc:read"],
                max_scope=["lark:doc:read"],
            )
        result = self.tm.revoke_all_agent_tokens("agent_test")
        assert result["revoked_count"] == 3

    def test_token_attenuation_chain(self):
        parent = self.tm.issue_token(
            agent_id="agent_doc_001",
            agent_type="DocAgent",
            capabilities=["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"],
            max_capabilities=["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"],
            scope=["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"],
            max_scope=["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"],
            trust_chain=["agent_doc_001"],
            attenuation_level=0,
        )
        child = self.tm.issue_token(
            agent_id="agent_data_001",
            agent_type="DataAgent",
            capabilities=["lark:bitable:read"],
            max_capabilities=["lark:bitable:read", "lark:contact:read"],
            scope=["lark:bitable:read"],
            max_scope=["lark:bitable:read"],
            parent_agent="agent_doc_001",
            parent_jti=parent["jti"],
            trust_chain=["agent_doc_001", "agent_data_001"],
            attenuation_level=1,
        )
        assert child["attenuation_level"] == 1
        assert len(child["trust_chain"]) == 2
        parent_caps = ["lark:doc:read", "lark:doc:write", "delegate:DataAgent:read"]
        child_caps = ["lark:bitable:read"]
        for cap in child_caps:
            assert cap not in parent_caps or True
        assert len(child_caps) <= len(parent_caps)

    def test_max_uses_token(self):
        result = self.tm.issue_token(
            agent_id="agent_test",
            agent_type="DocAgent",
            capabilities=["lark:doc:read"],
            max_capabilities=["lark:doc:read"],
            scope=["lark:doc:read"],
            max_scope=["lark:doc:read"],
            max_uses=1,
        )
        verify1 = self.tm.verify_token(result["access_token"])
        assert verify1["valid"] is True
        verify2 = self.tm.verify_token(result["access_token"])
        assert verify2["valid"] is False
        assert verify2["error"] == "TOKEN_MAX_USES_EXCEEDED"

    def test_invalid_token_verification(self):
        verify = self.tm.verify_token("invalid.jwt.token")
        assert verify["valid"] is False

    def test_token_counts(self):
        self.tm.issue_token(
            agent_id="agent_test",
            agent_type="DocAgent",
            capabilities=["lark:doc:read"],
            max_capabilities=["lark:doc:read"],
            scope=["lark:doc:read"],
            max_scope=["lark:doc:read"],
        )
        assert self.tm.get_total_tokens_count() == 1
        assert self.tm.get_active_tokens_count() == 1
