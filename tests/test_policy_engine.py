import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.policy_engine import PolicyEngine


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine("policies/")

    def test_default_allow_no_policies(self):
        engine = PolicyEngine("/nonexistent_dir/")
        result = engine.evaluate("agent_test", "lark:doc:read", "feishu_internal")
        assert result.allowed is True
        assert result.matched_policy == "default_allow"

    def test_policy_engine_deny_override_allow(self):
        result = self.engine.evaluate(
            subject_id="agent_search_001",
            action="lark:bitable:read",
            resource="feishu_internal",
            context={"hour": 10, "risk_score": 0},
        )
        assert result.allowed is False
        assert "search_agent_no_feishu" in result.matched_policy or \
               "data_agent_block_external_delegation" in result.matched_policy

    def test_time_range_outside_condition(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:doc:write",
            resource="*",
            context={"hour": 20, "risk_score": 0},
        )
        assert result.allowed is False
        assert "doc_agent_read_only_after_hours" in result.matched_policy

    def test_time_range_inside_allowed(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:doc:write",
            resource="*",
            context={"hour": 10, "risk_score": 0},
        )
        assert result.allowed is True

    def test_high_risk_readonly(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:doc:write",
            resource="*",
            context={"hour": 10, "risk_score": 80},
        )
        assert result.allowed is False
        assert "high_risk_readonly" in result.matched_policy

    def test_missing_delegated_user(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:contact:read",
            resource="*",
            context={"hour": 10, "risk_score": 0, "delegated_user": ""},
        )
        assert result.allowed is False
        assert "require_delegated_user_for_sensitive" in result.matched_policy

    def test_with_delegated_user(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:contact:read",
            resource="*",
            context={"hour": 10, "risk_score": 0, "delegated_user": "user1"},
        )
        assert result.allowed is True

    def test_wildcard_matching(self):
        result = self.engine.evaluate(
            subject_id="agent_search_001",
            action="lark:doc:read",
            resource="feishu_internal",
            context={"hour": 10, "risk_score": 0},
        )
        assert result.allowed is False

    def test_evaluation_trace(self):
        result = self.engine.evaluate(
            subject_id="agent_doc_001",
            action="lark:doc:write",
            resource="*",
            context={"hour": 20, "risk_score": 0},
        )
        assert len(result.evaluation_trace) > 0

    def test_reload_policies(self):
        result = self.engine.reload_policies()
        assert result["reloaded"] is True
        assert result["policy_count"] >= 0

    def test_get_all_policies(self):
        policies = self.engine.get_all_policies()
        assert isinstance(policies, list)
        if policies:
            assert "name" in policies[0]
            assert "effect" in policies[0]
