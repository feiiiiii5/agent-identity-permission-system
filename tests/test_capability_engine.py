import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.capability_engine import CapabilityEngine


class TestCapabilityEngine:
    def setup_method(self):
        self.engine = CapabilityEngine()

    def test_infer_capabilities_from_intent(self):
        caps = self.engine.infer_capabilities_from_intent("生成季度销售报告")
        assert "lark:doc:write" in caps
        assert "lark:bitable:read" in caps

    def test_infer_capabilities_empty(self):
        caps = self.engine.infer_capabilities_from_intent("")
        assert caps == []

    def test_compute_dynamic_least_privilege(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read", "lark:doc:write", "lark:bitable:read"],
            agent_capabilities=["lark:doc:read", "lark:doc:write", "lark:bitable:read"],
            task_description="生成销售报告",
        )
        assert "lark:doc:write" in result["granted_capabilities"]
        assert "lark:bitable:read" in result["granted_capabilities"]

    def test_check_delegation_permission_allowed(self):
        result = self.engine.check_delegation_permission(
            parent_capabilities=["delegate:DataAgent:read"],
            target_agent_name="DataAgent",
            requested_capabilities=["lark:bitable:read"],
        )
        assert "lark:bitable:read" in result["allowed"]
        assert result["has_delegate_read"] is True

    def test_check_delegation_permission_denied(self):
        result = self.engine.check_delegation_permission(
            parent_capabilities=["lark:doc:read"],
            target_agent_name="DataAgent",
            requested_capabilities=["lark:bitable:read"],
        )
        assert result["has_delegate_read"] is False
        assert result["has_delegate_write"] is False

    def test_delegation_map_search_agent(self):
        result = self.engine.check_delegation_permission(
            parent_capabilities=["delegate:SearchAgent:read"],
            target_agent_name="SearchAgent",
            requested_capabilities=["web:search"],
        )
        assert "web:search" in result["allowed"]

    def test_least_privilege_no_intent(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read"],
            agent_capabilities=["lark:doc:read", "lark:doc:write"],
            task_description="",
        )
        assert "lark:doc:read" in result["granted_capabilities"]
