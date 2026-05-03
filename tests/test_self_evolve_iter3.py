import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.capability_engine import CapabilityEngine


class TestCapabilityEngineLeastPrivilege:
    def setup_method(self):
        self.engine = CapabilityEngine()

    def test_explicit_capabilities_not_denied_by_intent(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read"],
            agent_capabilities=["lark:doc:write", "lark:doc:read"],
            task_description="生成季度报告",
        )
        assert "lark:doc:read" in result["granted_capabilities"]

    def test_intent_adds_extra_capabilities(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read"],
            agent_capabilities=["lark:doc:write", "lark:doc:read"],
            task_description="生成季度报告",
        )
        assert "lark:doc:write" in result["granted_capabilities"]

    def test_no_intent_grants_base_intersection(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read"],
            agent_capabilities=["lark:doc:write", "lark:doc:read"],
            task_description="",
        )
        assert "lark:doc:read" in result["granted_capabilities"]
        assert "lark:doc:write" not in result["granted_capabilities"]

    def test_unregistered_capability_denied(self):
        result = self.engine.compute_dynamic_least_privilege(
            user_permissions=["lark:doc:read", "lark:bitable:write"],
            agent_capabilities=["lark:doc:read"],
            task_description="",
        )
        assert "lark:doc:read" in result["granted_capabilities"]
        assert "lark:bitable:write" not in result["granted_capabilities"]

    def test_infer_capabilities(self):
        caps = self.engine.infer_capabilities_from_intent("搜索互联网信息")
        assert "web:search" in caps

    def test_delegation_permission(self):
        result = self.engine.check_delegation_permission(
            parent_capabilities=["delegate:DataAgent:read"],
            target_agent_name="DataAgent",
            requested_capabilities=["lark:bitable:read"],
        )
        assert "lark:bitable:read" in result["allowed"]
        assert result["has_delegate_read"] is True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
