import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.privilege_detector import PrivilegeDetector


class TestPrivilegeDetector:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        import sqlite3
        conn = sqlite3.connect(self.tmp)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("""CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            baseline_capabilities TEXT DEFAULT '[]'
        )""")
        conn.execute(
            "INSERT INTO agents (agent_id, baseline_capabilities) VALUES (?, ?)",
            ("agent_search_001", '["web:search", "web:fetch"]'),
        )
        conn.commit()
        conn.close()
        self.detector = PrivilegeDetector(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_no_escalation(self):
        result = self.detector.detect_escalation(
            "agent_search_001",
            ["web:search", "web:fetch"],
            ["web:search", "web:fetch"],
        )
        assert result["is_escalation"] is False

    def test_privilege_escalation_detection(self):
        scenarios = [
            {
                "requested": ["web:search", "lark:bitable:write", "lark:contact:read"],
                "registered": ["web:search", "web:fetch"],
                "expected_escalated": ["lark:bitable:write", "lark:contact:read"],
            },
            {
                "requested": ["lark:doc:write"],
                "registered": ["lark:doc:read"],
                "expected_write_esc": ["lark:doc:write"],
            },
            {
                "requested": ["web:search", "lark:doc:read"],
                "registered": ["web:search"],
                "expected_cross_domain": ["lark"],
            },
        ]
        for s in scenarios:
            result = self.detector.detect_escalation(
                "agent_test", s["requested"], s["registered"],
            )
            assert result["is_escalation"] is True

    def test_write_escalation(self):
        result = self.detector.detect_escalation(
            "agent_test",
            ["lark:doc:write"],
            ["lark:doc:read"],
        )
        assert result["is_escalation"] is True
        assert "lark:doc:write" in result["write_escalation"]

    def test_cross_domain_escalation(self):
        result = self.detector.detect_escalation(
            "agent_test",
            ["web:search", "lark:doc:read"],
            ["web:search"],
        )
        assert result["is_escalation"] is True
        assert "lark" in result["cross_domain_escalation"]

    def test_delegation_escalation(self):
        result = self.detector.check_delegation_escalation(
            parent_capabilities=["lark:doc:read"],
            child_requested_capabilities=["lark:doc:read", "lark:doc:write"],
        )
        assert result["is_escalation"] is True
        assert "lark:doc:write" in result["exceeded_capabilities"]

    def test_baseline_escalation(self):
        result = self.detector.check_baseline_escalation(
            "agent_search_001",
            ["web:search", "web:fetch", "lark:doc:read"],
        )
        assert result["is_escalation"] is True
        assert "lark:doc:read" in result["above_baseline_capabilities"]

    def test_critical_severity(self):
        result = self.detector.detect_escalation(
            "agent_test",
            ["lark:doc:read", "lark:doc:write", "lark:bitable:read", "lark:contact:read"],
            ["web:search"],
        )
        assert result["severity"] == "critical"
