import pytest
import sys
import os
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.audit_logger import AuditLogger, GENESIS_HASH


class TestAuditChain:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.logger = AuditLogger(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_write_log(self):
        result = self.logger.write_log(
            requesting_agent="agent_test",
            action_type="token_issue",
            decision="ALLOW",
        )
        assert "log_id" in result
        assert "log_hash" in result
        assert result["decision"] == "ALLOW"

    def test_audit_chain_integrity(self):
        for i in range(50):
            self.logger.write_log(
                requesting_agent=f"agent_{i % 3}",
                action_type="token_issue",
                decision="ALLOW" if i % 5 != 0 else "DENY",
                risk_score=float(i),
            )
        result = self.logger.verify_integrity()
        assert result["valid"] is True
        assert result["total_records"] == 50

    def test_chain_hash_linking(self):
        r1 = self.logger.write_log(
            requesting_agent="agent_a",
            action_type="token_issue",
            decision="ALLOW",
        )
        r2 = self.logger.write_log(
            requesting_agent="agent_b",
            action_type="token_delegate",
            decision="DENY",
        )
        result = self.logger.verify_integrity()
        assert result["valid"] is True
        assert result["total_records"] == 2

    def test_query_logs(self):
        self.logger.write_log(
            requesting_agent="agent_doc_001",
            action_type="token_issue",
            decision="ALLOW",
        )
        self.logger.write_log(
            requesting_agent="agent_doc_001",
            action_type="token_delegate",
            decision="DENY",
        )
        logs = self.logger.query_logs(requesting_agent="agent_doc_001")
        assert len(logs) == 2
        deny_logs = self.logger.query_logs(decision="DENY")
        assert len(deny_logs) == 1

    def test_genesis_hash(self):
        assert GENESIS_HASH == "0" * 64
        self.logger.write_log(
            requesting_agent="agent_test",
            action_type="test",
            decision="ALLOW",
        )
        import sqlite3
        conn = sqlite3.connect(self.tmp)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT prev_log_hash FROM audit_logs ORDER BY id ASC LIMIT 1").fetchone()
        conn.close()
        assert row["prev_log_hash"] == GENESIS_HASH

    def test_security_alerts(self):
        self.logger.create_security_alert(
            alert_type="PRIVILEGE_ESCALATION",
            severity="high",
            message="Agent attempted privilege escalation",
            agent_id="agent_test",
        )
        alerts = self.logger.get_security_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "PRIVILEGE_ESCALATION"

    def test_policy_decisions(self):
        self.logger.write_policy_decision(
            subject_id="agent_test",
            action="lark:doc:write",
            resource="feishu_internal",
            matched_policy="test_policy",
            effect="deny",
            reason="Test reason",
            evaluation_trace=[{"step": "check", "result": "deny"}],
            context={"hour": 20},
        )
        decisions = self.logger.get_policy_decisions()
        assert len(decisions) == 1
        assert decisions[0]["effect"] == "deny"

    def test_svid_events(self):
        self.logger.write_svid_event(
            agent_id="agent_test",
            event_type="issued",
            spiffe_id="spiffe://agentpass.local/ns/prod/agent/agent_test",
            expires_at=time.time() + 3600,
        )
        import sqlite3
        conn = sqlite3.connect(self.tmp)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM svid_events WHERE agent_id = ?", ("agent_test",)).fetchone()
        conn.close()
        assert row is not None
        assert row["event_type"] == "issued"

    def test_threat_summary(self):
        self.logger.write_log(
            requesting_agent="agent_test",
            action_type="injection_blocked",
            decision="DENY",
            injection_detected=True,
        )
        summary = self.logger.get_threat_summary()
        assert "summary" in summary
        assert "injection_events" in summary

    def test_capabilities_matrix(self):
        agents = [
            {"agent_id": "agent_a", "capabilities": ["lark:doc:read", "lark:doc:write"]},
            {"agent_id": "agent_b", "capabilities": ["lark:doc:read", "web:search"]},
        ]
        matrix = self.logger.get_capabilities_matrix(agents)
        assert "agents" in matrix
        assert "capabilities" in matrix
        assert "matrix" in matrix
        assert len(matrix["agents"]) == 2
