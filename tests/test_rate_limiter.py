import pytest
import sys
import os
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rate_limiter import SlidingWindowRateLimiter


class TestRateLimiter:
    def setup_method(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        self.limiter = SlidingWindowRateLimiter(self.tmp)

    def teardown_method(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_within_limit(self):
        result = self.limiter.check_rate_limit("agent_test", "token_issue")
        assert result.allowed is True
        assert result.remaining > 0

    def test_exceed_limit(self):
        for _ in range(25):
            self.limiter.record_request("agent_test", "token_issue")
        result = self.limiter.check_rate_limit("agent_test", "token_issue")
        assert result.allowed is False
        assert result.retry_after > 0

    def test_different_actions_independent(self):
        for _ in range(20):
            self.limiter.record_request("agent_test", "token_issue")
        issue_result = self.limiter.check_rate_limit("agent_test", "token_issue")
        verify_result = self.limiter.check_rate_limit("agent_test", "token_verify")
        assert issue_result.allowed is False
        assert verify_result.allowed is True

    def test_agent_stats(self):
        self.limiter.record_request("agent_test", "token_issue")
        self.limiter.record_request("agent_test", "token_issue")
        stats = self.limiter.get_agent_rate_stats("agent_test")
        assert "token_issue" in stats
        assert stats["token_issue"]["current_count"] == 2

    def test_unknown_action_allowed(self):
        result = self.limiter.check_rate_limit("agent_test", "unknown_action")
        assert result.allowed is True

    def test_rate_limit_result_fields(self):
        result = self.limiter.check_rate_limit("agent_test", "token_issue")
        assert hasattr(result, "allowed")
        assert hasattr(result, "current_count")
        assert hasattr(result, "limit")
        assert hasattr(result, "window_seconds")
        assert hasattr(result, "remaining")

    def test_record_and_check_consistency(self):
        self.limiter.record_request("agent_test", "token_delegate")
        result = self.limiter.check_rate_limit("agent_test", "token_delegate")
        assert result.current_count == 1
        assert result.allowed is True

    def test_sliding_window_expiry(self):
        for _ in range(20):
            self.limiter.record_request("agent_test", "feishu_api")
        result = self.limiter.check_rate_limit("agent_test", "feishu_api")
        assert result.allowed is False
