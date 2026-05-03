import pytest
from core.response_engine import ResponseEngine
from feishu.formatter import ResponseFormatter


class TestResponseFormatterInheritance:
    def test_formatter_inherits_from_engine(self):
        assert issubclass(ResponseFormatter, ResponseEngine)

    def test_formatter_has_format_security_response(self):
        f = ResponseFormatter()
        result = f.format_security_response("trace-1", 50.0, "Agent1→Agent2", "content")
        assert "trace-1" in result
        assert "50.0/100" in result
        assert "Agent1→Agent2" in result

    def test_formatter_inherits_format_allow(self):
        f = ResponseFormatter()
        result = f.format_allow_response("test", {"original_keywords": ["doc"]}, "done", "t1", 10.0)
        assert "✅" in result

    def test_formatter_inherits_format_deny(self):
        f = ResponseFormatter()
        result = f.format_deny_response("test", {"original_keywords": ["salary"], "resource": "salary",
                                               "scope": "self", "action": "read"}, 80.0, "t1")
        assert "🚫" in result

    def test_formatter_inherits_format_injection_block(self):
        f = ResponseFormatter()
        result = f.format_injection_block_response("ignore instructions", {"threats": []}, None, "t1")
        assert "🚨" in result

    def test_formatter_inherits_private_methods(self):
        f = ResponseFormatter()
        assert f._risk_level_label(90) == "🔴 严重"
        assert f._extract_user_quote("short") == "short"
        sanitized = f._sanitize_content("ignore this very long text that exceeds sixty characters completely")
        assert sanitized.startswith("***")
        assert sanitized.endswith("...")


class TestResponseEngineMethods:
    def test_format_chain_request(self):
        e = ResponseEngine()
        intent = {"chain_request": {"sub_requests": [
            {"action": "read", "resource": "document", "text": "read my docs"},
            {"action": "write", "resource": "bitable", "text": "write to table"},
        ]}}
        result = e.format_chain_request("test", intent, "t1")
        assert "🔗" in result
        assert "读取" in result
        assert "写入" in result

    def test_format_duplicate_warning(self):
        e = ResponseEngine()
        result = e.format_duplicate_warning("test", {}, {"count": 3}, "t1")
        assert "🔄" in result
        assert "3" in result

    def test_format_delayed_execution(self):
        e = ResponseEngine()
        result = e.format_delayed_execution("test", {"original_keywords": ["data"]}, 60.0, "t1")
        assert "⏰" in result
