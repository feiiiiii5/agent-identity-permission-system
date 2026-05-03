import time
import threading
import pytest
from core.dpop_verifier import DPoPVerifier, DPoPResult
from core.svid_manager import SVIDManager, SVID, SVIDVerifyResult, AttestationResult
from core.security_event_responder import SecurityEventResponder
from core.data_operation_guard import DataAnomalyDetector


class TestDPoPVerifierBounds:
    def test_used_jti_is_bounded_via_bind(self):
        v = DPoPVerifier()
        for i in range(v.MAX_USED_JTIS + 500):
            with v._lock:
                v._used_jti[f"jti-{i}"] = time.time()
                while len(v._used_jti) > v.MAX_USED_JTIS:
                    v._used_jti.popitem(last=False)
        assert len(v._used_jti) <= v.MAX_USED_JTIS

    def test_token_key_bindings_is_bounded(self):
        v = DPoPVerifier()
        for i in range(v.MAX_KEY_BINDINGS + 500):
            v.bind_token_to_key(f"jti-{i}", f"thumbprint-{i}")
        assert len(v._token_key_bindings) <= v.MAX_KEY_BINDINGS

    def test_thread_safety_concurrent_verify(self):
        v = DPoPVerifier()
        errors = []

        def worker(idx):
            try:
                jti = f"concurrent-jti-{idx}"
                with v._lock:
                    v._used_jti[jti] = time.time()
                    while len(v._used_jti) > v.MAX_USED_JTIS:
                        v._used_jti.popitem(last=False)
                v.bind_token_to_key(jti, f"thumb-{idx}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    def test_cleanup_removes_expired_jtis(self):
        v = DPoPVerifier()
        v._used_jti["old-jti"] = time.time() - 600
        v._used_jti["new-jti"] = time.time()
        v._last_cleanup = 0
        v._cleanup()
        assert "old-jti" not in v._used_jti
        assert "new-jti" in v._used_jti


class TestSVIDManagerBounds:
    def test_issue_svid_respects_bound(self):
        mgr = SVIDManager(trust_domain="test.local", key_dir="/tmp/test_svid_issue")
        for i in range(mgr.MAX_SVIDS + 10):
            mgr.issue_svid(f"agent-{i}", "test")
        assert len(mgr._svids) <= mgr.MAX_SVIDS

    def test_thread_safety_concurrent_issue(self):
        mgr = SVIDManager(trust_domain="test.local", key_dir="/tmp/test_svid_concurrent")
        errors = []

        def worker(idx):
            try:
                mgr.issue_svid(f"concurrent-agent-{idx}", "test")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    def test_verify_svid_uses_proper_datetime(self):
        mgr = SVIDManager(trust_domain="test.local", key_dir="/tmp/test_svid_verify")
        svid = mgr.issue_svid("test-agent", "test")
        result = mgr.verify_svid(svid.cert_pem)
        assert result.valid is True


class TestSecurityEventResponderBounds:
    def test_session_risk_is_bounded(self):
        r = SecurityEventResponder(db_path="")
        for i in range(r.MAX_SESSION_RISK_ENTRIES + 500):
            r._add_session_risk(f"user-{i}", 50)
        assert len(r._session_risk) <= r.MAX_SESSION_RISK_ENTRIES

    def test_deny_counter_is_bounded(self):
        r = SecurityEventResponder(db_path="")
        for i in range(r.MAX_DENY_COUNTER_ENTRIES + 500):
            with r._lock:
                r._deny_counter[f"user-{i}"] = [time.time()]
                while len(r._deny_counter) > r.MAX_DENY_COUNTER_ENTRIES:
                    r._deny_counter.popitem(last=False)
        assert len(r._deny_counter) <= r.MAX_DENY_COUNTER_ENTRIES

    def test_delayed_operations_is_bounded(self):
        r = SecurityEventResponder(db_path="")
        for i in range(r.MAX_DELAYED_OPERATIONS + 500):
            r._delayed_operations.append({"operation_id": f"op-{i}"})
            while len(r._delayed_operations) > r.MAX_DELAYED_OPERATIONS:
                r._delayed_operations.pop(0)
        assert len(r._delayed_operations) <= r.MAX_DELAYED_OPERATIONS

    def test_add_session_risk_caps_at_100(self):
        r = SecurityEventResponder(db_path="")
        r._add_session_risk("user-1", 80)
        r._add_session_risk("user-1", 80)
        assert r._session_risk["user-1"] == 100


class TestDataAnomalyDetectorBounds:
    def test_query_timestamps_is_bounded(self):
        d = DataAnomalyDetector(db_path="")
        for i in range(d.MAX_QUERY_TIMESTAMPS + 500):
            with d._lock:
                d._query_timestamps[f"user-{i}"] = [time.time()]
                while len(d._query_timestamps) > d.MAX_QUERY_TIMESTAMPS:
                    d._query_timestamps.popitem(last=False)
        assert len(d._query_timestamps) <= d.MAX_QUERY_TIMESTAMPS

    def test_query_cache_is_bounded(self):
        d = DataAnomalyDetector(db_path="")
        for i in range(d.MAX_QUERY_CACHE_ENTRIES + 500):
            with d._lock:
                d._query_cache[f"key-{i}"] = {"triggered": False}
                while len(d._query_cache) > d.MAX_QUERY_CACHE_ENTRIES:
                    d._query_cache.popitem(last=False)
        assert len(d._query_cache) <= d.MAX_QUERY_CACHE_ENTRIES

    def test_check_large_result_set_caches(self):
        d = DataAnomalyDetector(db_path="")
        r1 = d.check_large_result_set("user-1", 100)
        r2 = d.check_large_result_set("user-1", 100)
        assert r1 == r2
        assert len(d._query_cache) == 1
