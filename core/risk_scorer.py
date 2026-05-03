import json
import math
import time
import logging
import sqlite3

from core.db_pool import get_pool

logger = logging.getLogger(__name__)


class RiskScorer:

    RISK_THRESHOLD_DOWNGRADE = 70
    RISK_THRESHOLD_FREEZE = 90
    RISK_THRESHOLD_REVOKE = 80

    DEFAULT_WEIGHTS = {
        "request_frequency": 0.18,
        "chain_depth": 0.15,
        "time_period": 0.12,
        "capability_combo": 0.25,
        "history_violations": 0.18,
        "behavior_anomaly": 0.12,
    }

    CAPABILITY_RISK_MAP = {
        "lark:contact:read": 0.8,
        "lark:contact:write": 0.95,
        "lark:bitable:read": 0.5,
        "lark:bitable:write": 0.85,
        "lark:doc:write": 0.6,
        "lark:doc:read": 0.3,
        "web:search": 0.2,
        "web:fetch": 0.3,
        "delegate:DataAgent:read": 0.7,
        "delegate:DataAgent:write": 0.9,
        "delegate:SearchAgent:read": 0.4,
    }

    DANGEROUS_COMBOS = [
        ({"lark:contact:read", "web:search"}, 0.3),
        ({"lark:bitable:read", "web:fetch"}, 0.25),
        ({"lark:contact:read", "lark:bitable:write"}, 0.35),
        ({"lark:bitable:read", "lark:bitable:write"}, 0.2),
    ]

    DIMENSIONS = [
        "request_frequency",
        "chain_depth",
        "time_period",
        "capability_combo",
        "history_violations",
        "behavior_anomaly",
    ]

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._weights = dict(self.DEFAULT_WEIGHTS)
        self._behavior_analyzer = None
        self._injection_scanner = None

    def _get_behavior_analyzer(self):
        if self._behavior_analyzer is None:
            from core.behavior_analyzer import BehaviorAnalyzer
            self._behavior_analyzer = BehaviorAnalyzer(self.db_path)
        return self._behavior_analyzer

    def _get_injection_scanner(self):
        if self._injection_scanner is None:
            from core.injection_scanner import InjectionScanner
            self._injection_scanner = InjectionScanner()
        return self._injection_scanner

    def set_weights(self, weights: dict):
        for k, v in weights.items():
            if k in self._weights:
                self._weights[k] = float(v)
        total = sum(self._weights.values())
        if total > 0:
            for k in self._weights:
                self._weights[k] /= total

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        self._pool.return_connection(conn)

    def _compute_freq_risk(self, agent_id: str, conn) -> float:
        now = time.time()
        one_hour_ago = now - 3600
        freq_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE requesting_agent = ? AND timestamp > ?",
            (agent_id, one_hour_ago),
        ).fetchone()
        request_count = freq_row["cnt"] if freq_row else 0
        return min(1.0, request_count / 50.0)

    def _compute_depth_risk(self, agent_id: str, conn) -> float:
        depth_row = conn.execute(
            "SELECT MAX(attenuation_level) as max_depth FROM tokens WHERE agent_id = ? AND is_revoked = 0",
            (agent_id,),
        ).fetchone()
        max_depth = depth_row["max_depth"] if depth_row and depth_row["max_depth"] is not None else 0
        return min(1.0, max_depth * 0.25)

    def _compute_time_risk(self) -> float:
        hour = time.localtime().tm_hour
        if hour < 6 or hour > 22:
            return 0.7
        elif hour < 8 or hour > 20:
            return 0.3
        return 0.1

    def _compute_capability_risk(self, capabilities: list) -> float:
        if not capabilities:
            return 0.0
        cap_set = set(capabilities)
        base_risk = sum(self.CAPABILITY_RISK_MAP.get(c, 0.1) for c in capabilities) / len(capabilities)
        write_caps = [c for c in capabilities if ":write" in c or ":delete" in c]
        sensitive_caps = [c for c in capabilities if "contact" in c or "admin" in c]
        combo_bonus = 0.0
        for dangerous_set, bonus in self.DANGEROUS_COMBOS:
            if dangerous_set.issubset(cap_set):
                combo_bonus += bonus
        return min(1.0, base_risk * 0.5 + len(write_caps) * 0.12 + len(sensitive_caps) * 0.2 + combo_bonus)

    def _compute_history_risk(self, agent_id: str, conn) -> float:
        now = time.time()
        deny_row = conn.execute(
            "SELECT COUNT(*) as cnt, MAX(timestamp) as last_deny FROM audit_logs WHERE requesting_agent = ? AND decision = 'DENY'",
            (agent_id,),
        ).fetchone()
        deny_count = deny_row["cnt"] if deny_row else 0
        inj_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_logs WHERE requesting_agent = ? AND injection_detected = 1",
            (agent_id,),
        ).fetchone()
        inj_count = inj_row["cnt"] if inj_row else 0
        base_risk = deny_count * 0.1 + inj_count * 0.25
        last_deny = deny_row["last_deny"] if deny_row and deny_row["last_deny"] else 0
        if last_deny > 0:
            decay_hours = (now - last_deny) / 3600
            decay_factor = math.exp(-decay_hours / 168)
            base_risk *= (0.5 + 0.5 * decay_factor)
        return min(1.0, base_risk)

    def _compute_behavior_risk(self, agent_id: str, capabilities: list, delegation_depth: int) -> float:
        try:
            ba = self._get_behavior_analyzer()
            anomaly = ba.check_anomaly(agent_id, capabilities, delegation_depth)
            if anomaly.get("is_anomaly"):
                if anomaly.get("anomaly_level") == "critical":
                    return 0.9
                return 0.6
        except Exception as e:
            logger.warning("Behavior anomaly check failed: %s", e)
            pass
        return 0.0

    def compute_risk_score(self, agent_id: str, capabilities: list, delegation_depth: int = 0,
                           user_input: str = "", conversation_history: list = None,
                           time_since_last_action: float = None) -> dict:
        conn = self._get_conn()

        agent_row = conn.execute(
            "SELECT trust_score FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        trust_score = agent_row["trust_score"] if agent_row else 50.0

        freq_risk = self._compute_freq_risk(agent_id, conn)
        depth_risk = self._compute_depth_risk(agent_id, conn)
        time_risk = self._compute_time_risk()
        combo_risk = self._compute_capability_risk(capabilities)
        history_risk = self._compute_history_risk(agent_id, conn)
        behavior_risk = self._compute_behavior_risk(agent_id, capabilities, delegation_depth)

        self._return_conn(conn)

        progressive_bonus = self._detect_progressive_attack(agent_id, conversation_history)

        rapid_action_bonus = 0.0
        if time_since_last_action is not None and time_since_last_action < 1.0:
            rapid_action_bonus = 0.15

        input_risk_bonus = 0.0
        if user_input:
            input_risk_bonus = self._compute_input_risk_bonus(user_input)

        risk_score = (
            freq_risk * self._weights["request_frequency"]
            + depth_risk * self._weights["chain_depth"]
            + time_risk * self._weights["time_period"]
            + combo_risk * self._weights["capability_combo"]
            + history_risk * self._weights["history_violations"]
            + behavior_risk * self._weights["behavior_anomaly"]
        ) * 100

        risk_score += progressive_bonus + rapid_action_bonus * 100 + input_risk_bonus * 100

        trust_modifier = max(0, (100 - trust_score) / 200)
        risk_score = risk_score * (1 + trust_modifier)
        risk_score = round(min(risk_score, 100.0), 1)

        if risk_score >= self.RISK_THRESHOLD_FREEZE:
            action_taken = "freeze"
        elif risk_score >= self.RISK_THRESHOLD_REVOKE:
            action_taken = "revoke_tokens"
        elif risk_score >= self.RISK_THRESHOLD_DOWNGRADE:
            action_taken = "downgrade"
        elif risk_score >= 40:
            action_taken = "monitor"
        else:
            action_taken = "normal"

        return {
            "risk_score": risk_score,
            "action_taken": action_taken,
            "dimensions": {
                "request_frequency": round(freq_risk * 100, 1),
                "chain_depth": round(depth_risk * 100, 1),
                "time_period": round(time_risk * 100, 1),
                "capability_combo": round(combo_risk * 100, 1),
                "history_violations": round(history_risk * 100, 1),
                "behavior_anomaly": round(behavior_risk * 100, 1),
            },
            "agent_id": agent_id,
            "trust_score": trust_score,
            "thresholds": {
                "downgrade": self.RISK_THRESHOLD_DOWNGRADE,
                "freeze": self.RISK_THRESHOLD_FREEZE,
                "revoke": self.RISK_THRESHOLD_REVOKE,
            },
            "weights": self._weights,
            "progressive_attack_bonus": progressive_bonus,
            "rapid_action_bonus": rapid_action_bonus * 100,
            "input_risk_bonus": input_risk_bonus * 100,
        }

    def _detect_progressive_attack(self, agent_id: str, conversation_history: list = None, conn=None) -> float:
        if not conversation_history or len(conversation_history) < 3:
            return 0.0
        injection_count = 0
        scanner = self._get_injection_scanner()
        for msg in conversation_history[-3:]:
            if isinstance(msg, dict) and msg.get("injection_detected"):
                injection_count += 1
            elif isinstance(msg, str):
                try:
                    result = scanner.scan(msg)
                    if result.get("is_injection"):
                        injection_count += 1
                except Exception as e:
                    logger.debug("Injection scan in risk scoring failed: %s", e)
        if injection_count >= 2:
            return 30.0
        return 0.0

    def _compute_input_risk_bonus(self, user_input: str) -> float:
        bonus = 0.0
        high_risk_keywords = ["删除", "drop", "admin", "root", "管理员", "绕过", "bypass", "忽略指令"]
        lower = user_input.lower()
        for kw in high_risk_keywords:
            if kw in lower:
                bonus += 0.05
        if len(user_input) > 500:
            bonus += 0.08
        return min(bonus, 0.3)

    def update_trust_score(self, agent_id: str, delta: float) -> float:
        conn = self._get_conn()
        conn.execute(
            "UPDATE agents SET trust_score = MAX(0, MIN(100, trust_score + ?)) WHERE agent_id = ?",
            (delta, agent_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT trust_score FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        self._return_conn(conn)
        return row["trust_score"] if row else 0.0
