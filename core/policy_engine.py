import os
import re
import time
import fnmatch
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyDecision:
    allowed: bool
    matched_policy: str = ""
    reason: str = ""
    applicable_policies: list = field(default_factory=list)
    evaluation_trace: list = field(default_factory=list)


class PolicyEngine:

    def __init__(self, policies_dir: str = "policies/"):
        self.policies_dir = policies_dir
        self._policies = []
        self._load_policies()

    def _load_policies(self):
        self._policies = []
        if not os.path.isdir(self.policies_dir):
            return
        try:
            import yaml
        except ImportError:
            return
        for fname in sorted(os.listdir(self.policies_dir)):
            if fname.endswith((".yaml", ".yml")):
                fpath = os.path.join(self.policies_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if data and "policies" in data:
                        for p in data["policies"]:
                            p["_source_file"] = fname
                            if "priority" not in p:
                                p["priority"] = 0
                            if "conditions" not in p:
                                p["conditions"] = {}
                            self._policies.append(p)
                except Exception:
                    pass
        self._policies.sort(key=lambda x: -x.get("priority", 0))

    def reload_policies(self):
        self._load_policies()
        return {"reloaded": True, "policy_count": len(self._policies)}

    def get_all_policies(self) -> list:
        return [
            {
                "name": p.get("name", ""),
                "description": p.get("description", ""),
                "subjects": p.get("subjects", []),
                "actions": p.get("actions", []),
                "resources": p.get("resources", []),
                "effect": p.get("effect", "allow"),
                "conditions": p.get("conditions", {}),
                "priority": p.get("priority", 0),
                "source_file": p.get("_source_file", ""),
            }
            for p in self._policies
        ]

    def _match_wildcard(self, pattern: str, value: str) -> bool:
        if pattern == "*":
            return True
        if "*" in pattern:
            regex = fnmatch.translate(pattern)
            return bool(re.match(regex, value))
        return pattern == value

    def _check_conditions(self, conditions: dict, context: dict, trace: list) -> bool:
        if not conditions:
            trace.append({"step": "check_conditions", "result": "pass", "reason": "no conditions"})
            return True

        for cond_key, cond_val in conditions.items():
            if cond_key == "time_range":
                hour = context.get("hour", time.localtime().tm_hour)
                from_h, to_h = self._parse_time_range(cond_val)
                in_range = from_h <= hour < to_h
                if not in_range:
                    trace.append({"step": "condition_time_range", "result": "fail",
                                  "detail": f"hour={hour} not in {from_h}-{to_h}"})
                    return False
                trace.append({"step": "condition_time_range", "result": "pass",
                              "detail": f"hour={hour} in {from_h}-{to_h}"})

            elif cond_key == "time_range_outside":
                hour = context.get("hour", time.localtime().tm_hour)
                from_h, to_h = self._parse_time_range(cond_val)
                in_range = from_h <= hour < to_h
                if in_range:
                    trace.append({"step": "condition_time_range_outside", "result": "fail",
                                  "detail": f"hour={hour} is inside {from_h}-{to_h}"})
                    return False
                trace.append({"step": "condition_time_range_outside", "result": "pass",
                              "detail": f"hour={hour} is outside {from_h}-{to_h}"})

            elif cond_key == "min_attenuation_level":
                att = context.get("attenuation_level", 0)
                if att < cond_val:
                    trace.append({"step": "condition_min_attenuation_level", "result": "fail",
                                  "detail": f"attenuation_level={att} < {cond_val}"})
                    return False
                trace.append({"step": "condition_min_attenuation_level", "result": "pass",
                              "detail": f"attenuation_level={att} >= {cond_val}"})

            elif cond_key == "min_risk_score":
                rs = context.get("risk_score", 0)
                if rs < cond_val:
                    trace.append({"step": "condition_min_risk_score", "result": "fail",
                                  "detail": f"risk_score={rs} < {cond_val}"})
                    return False
                trace.append({"step": "condition_min_risk_score", "result": "pass",
                              "detail": f"risk_score={rs} >= {cond_val}"})

            elif cond_key == "required_trust_score":
                ts = context.get("trust_score", 0)
                if ts < cond_val:
                    trace.append({"step": "condition_required_trust_score", "result": "fail",
                                  "detail": f"trust_score={ts} < {cond_val}"})
                    return False
                trace.append({"step": "condition_required_trust_score", "result": "pass",
                              "detail": f"trust_score={ts} >= {cond_val}"})

            elif cond_key == "deny_if_injection_history":
                has_inj = context.get("injection_history", False)
                if cond_val and has_inj:
                    trace.append({"step": "condition_deny_if_injection_history", "result": "fail",
                                  "detail": "agent has injection history"})
                    return False
                trace.append({"step": "condition_deny_if_injection_history", "result": "pass"})

            elif cond_key == "required_delegated_user":
                du = context.get("delegated_user", "")
                if cond_val and not du:
                    trace.append({"step": "condition_required_delegated_user", "result": "fail",
                                  "detail": "no delegated_user in context"})
                    return False
                trace.append({"step": "condition_required_delegated_user", "result": "pass"})

            elif cond_key == "missing_delegated_user":
                du = context.get("delegated_user", "")
                if cond_val and not du:
                    trace.append({"step": "condition_missing_delegated_user", "result": "match",
                                  "detail": "delegated_user is missing"})
                    return True
                trace.append({"step": "condition_missing_delegated_user", "result": "no_match",
                              "detail": "delegated_user is present"})
                return False

            elif cond_key == "max_daily_calls":
                daily_calls = context.get("daily_calls", 0)
                if daily_calls >= cond_val:
                    trace.append({"step": "condition_max_daily_calls", "result": "fail",
                                  "detail": f"daily_calls={daily_calls} >= {cond_val}"})
                    return False
                trace.append({"step": "condition_max_daily_calls", "result": "pass",
                              "detail": f"daily_calls={daily_calls} < {cond_val}"})

        trace.append({"step": "check_conditions", "result": "pass"})
        return True

    def _parse_time_range(self, tr: dict) -> tuple:
        from_str = tr.get("from", "00:00")
        to_str = tr.get("to", "23:59")
        from_parts = from_str.split(":")
        to_parts = to_str.split(":")
        from_h = int(from_parts[0])
        to_h = int(to_parts[0])
        return from_h, to_h

    def evaluate(self, subject_id: str, action: str, resource: str, context: dict = None) -> PolicyDecision:
        if context is None:
            context = {}

        trace = []
        applicable = []
        matched_deny = None
        matched_allow = None

        for policy in self._policies:
            pname = policy.get("name", "unnamed")
            step = {"policy": pname, "priority": policy.get("priority", 0)}

            subject_match = any(
                self._match_wildcard(s, subject_id) for s in policy.get("subjects", [])
            )
            if not subject_match:
                step["result"] = "skip"
                step["reason"] = f"subject '{subject_id}' not matched"
                trace.append(step)
                continue

            action_match = any(
                self._match_wildcard(a, action) for a in policy.get("actions", [])
            )
            if not action_match:
                step["result"] = "skip"
                step["reason"] = f"action '{action}' not matched"
                trace.append(step)
                continue

            resource_match = any(
                self._match_wildcard(r, resource) for r in policy.get("resources", [])
            )
            if not resource_match:
                step["result"] = "skip"
                step["reason"] = f"resource '{resource}' not matched"
                trace.append(step)
                continue

            cond_result = self._check_conditions(policy.get("conditions", {}), context, trace)
            if not cond_result:
                step["result"] = "skip"
                step["reason"] = "conditions not met"
                trace.append(step)
                continue

            step["result"] = "matched"
            step["effect"] = policy.get("effect", "allow")
            trace.append(step)

            applicable.append(pname)

            if policy.get("effect") == "deny" and matched_deny is None:
                matched_deny = policy
            elif policy.get("effect") == "allow" and matched_allow is None:
                matched_allow = policy

        if matched_deny:
            return PolicyDecision(
                allowed=False,
                matched_policy=matched_deny.get("name", ""),
                reason=matched_deny.get("description", "Denied by policy"),
                applicable_policies=applicable,
                evaluation_trace=trace,
            )

        if matched_allow:
            return PolicyDecision(
                allowed=True,
                matched_policy=matched_allow.get("name", ""),
                reason=matched_allow.get("description", "Allowed by policy"),
                applicable_policies=applicable,
                evaluation_trace=trace,
            )

        return PolicyDecision(
            allowed=True,
            matched_policy="default_allow",
            reason="No matching deny policy; default allow",
            applicable_policies=applicable,
            evaluation_trace=trace,
        )
