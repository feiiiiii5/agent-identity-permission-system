import json
import sqlite3


class PrivilegeDetector:

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def detect_escalation(
        self,
        agent_id: str,
        requested_capabilities: list,
        registered_capabilities: list,
    ) -> dict:
        registered_set = set(registered_capabilities)
        requested_set = set(requested_capabilities)

        escalated = requested_set - registered_set

        write_escalation = []
        for cap in requested_capabilities:
            if ":write" in cap or ":delete" in cap:
                read_equiv = cap.replace(":write", ":read").replace(":delete", ":read")
                if read_equiv in registered_set and cap not in registered_set:
                    write_escalation.append(cap)

        registered_domains = set()
        for cap in registered_capabilities:
            parts = cap.split(":")
            if len(parts) >= 2:
                registered_domains.add(parts[0])

        requested_domains = set()
        for cap in requested_capabilities:
            parts = cap.split(":")
            if len(parts) >= 2:
                requested_domains.add(parts[0])

        cross_domain = requested_domains - registered_domains

        is_escalation = len(escalated) > 0 or len(write_escalation) > 0 or len(cross_domain) > 0

        severity = "none"
        if len(escalated) > 2 or len(cross_domain) > 1:
            severity = "critical"
        elif len(escalated) > 0 or len(write_escalation) > 0:
            severity = "warning"

        return {
            "is_escalation": is_escalation,
            "severity": severity,
            "escalated_capabilities": sorted(list(escalated)),
            "write_escalation": write_escalation,
            "cross_domain_escalation": sorted(list(cross_domain)),
            "registered_capabilities": sorted(list(registered_set)),
            "requested_capabilities": sorted(list(requested_set)),
        }

    def check_delegation_escalation(
        self,
        parent_capabilities: list,
        child_requested_capabilities: list,
    ) -> dict:
        parent_set = set(parent_capabilities)
        child_set = set(child_requested_capabilities)

        exceeded = child_set - parent_set

        return {
            "is_escalation": len(exceeded) > 0,
            "exceeded_capabilities": sorted(list(exceeded)),
            "parent_capabilities": sorted(list(parent_set)),
            "child_requested": sorted(list(child_set)),
        }

    def check_baseline_escalation(
        self,
        agent_id: str,
        current_capabilities: list,
    ) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT baseline_capabilities FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        conn.close()

        if not row:
            return {"is_escalation": False, "reason": "agent_not_found"}

        try:
            baseline_caps = json.loads(row["baseline_capabilities"])
        except (json.JSONDecodeError, TypeError):
            baseline_caps = []

        baseline_set = set(baseline_caps)
        current_set = set(current_capabilities)

        above_baseline = current_set - baseline_set

        return {
            "is_escalation": len(above_baseline) > 0,
            "above_baseline_capabilities": sorted(list(above_baseline)),
            "baseline_capabilities": sorted(list(baseline_set)),
            "current_capabilities": sorted(list(current_set)),
        }
