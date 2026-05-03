import re
import time
import threading
from typing import Optional
from collections import OrderedDict


class DataOperationClassifier:

    LEVEL_0_DIRECT = 0
    LEVEL_1_RISK_WARN = 1
    LEVEL_2_HUMAN_APPROVAL = 2
    LEVEL_3_PERMANENT_DENY = 3

    LEVEL_LABELS = {
        0: "LEVEL 0 - 直接执行",
        1: "LEVEL 1 - 风险提示后执行",
        2: "LEVEL 2 - 人工审批",
        3: "LEVEL 3 - 永久拒绝",
    }

    LEVEL_DESCRIPTIONS = {
        0: "低风险操作，可直接执行",
        1: "中等风险，需提示用户后执行",
        2: "高风险操作，需人工审批",
        3: "极高风险，永久拒绝，无法审批通过",
    }

    def classify(self, text: str, resource: str, action: str, scope: str,
                 user_id: str = "") -> dict:
        level = self.LEVEL_0_DIRECT
        reasons = []
        requirements = []

        if resource == "bitable":
            level, reasons, requirements = self._classify_bitable(text, action, scope, level, reasons, requirements)
        elif resource == "contact":
            level, reasons, requirements = self._classify_contact(text, action, scope, level, reasons, requirements)
        elif resource == "calendar":
            level, reasons, requirements = self._classify_calendar(text, action, scope, level, reasons, requirements)
        elif resource == "salary":
            level, reasons, requirements = self._classify_salary(text, action, scope, level, reasons, requirements)
        elif resource == "customer":
            level, reasons, requirements = self._classify_customer(text, action, scope, level, reasons, requirements)
        elif resource == "finance":
            level, reasons, requirements = self._classify_finance(text, action, scope, level, reasons, requirements)

        if action == "delete":
            if level < self.LEVEL_2_HUMAN_APPROVAL:
                level = self.LEVEL_2_HUMAN_APPROVAL
            reasons.append("删除操作需要人工审批")
            requirements.append("二次确认")

        if action == "export" and scope in ("company", "cross_department"):
            if level < self.LEVEL_2_HUMAN_APPROVAL:
                level = self.LEVEL_2_HUMAN_APPROVAL
            reasons.append("跨部门/全量数据导出需要审批")
            requirements.append("主管审批")

        return {
            "level": level,
            "level_label": self.LEVEL_LABELS.get(level, "UNKNOWN"),
            "description": self.LEVEL_DESCRIPTIONS.get(level, ""),
            "reasons": reasons,
            "requirements": requirements,
            "resource": resource,
            "action": action,
            "scope": scope,
        }

    def _classify_bitable(self, text: str, action: str, scope: str,
                          level: int, reasons: list, requirements: list) -> tuple:
        if action == "read" and scope in ("self", "department"):
            level = max(level, self.LEVEL_0_DIRECT)
            reasons.append("读取本部门多维表格")
        elif action == "read" and scope == "cross_department":
            level = max(level, self.LEVEL_1_RISK_WARN)
            reasons.append("读取跨部门数据需要业务理由")
            requirements.append("提供业务理由")
        elif action == "write":
            level = max(level, self.LEVEL_1_RISK_WARN)
            reasons.append("写入多维表格需要风险提示")
            requirements.append("确认写入范围")
        elif action in ("delete", "export") and scope in ("company", "cross_department"):
            level = max(level, self.LEVEL_2_HUMAN_APPROVAL)
            reasons.append("批量写入/修改超过100条记录需要审批")
            requirements.append("人工审批")

        return level, reasons, requirements

    def _classify_contact(self, text: str, action: str, scope: str,
                          level: int, reasons: list, requirements: list) -> tuple:
        lower = text.lower()

        if action == "read" and scope in ("self", "department"):
            if any(w in lower for w in ["手机号", "电话", "邮箱", "email"]):
                level = max(level, self.LEVEL_1_RISK_WARN)
                reasons.append("读取通讯录手机号/邮箱字段需要风险提示")
                requirements.append("确认数据用途")
            else:
                level = max(level, self.LEVEL_0_DIRECT)
                reasons.append("读取公司公开通讯录基本信息")
        elif action == "read" and scope in ("company", "cross_department"):
            if any(w in lower for w in ["手机号", "邮箱", "全部", "所有"]):
                level = max(level, self.LEVEL_2_HUMAN_APPROVAL)
                reasons.append("读取全量通讯录（含手机号+邮箱+部门）需要人工审批")
                requirements.append("人工审批")
            else:
                level = max(level, self.LEVEL_1_RISK_WARN)
                reasons.append("跨部门读取通讯录需要业务理由")
                requirements.append("提供业务理由")
        elif action == "export":
            if any(w in lower for w in ["外部", "邮箱", "email", "第三方", "个人", "服务器", "发送到", "传到"]):
                level = max(level, self.LEVEL_3_PERMANENT_DENY)
                reasons.append("导出通讯录到外部系统/邮箱属于LEVEL 3永久拒绝")
                requirements.append("无法审批通过")
            else:
                level = max(level, self.LEVEL_2_HUMAN_APPROVAL)
                reasons.append("导出通讯录需要人工审批确认")
                requirements.append("人工审批")

        return level, reasons, requirements

    def _classify_calendar(self, text: str, action: str, scope: str,
                           level: int, reasons: list, requirements: list) -> tuple:
        if action == "read" and scope == "self":
            level = max(level, self.LEVEL_0_DIRECT)
            reasons.append("读取自己的日历数据")
        elif action == "read" and scope != "self":
            level = max(level, self.LEVEL_1_RISK_WARN)
            reasons.append("读取他人日历需要理由")
            requirements.append("提供业务理由")

        return level, reasons, requirements

    def _classify_salary(self, text: str, action: str, scope: str,
                         level: int, reasons: list, requirements: list) -> tuple:
        level = max(level, self.LEVEL_3_PERMANENT_DENY)
        reasons.append("薪资/绩效数据需要专用HR Agent，不在DataAgent能力范围")
        requirements.append("无法审批通过，需使用HR Agent")

        return level, reasons, requirements

    def _classify_customer(self, text: str, action: str, scope: str,
                           level: int, reasons: list, requirements: list) -> tuple:
        if action == "read" and scope in ("self", "department"):
            level = max(level, self.LEVEL_1_RISK_WARN)
            reasons.append("客户数据访问需要风险提示")
            requirements.append("确认数据用途")
        elif action in ("export", "read") and scope in ("company", "cross_department"):
            level = max(level, self.LEVEL_2_HUMAN_APPROVAL)
            reasons.append("全量客户数据访问需要审批")
            requirements.append("人工审批")

        return level, reasons, requirements

    def _classify_finance(self, text: str, action: str, scope: str,
                          level: int, reasons: list, requirements: list) -> tuple:
        if action == "read" and scope in ("self", "department"):
            level = max(level, self.LEVEL_1_RISK_WARN)
            reasons.append("财务数据访问需要风险提示")
            requirements.append("确认数据用途")
        elif scope in ("company", "cross_department"):
            level = max(level, self.LEVEL_2_HUMAN_APPROVAL)
            reasons.append("跨部门/全公司财务数据需要审批")
            requirements.append("人工审批")

        return level, reasons, requirements


class DataAnomalyDetector:

    RULE_HIGH_FREQ = {
        "name": "高频查询",
        "description": "1分钟内连续查询超过10次",
        "window_seconds": 60,
        "threshold": 10,
        "action": "alert",
    }

    RULE_LARGE_RESULT = {
        "name": "大量数据查询",
        "description": "单次查询记录数超过200条",
        "threshold": 200,
        "action": "alert",
    }

    RULE_OFF_HOUR_LARGE = {
        "name": "非工作时间大量查询",
        "description": "查询时间为非工作时间（22:00-7:00）且数据量超过50条",
        "off_hours": (22, 7),
        "threshold": 50,
        "action": "alert",
    }

    RULE_DUPLICATE_QUERY = {
        "name": "重复查询相同数据",
        "description": "同一trace_id下出现重复查询相同数据",
        "action": "alert",
    }

    RULE_WILDCARD_FIELDS = {
        "name": "全字段请求",
        "description": "请求的字段列表包含'全部'/'所有'/'*'",
        "keywords": ["全部", "所有", "*", "all"],
        "action": "alert",
    }

    MAX_QUERY_TIMESTAMPS = 5000
    MAX_QUERY_CACHE_ENTRIES = 5000

    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self._query_timestamps = OrderedDict()
        self._query_cache = OrderedDict()
        self._lock = threading.Lock()

    def check_all_rules(self, user_id: str, text: str, record_count: int = 0,
                        fields: list = None, trace_id: str = "") -> dict:
        alerts = []

        freq_alert = self.check_high_frequency(user_id)
        if freq_alert["triggered"]:
            alerts.append(freq_alert)

        large_alert = self.check_large_result_set(user_id, record_count)
        if large_alert["triggered"]:
            alerts.append(large_alert)

        off_hour_alert = self.check_off_hour_large(record_count)
        if off_hour_alert["triggered"]:
            alerts.append(off_hour_alert)

        dup_alert = self.check_duplicate_query(user_id, text, trace_id)
        if dup_alert["triggered"]:
            alerts.append(dup_alert)

        wildcard_alert = self.check_wildcard_fields(text, fields)
        if wildcard_alert["triggered"]:
            alerts.append(wildcard_alert)

        return {
            "has_anomaly": len(alerts) > 0,
            "alert_count": len(alerts),
            "alerts": alerts,
            "user_id": user_id,
        }

    def check_high_frequency(self, user_id: str) -> dict:
        now = time.time()
        with self._lock:
            if user_id not in self._query_timestamps:
                self._query_timestamps[user_id] = []

            self._query_timestamps[user_id] = [
                t for t in self._query_timestamps[user_id]
                if now - t < self.RULE_HIGH_FREQ["window_seconds"]
            ]
            self._query_timestamps[user_id].append(now)
            while len(self._query_timestamps) > self.MAX_QUERY_TIMESTAMPS:
                self._query_timestamps.popitem(last=False)

            count = len(self._query_timestamps[user_id])
        triggered = count > self.RULE_HIGH_FREQ["threshold"]

        return {
            "rule": self.RULE_HIGH_FREQ["name"],
            "triggered": triggered,
            "description": self.RULE_HIGH_FREQ["description"],
            "current_count": count,
            "threshold": self.RULE_HIGH_FREQ["threshold"],
            "window_seconds": self.RULE_HIGH_FREQ["window_seconds"],
            "action": self.RULE_HIGH_FREQ["action"] if triggered else None,
        }

    def check_large_result_set(self, user_id: str, record_count: int) -> dict:
        with self._lock:
            cache_key = f"{user_id}:{record_count}"
            if cache_key in self._query_cache:
                return self._query_cache[cache_key]

            triggered = record_count > self.RULE_LARGE_RESULT["threshold"]

            result = {
                "rule": self.RULE_LARGE_RESULT["name"],
                "triggered": triggered,
                "description": self.RULE_LARGE_RESULT["description"],
                "current_count": record_count,
                "threshold": self.RULE_LARGE_RESULT["threshold"],
                "action": self.RULE_LARGE_RESULT["action"] if triggered else None,
            }

            self._query_cache[cache_key] = result
            while len(self._query_cache) > self.MAX_QUERY_CACHE_ENTRIES:
                self._query_cache.popitem(last=False)

            return result

    def check_off_hour_large(self, record_count: int) -> dict:
        hour = time.localtime().tm_hour
        off_start, off_end = self.RULE_OFF_HOUR_LARGE["off_hours"]
        is_off_hour = hour >= off_start or hour < off_end

        triggered = is_off_hour and record_count > self.RULE_OFF_HOUR_LARGE["threshold"]

        return {
            "rule": self.RULE_OFF_HOUR_LARGE["name"],
            "triggered": triggered,
            "description": self.RULE_OFF_HOUR_LARGE["description"],
            "is_off_hour": is_off_hour,
            "current_hour": hour,
            "current_count": record_count,
            "threshold": self.RULE_OFF_HOUR_LARGE["threshold"],
            "action": self.RULE_OFF_HOUR_LARGE["action"] if triggered else None,
        }

    def check_duplicate_query(self, user_id: str, text: str, trace_id: str) -> dict:
        key = f"{user_id}:{trace_id}"
        normalized = re.sub(r"\s+", "", text.lower().strip())

        if key not in self._query_cache:
            self._query_cache[key] = []

        is_duplicate = any(q == normalized for q in self._query_cache[key])
        self._query_cache[key].append(normalized)

        if len(self._query_cache[key]) > 20:
            self._query_cache[key] = self._query_cache[key][-20:]

        return {
            "rule": self.RULE_DUPLICATE_QUERY["name"],
            "triggered": is_duplicate,
            "description": self.RULE_DUPLICATE_QUERY["description"],
            "trace_id": trace_id,
            "action": self.RULE_DUPLICATE_QUERY["action"] if is_duplicate else None,
        }

    def check_wildcard_fields(self, text: str, fields: list = None) -> dict:
        lower = text.lower()
        triggered = False
        matched_keywords = []

        for kw in self.RULE_WILDCARD_FIELDS["keywords"]:
            if kw.lower() in lower:
                triggered = True
                matched_keywords.append(kw)

        if fields:
            for field in fields:
                if field in ("*", "all", "全部", "所有"):
                    triggered = True
                    matched_keywords.append(field)

        return {
            "rule": self.RULE_WILDCARD_FIELDS["name"],
            "triggered": triggered,
            "description": self.RULE_WILDCARD_FIELDS["description"],
            "matched_keywords": matched_keywords,
            "action": self.RULE_WILDCARD_FIELDS["action"] if triggered else None,
        }
