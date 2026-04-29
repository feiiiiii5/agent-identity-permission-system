import re
from typing import Optional


class CapabilityEngine:

    CAPABILITY_KEYWORDS = {
        "lark:doc:write": ["写", "创建", "生成", "编辑", "write", "create", "generate", "报告", "文档", "report", "document"],
        "lark:doc:read": ["读", "查看", "获取", "read", "view", "get", "文档", "document"],
        "lark:bitable:read": ["表格", "数据", "多维", "bitable", "table", "查询", "query", "统计", "销售"],
        "lark:bitable:write": ["写入", "更新", "修改", "write", "update", "modify", "表格", "bitable"],
        "lark:contact:read": ["通讯录", "联系人", "员工", "contact", "member", "人员"],
        "lark:calendar:read": ["日历", "日程", "会议", "calendar", "schedule", "meeting"],
        "web:search": ["搜索", "查找", "search", "find", "互联网", "网络"],
        "web:fetch": ["抓取", "获取", "fetch", "crawl", "爬取"],
    }

    DELEGATION_MAP = {
        "DataAgent": {
            "delegate:DataAgent:read": ["lark:bitable:read", "lark:contact:read", "lark:calendar:read"],
            "delegate:DataAgent:write": ["lark:bitable:write"],
        },
        "SearchAgent": {
            "delegate:SearchAgent:read": ["web:search", "web:fetch"],
        },
    }

    def infer_capabilities_from_intent(self, task_description: str) -> list:
        if not task_description:
            return []

        text = task_description.lower()
        inferred = set()

        for cap, keywords in self.CAPABILITY_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    inferred.add(cap)
                    break

        return sorted(list(inferred))

    def compute_dynamic_least_privilege(
        self,
        user_permissions: list,
        agent_capabilities: list,
        task_description: str,
    ) -> dict:
        intent_caps = self.infer_capabilities_from_intent(task_description)

        user_set = set(user_permissions)
        agent_set = set(agent_capabilities)
        intent_set = set(intent_caps)

        if intent_set:
            intersection = user_set & agent_set & intent_set
        else:
            intersection = user_set & agent_set

        granted = sorted(list(intersection))
        denied = sorted(list((user_set | agent_set) - intersection))

        return {
            "granted_capabilities": granted,
            "denied_capabilities": denied,
            "user_permissions": sorted(list(user_set)),
            "agent_capabilities": sorted(list(agent_set)),
            "intent_inferred": sorted(list(intent_set)),
            "intersection_method": "user ∩ agent ∩ intent" if intent_set else "user ∩ agent",
        }

    def check_delegation_permission(
        self,
        parent_capabilities: list,
        target_agent_name: str,
        requested_capabilities: list,
    ) -> dict:
        delegation_map = self.DELEGATION_MAP.get(target_agent_name, {})

        allowed = []
        delegate_read_perm = ""
        delegate_write_perm = ""
        has_delegate_read = False
        has_delegate_write = False

        for delegate_perm, target_caps in delegation_map.items():
            if ":read" in delegate_perm:
                delegate_read_perm = delegate_perm
                if delegate_perm in parent_capabilities:
                    has_delegate_read = True
                    for cap in requested_capabilities:
                        if cap in target_caps:
                            allowed.append(cap)
            elif ":write" in delegate_perm:
                delegate_write_perm = delegate_perm
                if delegate_perm in parent_capabilities:
                    has_delegate_write = True
                    for cap in requested_capabilities:
                        if cap in target_caps:
                            allowed.append(cap)

        allowed = sorted(list(set(allowed)))

        return {
            "allowed": allowed,
            "has_delegate_read": has_delegate_read,
            "has_delegate_write": has_delegate_write,
            "delegate_read_perm": delegate_read_perm,
            "delegate_write_perm": delegate_write_perm,
            "target_agent": target_agent_name,
        }
