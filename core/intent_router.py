import re
import time
import uuid
from typing import Optional


class IntentRouter:

    INTENT_PATTERNS = [
        {
            "intent": "generate_report",
            "patterns": [
                r"生成.*报告", r"创建.*报告", r"写.*报告", r"汇总.*报告",
                r"季度.*报告", r"月度.*报告", r"年度.*报告",
                r"generate.*report", r"create.*report", r"write.*report",
                r"销售.*报告", r"业绩.*报告", r"数据.*报告",
            ],
            "workflow": "doc_delegate_data",
            "required_agents": ["agent_doc_001", "agent_data_001"],
            "required_capabilities": ["lark:doc:write", "delegate:DataAgent:read"],
            "delegation_target": "agent_data_001",
            "delegation_capabilities": ["lark:bitable:read"],
            "description": "生成报告：DocAgent 委托 DataAgent 读取数据后写入飞书文档",
            "friendly_name": "生成报告",
        },
        {
            "intent": "query_data",
            "patterns": [
                r"查询.*数据", r"读取.*数据", r"查看.*表格", r"获取.*数据",
                r"多维表格", r"通讯录", r"员工.*信息",
                r"query.*data", r"read.*data", r"get.*data", r"fetch.*data",
                r"统计.*数据", r"分析.*数据",
            ],
            "workflow": "data_direct",
            "required_agents": ["agent_data_001"],
            "required_capabilities": ["lark:bitable:read"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "查询数据：DataAgent 直接读取飞书企业数据",
            "friendly_name": "查询企业数据",
        },
        {
            "intent": "search_web",
            "patterns": [
                r"搜索.*信息", r"查找.*网页", r"互联网.*搜索", r"网上.*查",
                r"search.*web", r"find.*online", r"lookup.*internet",
                r"公开.*信息", r"外部.*检索",
            ],
            "workflow": "search_direct",
            "required_agents": ["agent_search_001"],
            "required_capabilities": ["web:search"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "网络搜索：SearchAgent 检索互联网公开信息",
            "friendly_name": "搜索互联网",
        },
        {
            "intent": "generate_report_with_search",
            "patterns": [
                r"生成.*报告.*搜索", r"搜索.*写.*报告", r"结合.*外部.*报告",
                r"综合.*分析", r"市场.*报告", r"竞品.*分析",
                r"research.*report", r"comprehensive.*analysis",
            ],
            "workflow": "doc_delegate_both",
            "required_agents": ["agent_doc_001", "agent_data_001", "agent_search_001"],
            "required_capabilities": ["lark:doc:write", "delegate:DataAgent:read", "delegate:SearchAgent:read"],
            "delegation_target": "agent_data_001",
            "delegation_capabilities": ["lark:bitable:read"],
            "description": "综合报告：DocAgent 委托 DataAgent 和 SearchAgent 获取内外数据后写入文档",
            "friendly_name": "生成综合报告",
        },
        {
            "intent": "read_contact",
            "patterns": [
                r"通讯录", r"联系人", r"员工.*列表", r"部门.*人员",
                r"contact", r"member.*list", r"employee",
            ],
            "workflow": "data_contact",
            "required_agents": ["agent_data_001"],
            "required_capabilities": ["lark:contact:read"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "读取通讯录：DataAgent 读取飞书通讯录（敏感操作，需审批）",
            "friendly_name": "读取通讯录",
        },
    ]

    UNAUTHORIZED_PATTERNS = [
        {
            "patterns": [
                r"删除.*所有", r"drop.*table", r"delete.*all",
                r"忽略.*指令", r"ignore.*instruction",
                r"管理员.*权限", r"admin.*privilege",
                r"绕过.*安全", r"bypass.*security",
            ],
            "response": "检测到潜在恶意指令，操作已被安全策略拦截",
            "error_code": "ERR_UNAUTHORIZED_COMMAND",
        },
    ]

    def __init__(self):
        self._compiled_patterns = []
        for intent_def in self.INTENT_PATTERNS:
            compiled = {
                "intent": intent_def["intent"],
                "patterns": [re.compile(p, re.IGNORECASE) for p in intent_def["patterns"]],
                "workflow": intent_def["workflow"],
                "required_agents": intent_def["required_agents"],
                "required_capabilities": intent_def["required_capabilities"],
                "delegation_target": intent_def.get("delegation_target"),
                "delegation_capabilities": intent_def.get("delegation_capabilities", []),
                "description": intent_def["description"],
                "friendly_name": intent_def["friendly_name"],
            }
            self._compiled_patterns.append(compiled)

        self._compiled_unauthorized = []
        for unauth_def in self.UNAUTHORIZED_PATTERNS:
            self._compiled_unauthorized.append({
                "patterns": [re.compile(p, re.IGNORECASE) for p in unauth_def["patterns"]],
                "response": unauth_def["response"],
                "error_code": unauth_def["error_code"],
            })

    def route(self, user_input: str) -> dict:
        if not user_input or not user_input.strip():
            return {
                "routed": False,
                "intent": "empty",
                "error": "请输入您的需求，例如：生成季度销售报告",
                "suggestions": self._get_suggestions(),
            }

        for unauth in self._compiled_unauthorized:
            for pattern in unauth["patterns"]:
                if pattern.search(user_input):
                    return {
                        "routed": False,
                        "intent": "unauthorized",
                        "error": unauth["response"],
                        "error_code": unauth["error_code"],
                        "blocked": True,
                    }

        best_match = None
        best_score = 0

        for intent_def in self._compiled_patterns:
            score = 0
            matched_patterns = []
            for pattern in intent_def["patterns"]:
                if pattern.search(user_input):
                    score += 1
                    matched_patterns.append(pattern.pattern)

            if score > best_score:
                best_score = score
                best_match = intent_def
                best_match["_matched_patterns"] = matched_patterns

        if best_match and best_score > 0:
            confidence = min(best_score / 2.0, 1.0)
            return {
                "routed": True,
                "intent": best_match["intent"],
                "confidence": confidence,
                "workflow": best_match["workflow"],
                "required_agents": best_match["required_agents"],
                "required_capabilities": best_match["required_capabilities"],
                "delegation_target": best_match["delegation_target"],
                "delegation_capabilities": best_match["delegation_capabilities"],
                "description": best_match["description"],
                "friendly_name": best_match["friendly_name"],
                "matched_patterns": best_match.get("_matched_patterns", []),
                "user_input": user_input,
            }

        return {
            "routed": False,
            "intent": "unknown",
            "error": "未能理解您的需求，请尝试更具体的描述",
            "suggestions": self._get_suggestions(),
            "user_input": user_input,
        }

    def _get_suggestions(self) -> list:
        return [
            {"text": "生成季度销售报告", "intent": "generate_report"},
            {"text": "查询多维表格数据", "intent": "query_data"},
            {"text": "搜索互联网公开信息", "intent": "search_web"},
            {"text": "读取企业通讯录", "intent": "read_contact"},
            {"text": "生成综合市场分析报告", "intent": "generate_report_with_search"},
        ]

    def get_all_workflows(self) -> list:
        return [
            {
                "intent": w["intent"],
                "workflow": w["workflow"],
                "description": w["description"],
                "friendly_name": w["friendly_name"],
                "required_agents": w["required_agents"],
                "required_capabilities": w["required_capabilities"],
            }
            for w in self.INTENT_PATTERNS
        ]
