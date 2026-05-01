import re
import time
import uuid
from typing import Optional


class IntentRouter:

    INTENT_PATTERNS = [
        {
            "intent": "unauthorized_delegation",
            "priority": 10,
            "patterns": [
                r"外部.*读取.*数据", r"搜索.*读取.*表格", r"search.*read.*bitable",
                r"外部检索.*企业数据", r"search.*agent.*data.*agent",
                r"让.*搜索.*读取.*企业", r"让.*外部.*访问.*内部",
                r"search.*access.*bitable", r"search.*access.*contact",
                r"搜索助手.*企业数据", r"外部.*访问.*飞书",
                r"searchagent.*data", r"检索.*读取.*表格",
                r"外部agent.*企业数据", r"搜索.*获取.*通讯录",
                r"外部.*获取.*内部.*数据",
                r"intercept", r"unauthorized.*delegation",
                r"search.*try.*data", r"search.*attempt.*enterprise",
                r"外部.*agent.*数据", r"外部.*读取.*表格",
                r"外部.*访问.*数据", r"外部.*获取.*数据",
                r"搜索.*agent.*读取", r"search.*agent.*read",
                r"越权.*委托", r"越权.*访问", r"越权.*读取",
                r"非法.*委托", r"非法.*访问", r"非法.*读取",
                r"越权.*拦截", r"越权.*演示", r"越权.*测试",
                r"权限.*越界", r"权限.*滥用", r"权限.*突破",
                r"外部检索.*agent.*数据", r"外部检索.*读取",
                r"search.*越权", r"search.*unauthorized",
            ],
            "workflow": "unauthorized_delegation",
            "required_agents": ["agent_search_001", "agent_data_001"],
            "required_capabilities": ["web:search"],
            "delegation_target": "agent_data_001",
            "delegation_capabilities": ["lark:bitable:read"],
            "description": "越权拦截：SearchAgent 尝试委托 DataAgent 读取企业数据，被权限系统拦截",
            "friendly_name": "越权拦截演示",
        },
        {
            "intent": "generate_report",
            "priority": 5,
            "patterns": [
                r"生成.*报告", r"创建.*报告", r"写.*报告", r"汇总.*报告",
                r"季度.*报告", r"月度.*报告", r"年度.*报告",
                r"generate.*report", r"create.*report", r"write.*report",
                r"销售.*报告", r"业绩.*报告", r"数据.*报告",
                r"帮我.*报告", r"制作.*报告", r"整理.*报告",
                r"输出.*报告", r"导出.*报告", r"一份.*报告",
                r"报告.*生成", r"报告.*创建", r"报告.*写",
                r"文档助手", r"让.*文档.*助手", r"doc.*agent",
                r"飞书.*文档", r"写入.*文档", r"创建.*文档",
                r"季度.*销售", r"销售.*数据.*报告", r"业绩.*汇总",
                r"工作.*总结", r"项目.*报告", r"周报", r"月报",
                r"报表", r"数据.*汇总", r"统计.*报告",
                r"分析.*报告", r"总结.*报告", r"汇报",
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
            "priority": 3,
            "patterns": [
                r"查询.*数据", r"读取.*数据", r"查看.*表格", r"获取.*数据",
                r"多维表格", r"员工.*信息",
                r"query.*data", r"read.*data", r"get.*data", r"fetch.*data",
                r"统计.*数据", r"分析.*数据",
                r"看看.*数据", r"数据.*多少", r"数据.*怎样",
                r"表格.*数据", r"bitable", r"base.*table",
                r"销售.*数据", r"业绩.*数据", r"财务.*数据",
                r"企业.*数据", r"内部.*数据", r"公司.*数据",
                r"数据.*查询", r"数据.*读取", r"数据.*获取",
                r"数据.*agent", r"让.*数据.*助手", r"data.*agent",
                r"表格里.*什么", r"表格.*内容", r"记录.*查询",
                r"有多少.*数据", r"最新.*数据", r"当前.*数据",
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
            "priority": 2,
            "patterns": [
                r"搜索.*信息", r"查找.*网页", r"互联网.*搜索", r"网上.*查",
                r"search.*web", r"find.*online", r"lookup.*internet",
                r"公开.*信息",
                r"搜一下", r"查一下.*网上", r"网上.*搜",
                r"搜索引擎", r"google", r"百度.*搜索",
                r"外部.*信息", r"公开.*网页", r"网络.*检索",
                r"新闻.*搜索", r"资讯.*搜索", r"网页.*查找",
                r"帮我搜", r"搜搜", r"查找.*资料",
                r"网络搜索",
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
            "priority": 5,
            "patterns": [
                r"生成.*报告.*搜索", r"搜索.*写.*报告", r"结合.*外部.*报告",
                r"综合.*分析", r"市场.*报告", r"竞品.*分析",
                r"research.*report", r"comprehensive.*analysis",
                r"综合.*报告", r"全面.*分析", r"深度.*报告",
                r"内外.*数据", r"结合.*内外", r"市场.*调研",
                r"行业.*分析", r"竞品.*调研", r"综合.*调研",
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
            "priority": 3,
            "patterns": [
                r"通讯录", r"联系人", r"员工.*列表", r"部门.*人员",
                r"contact", r"member.*list", r"employee",
                r"同事.*信息", r"人员.*名单", r"组织.*架构",
                r"谁.*负责", r"谁.*部门", r"部门.*有哪些人",
                r"员工.*联系方式", r"手机.*号", r"邮箱.*查询",
                r"人员.*查询", r"查找.*同事", r"同事.*列表",
                r"企业.*通讯录", r"公司.*通讯录", r"内部.*通讯录",
            ],
            "workflow": "data_contact",
            "required_agents": ["agent_data_001"],
            "required_capabilities": ["lark:contact:read"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "读取通讯录：DataAgent 读取飞书通讯录（敏感操作，需审批）",
            "friendly_name": "读取通讯录",
        },
        {
            "intent": "token_management",
            "priority": 4,
            "patterns": [
                r"签发.*token", r"发行.*token", r"创建.*token",
                r"issue.*token", r"create.*token", r"generate.*token",
                r"通行证", r"access.*token", r"令牌",
                r"委托.*token", r"delegate.*token",
                r"验证.*token", r"verify.*token", r"校验.*token",
                r"撤销.*token", r"revoke.*token", r"吊销.*token",
                r"token.*管理", r"token.*操作",
            ],
            "workflow": "token_management",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "Token管理：签发、委托、验证、撤销Token",
            "friendly_name": "Token管理",
        },
        {
            "intent": "security_scan",
            "priority": 4,
            "patterns": [
                r"安全.*扫描", r"注入.*检测", r"安全.*检查",
                r"scan.*injection", r"security.*scan", r"check.*safety",
                r"检测.*注入", r"扫描.*安全", r"安全.*审计",
                r"威胁.*检测", r"风险.*扫描", r"安全.*评估",
            ],
            "workflow": "security_scan",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "安全扫描：检测Prompt注入等AI特有攻击",
            "friendly_name": "安全扫描",
        },
        {
            "intent": "system_status",
            "priority": 1,
            "patterns": [
                r"系统.*状态", r"运行.*状态", r"system.*status",
                r"当前.*状态", r"服务.*状态", r"健康.*检查",
                r"系统.*信息", r"运行.*信息", r"系统.*概况",
                r"status", r"health", r"info",
                r"什么.*状态", r"怎么样", r"还好吗",
                r"系统.*正常", r"服务.*正常",
            ],
            "workflow": "system_status",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "系统状态：查看系统运行状况",
            "friendly_name": "系统状态",
        },
        {
            "intent": "audit_query",
            "priority": 1,
            "patterns": [
                r"审计.*日志", r"操作.*记录", r"audit.*log",
                r"查看.*日志", r"日志.*查询", r"追溯.*记录",
                r"谁.*做了.*什么", r"操作.*历史", r"授权.*记录",
                r"拦截.*记录", r"安全.*事件", r"审计.*追溯",
                r"信任链", r"chain.*trust", r"调用链.*记录",
            ],
            "workflow": "audit_query",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "审计日志：查看授权决策和操作记录",
            "friendly_name": "审计日志",
        },
        {
            "intent": "agent_info",
            "priority": 1,
            "patterns": [
                r"agent.*列表", r"有哪些.*agent", r"agent.*信息",
                r"智能体.*列表", r"助手.*列表", r"ai.*助手",
                r"注册.*agent", r"agent.*注册", r"哪些.*助手",
                r"agent.*角色", r"角色.*列表", r"身份.*信息",
                r"svid", r"身份.*证明", r"spiffe",
            ],
            "workflow": "agent_info",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "Agent信息：查看已注册的Agent列表和身份信息",
            "friendly_name": "Agent信息",
        },
        {
            "intent": "risk_assessment",
            "priority": 1,
            "patterns": [
                r"风险.*评分", r"风险.*评估", r"risk.*score",
                r"安全.*评分", r"风险.*等级", r"威胁.*等级",
                r"风险.*分析", r"安全.*等级", r"agent.*风险",
                r"哪个.*安全", r"哪个.*危险",
            ],
            "workflow": "risk_assessment",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "风险评估：查看Agent风险评分和安全等级",
            "friendly_name": "风险评估",
        },
        {
            "intent": "demo_scenario",
            "priority": 1,
            "patterns": [
                r"演示.*场景", r"运行.*演示", r"demo",
                r"展示.*功能", r"功能.*演示", r"跑.*场景",
                r"正常.*委托", r"越权.*拦截", r"token.*盗用",
                r"注入.*防御", r"人工.*审批", r"特权.*升级",
                r"capability.*mismatch", r"token.*theft",
                r"privilege.*escalation", r"human.*approval",
                r"演示.*一下", r"测试.*场景",
            ],
            "workflow": "demo_scenario",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "演示场景：运行预设的安全演示场景",
            "friendly_name": "演示场景",
        },
        {
            "intent": "policy_info",
            "priority": 1,
            "patterns": [
                r"策略.*配置", r"权限.*策略", r"policy",
                r"规则.*配置", r"安全.*策略", r"授权.*策略",
                r"访问.*控制", r"权限.*配置", r"capability.*policy",
            ],
            "workflow": "policy_info",
            "required_agents": [],
            "required_capabilities": [],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "策略配置：查看系统安全策略和权限配置",
            "friendly_name": "策略配置",
        },
        {
            "intent": "feishu_doc",
            "priority": 3,
            "patterns": [
                r"创建.*飞书.*文档", r"新建.*文档", r"写.*飞书.*文档",
                r"飞书.*文档", r"lark.*doc", r"feishu.*doc",
                r"文档.*创建", r"文档.*写入", r"文档.*操作",
                r"写.*文档", r"新建.*飞书", r"创建.*文档",
            ],
            "workflow": "feishu_doc",
            "required_agents": ["agent_doc_001"],
            "required_capabilities": ["lark:doc:write"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "飞书文档：创建和编辑飞书文档",
            "friendly_name": "飞书文档",
        },
        {
            "intent": "feishu_bitable",
            "priority": 3,
            "patterns": [
                r"读取.*多维表格", r"查看.*多维表格", r"多维表格.*数据",
                r"bitable", r"base.*table", r"飞书.*表格",
                r"表格.*读取", r"表格.*查看", r"电子表格",
            ],
            "workflow": "feishu_bitable",
            "required_agents": ["agent_data_001"],
            "required_capabilities": ["lark:bitable:read"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "多维表格：读取飞书多维表格数据",
            "friendly_name": "多维表格",
        },
        {
            "intent": "feishu_contact",
            "priority": 3,
            "patterns": [
                r"读取.*通讯录", r"查看.*通讯录", r"飞书.*通讯录",
                r"lark.*contact", r"feishu.*contact",
                r"通讯录.*读取", r"通讯录.*查看",
            ],
            "workflow": "feishu_contact",
            "required_agents": ["agent_data_001"],
            "required_capabilities": ["lark:contact:read"],
            "delegation_target": None,
            "delegation_capabilities": [],
            "description": "飞书通讯录：读取飞书企业通讯录",
            "friendly_name": "飞书通讯录",
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

    KEYWORD_MAP = {
        "报告": "generate_report",
        "文档": "feishu_doc",
        "表格": "feishu_bitable",
        "通讯录": "read_contact",
        "搜索": "search_web",
        "查找": "search_web",
        "数据": "query_data",
        "token": "token_management",
        "令牌": "token_management",
        "通行证": "token_management",
        "审计": "audit_query",
        "日志": "audit_query",
        "风险": "risk_assessment",
        "安全": "security_scan",
        "注入": "security_scan",
        "agent": "agent_info",
        "助手": "agent_info",
        "状态": "system_status",
        "策略": "policy_info",
        "规则": "policy_info",
        "演示": "demo_scenario",
        "委托": "token_management",
        "越权": "unauthorized_delegation",
        "拦截": "unauthorized_delegation",
        "签发": "token_management",
        "撤销": "token_management",
        "验证": "token_management",
        "svid": "agent_info",
        "身份": "agent_info",
    }

    def __init__(self):
        self._compiled_patterns = []
        for intent_def in self.INTENT_PATTERNS:
            compiled = {
                "intent": intent_def["intent"],
                "priority": intent_def.get("priority", 1),
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

            if score > 0:
                priority = intent_def.get("priority", 1)
                weighted_score = score * priority
                if weighted_score > best_score:
                    best_score = weighted_score
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

        fallback_intent = self._keyword_fallback(user_input)
        if fallback_intent:
            return fallback_intent

        return {
            "routed": False,
            "intent": "unknown",
            "error": "未能理解您的需求，请尝试更具体的描述",
            "suggestions": self._get_suggestions(),
            "user_input": user_input,
        }

    def _keyword_fallback(self, user_input: str) -> Optional[dict]:
        lower = user_input.lower()
        matched_intents = {}
        for keyword, intent_name in self.KEYWORD_MAP.items():
            if keyword in lower:
                matched_intents[intent_name] = matched_intents.get(intent_name, 0) + 1

        if not matched_intents:
            return None

        best_intent_name = max(matched_intents, key=matched_intents.get)
        for intent_def in self._compiled_patterns:
            if intent_def["intent"] == best_intent_name:
                return {
                    "routed": True,
                    "intent": intent_def["intent"],
                    "confidence": 0.4,
                    "workflow": intent_def["workflow"],
                    "required_agents": intent_def["required_agents"],
                    "required_capabilities": intent_def["required_capabilities"],
                    "delegation_target": intent_def["delegation_target"],
                    "delegation_capabilities": intent_def["delegation_capabilities"],
                    "description": intent_def["description"],
                    "friendly_name": intent_def["friendly_name"],
                    "matched_patterns": [],
                    "user_input": user_input,
                    "fallback": True,
                }

        return None

    def _get_suggestions(self) -> list:
        return [
            {"text": "生成季度销售报告", "intent": "generate_report"},
            {"text": "查询多维表格数据", "intent": "query_data"},
            {"text": "搜索互联网公开信息", "intent": "search_web"},
            {"text": "读取企业通讯录", "intent": "read_contact"},
            {"text": "生成综合市场分析报告", "intent": "generate_report_with_search"},
            {"text": "外部检索Agent尝试读取企业数据", "intent": "unauthorized_delegation"},
            {"text": "查看系统状态", "intent": "system_status"},
            {"text": "查看审计日志", "intent": "audit_query"},
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
