import re
import time
import uuid
import logging
from typing import Optional
from core.db_pool import get_pool

logger = logging.getLogger(__name__)


class IntentAnalyzer:

    ACTION_VERBS = {
        "read": ["读取", "查看", "查询", "获取", "看看", "拉", "取", "查", "搜索", "搜", "找", "read", "get", "fetch", "query", "search", "lookup", "list"],
        "write": ["写入", "创建", "新建", "生成", "制作", "编辑", "修改", "更新", "write", "create", "new", "make", "edit", "update", "generate"],
        "delete": ["删除", "删掉", "清空", "移除", "去掉", "drop", "delete", "remove", "clear", "erase"],
        "export": ["导出", "下载", "备份", "输出", "export", "download", "backup", "extract"],
        "share": ["分享", "共享", "发送", "发给", "share", "send", "forward"],
        "approve": ["审批", "批准", "同意", "通过", "approve", "accept", "confirm"],
    }

    RESOURCE_MAP = {
        "document": ["文档", "文件", "报告", "报表", "doc", "document", "file", "report"],
        "bitable": ["多维表格", "表格", "数据表", "bitable", "table", "spreadsheet", "base", "销售数据", "业绩数据", "数据汇总", "数据报告"],
        "contact": ["通讯录", "联系人", "员工", "同事", "人员", "手机号", "邮箱", "contact", "employee", "member"],
        "calendar": ["日程", "日历", "会议", "安排", "calendar", "schedule", "meeting"],
        "task": ["任务", "待办", "todo", "task", "assignment"],
        "approval": ["审批", "请假", "报销", "出差", "approval", "leave", "expense"],
        "salary": ["薪资", "工资", "绩效", "考核", "薪酬", "salary", "payroll", "performance", "薪资表格"],
        "customer": ["客户", "CRM", "customer", "client", "客户数据", "客户联系"],
        "finance": ["财务", "收支", "营收", "账目", "finance", "revenue", "财务部"],
        "wiki": ["知识库", "wiki", "文库", "资料库"],
        "drive": ["云盘", "云文档", "drive", "folder"],
        "internet": ["互联网", "网络", "网页", "internet", "web", "online"],
    }

    SCOPE_INDICATORS = {
        "self": ["我的", "自己", "本人", "我", "my", "self", "me"],
        "department": ["部门", "本部门", "我们", "团队", "department", "team", "group"],
        "cross_department": ["跨部门", "其他部门", "财务部", "技术部", "市场部", "销售部", "HR", "法务部", "other department"],
        "company": ["全公司", "所有", "全部", "整个", "公司", "company", "all", "everyone", "entire"],
        "external": ["外部", "客户", "竞品", "互联网", "公开", "external", "public", "internet"],
    }

    HIGH_RISK_KEYWORDS = [
        "所有", "全部", "批量", "导出", "下载", "删除", "清空", "覆盖", "绕过",
        "管理员", "root", "admin", "紧急", "跳过", "无需验证", "忽略",
        "所有员工", "全量", "完整", "原始",
        "外部邮箱", "外部服务器", "第三方", "个人邮箱",
    ]

    MEDIUM_RISK_KEYWORDS = [
        "薪资", "绩效", "考核", "财务", "客户", "竞品", "合同", "离职", "招聘",
        "机密", "敏感", "内部", "保密", "隐私",
        "发到", "发送到", "传到", "同步到",
    ]

    LOW_RISK_KEYWORDS = [
        "跨部门", "他人", "其他", "所有人", "公司级", "组织架构",
    ]

    DATA_SENSITIVITY_MAP = {
        "salary": 40,
        "contact_phone": 30,
        "contact_email": 25,
        "customer_data": 35,
        "finance_data": 30,
        "personal_info": 30,
        "internal_doc": 15,
        "public_info": 5,
    }

    OPERATION_DANGER_MAP = {
        "delete": 40,
        "export_full": 35,
        "export_batch": 30,
        "write": 20,
        "share": 15,
        "read": 5,
        "approve": 10,
    }

    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self._pool = get_pool(db_path) if db_path else None
        self._request_history = {}

    def _get_conn(self):
        if not self.db_path:
            return None
        return self._pool.get_connection()

    def _return_conn(self, conn):
        if conn and self._pool:
            self._pool.return_connection(conn)

    CONFIRM_LIKE_WORDS = {"确认", "确认执行", "确认继续", "继续", "执行", "同意", "是的", "yes", "y", "确认操作", "sure", "confirm", "ok", "好的", "没问题", "可以"}
    CANCEL_LIKE_WORDS = {"取消", "取消执行", "中止", "放弃", "停止", "否", "no", "cancel", "n", "不要", "不行", "拒绝", "deny", "abort"}

    NORMAL_OPERATION_PATTERNS = [
        (r"(查看|读取|查询|获取|看看).{0,4}(企业|公司|内部)?通讯录", "contact", "read", -20),
        (r"(查看|读取|查询|获取).{0,4}(日程|日历|会议|安排)", "calendar", "read", -20),
        (r"(查看|读取|查询|获取).{0,4}(任务|待办|todo)", "task", "read", -20),
        (r"(查看|读取|查询|获取).{0,4}(审批|流程)", "approval", "read", -15),
        (r"(查看|读取|查询|获取).{0,4}(文档|报告|文件)", "document", "read", -15),
        (r"(查看|读取|查询|获取).{0,4}(数据|表格|记录)", "bitable", "read", -15),
        (r"(生成|创建|制作|写).{0,4}(报告|文档|总结)", "document", "write", -10),
        (r"(搜索|查找|检索).{0,4}(信息|资料|网页|互联网)", "document", "read", -15),
    ]

    def analyze(self, text: str, conversation_history: list = None,
                user_id: str = "") -> dict:
        trace_id = uuid.uuid4().hex[:16]

        stripped = text.strip().lower()
        if stripped in self.CONFIRM_LIKE_WORDS or stripped in self.CANCEL_LIKE_WORDS:
            return {
                "trace_id": trace_id,
                "action": "confirm_cancel",
                "resource": "unknown",
                "scope": "self",
                "original_keywords": [],
                "data_sensitivity": 0,
                "operation_danger": 0,
                "scope_risk": 0,
                "time_risk": 0,
                "history_risk": 0,
                "confidence": 1.0,
                "risk_score": 0,
                "decision": "ALLOW",
                "intent_triple": "[用户] [确认/取消] [待确认操作]",
                "risk_keywords": {"high": [], "medium": [], "low": []},
                "chain_request": {"is_chain": False, "sub_requests": []},
                "duplicate_info": {"is_duplicate": False, "count": 0},
                "business_reason": None,
                "clarification": None,
                "timestamp": time.time(),
            }

        action = self._extract_action(text)
        resource = self._extract_resource(text)
        scope = self._extract_scope(text)
        original_keywords = self._extract_keywords(text)
        data_sensitivity = self._compute_data_sensitivity(text, resource)
        confidence = self._compute_confidence(text, action, resource, scope)
        risk_keywords = self._extract_risk_keywords(text)
        operation_danger = self._compute_operation_danger(text, action)
        scope_risk = self._compute_scope_risk(text, scope)
        time_risk = self._compute_time_risk()
        history_risk = self._compute_history_risk(user_id)
        chain_request = self._detect_chain_request(text)
        duplicate_info = self._detect_duplicate_request(text, user_id)
        business_reason = self._extract_business_reason(text)

        risk_score = min(100, data_sensitivity + operation_danger + scope_risk + time_risk + history_risk)

        risk_score += self._risk_keyword_bonus(text, risk_keywords)

        search_agent_violation = self._detect_search_agent_violation(text)
        if search_agent_violation["is_violation"]:
            risk_score = min(100, risk_score + 50)

        if duplicate_info.get("is_duplicate") and duplicate_info.get("count", 0) >= 3:
            risk_score = min(100, risk_score + 20)

        normal_bonus = self._normal_operation_bonus(text, action, resource)
        risk_score = max(0, risk_score + normal_bonus)

        risk_score = min(100, max(0, risk_score))

        intent_triple = self._build_intent_triple(action, resource, scope, text)

        if confidence < 0.6:
            clarification = self._generate_clarification(text, action, resource, original_keywords)
        else:
            clarification = None

        if risk_score >= 81:
            decision = "DENY"
        elif risk_score >= 61:
            decision = "CONFIRM"
        elif risk_score >= 31:
            decision = "WARN"
        else:
            decision = "ALLOW"

        return {
            "trace_id": trace_id,
            "action": action,
            "resource": resource,
            "scope": scope,
            "original_keywords": original_keywords,
            "data_sensitivity": data_sensitivity,
            "operation_danger": operation_danger,
            "scope_risk": scope_risk,
            "time_risk": time_risk,
            "history_risk": history_risk,
            "confidence": confidence,
            "risk_score": risk_score,
            "decision": decision,
            "intent_triple": intent_triple,
            "risk_keywords": risk_keywords,
            "chain_request": chain_request,
            "duplicate_info": duplicate_info,
            "business_reason": business_reason,
            "clarification": clarification,
            "timestamp": time.time(),
        }

    def _extract_action(self, text: str) -> str:
        action_scores = {}
        for action_type, verbs in self.ACTION_VERBS.items():
            score = 0
            for verb in verbs:
                if verb in text.lower():
                    score += 1
            if score > 0:
                action_scores[action_type] = score

        if not action_scores:
            if any(q in text for q in ["什么", "怎么", "为什么", "是否", "多少", "哪些"]):
                return "read"
            return "unknown"

        return max(action_scores, key=action_scores.get)

    RESOURCE_PRIORITY = ["salary", "customer", "finance", "contact", "calendar", "approval", "task", "bitable", "document", "wiki", "drive"]

    def _extract_resource(self, text: str) -> str:
        resource_scores = {}
        for resource_type, keywords in self.RESOURCE_MAP.items():
            score = 0
            for kw in keywords:
                if kw in text.lower():
                    score += len(kw)
            if score > 0:
                resource_scores[resource_type] = score

        if not resource_scores:
            return "unknown"

        max_score = max(resource_scores.values())
        top_resources = [r for r, s in resource_scores.items() if s == max_score]
        if len(top_resources) == 1:
            return top_resources[0]

        for priority_resource in self.RESOURCE_PRIORITY:
            if priority_resource in top_resources:
                return priority_resource

        return top_resources[0]

    SCOPE_PRIORITY = ["company", "cross_department", "external", "department", "self"]

    def _extract_scope(self, text: str) -> str:
        scope_scores = {}
        for scope_type, indicators in self.SCOPE_INDICATORS.items():
            score = 0
            for indicator in indicators:
                if indicator in text.lower():
                    score += len(indicator)
            if score > 0:
                scope_scores[scope_type] = score

        if not scope_scores:
            return "self"

        max_score = max(scope_scores.values())
        top_scopes = [s for s, sc in scope_scores.items() if sc == max_score]
        if len(top_scopes) == 1:
            return top_scopes[0]

        for priority_scope in self.SCOPE_PRIORITY:
            if priority_scope in top_scopes:
                return priority_scope

        return top_scopes[0]

    def _extract_keywords(self, text: str) -> list:
        keywords = []
        for resource_type, kws in self.RESOURCE_MAP.items():
            for kw in kws:
                if kw in text.lower():
                    keywords.append(kw)
                    break

        for action_type, verbs in self.ACTION_VERBS.items():
            for verb in verbs:
                if verb in text.lower():
                    keywords.append(verb)
                    break

        time_patterns = [r"本周", r"上周", r"本月", r"上月", r"季度", r"年度", r"今天", r"昨天",
                         r"Q[1-4]", r"\d{4}年", r"最近", r"最新"]
        for pattern in time_patterns:
            match = re.search(pattern, text)
            if match:
                keywords.append(match.group())

        dept_patterns = [r"财务部", r"技术部", r"市场部", r"销售部", r"HR", r"法务部", r"产品部", r"运营部"]
        for pattern in dept_patterns:
            if pattern in text:
                keywords.append(pattern)

        name_match = re.search(r"[\u4e00-\u9fff]{2,4}的", text)
        if name_match:
            keywords.append(name_match.group().rstrip("的"))

        return list(set(keywords))[:10]

    def _compute_data_sensitivity(self, text: str, resource: str) -> int:
        score = 0
        lower = text.lower()

        if resource == "salary":
            score += self.DATA_SENSITIVITY_MAP["salary"]
        elif resource == "contact":
            if any(w in lower for w in ["手机号", "电话", "手机"]):
                score += self.DATA_SENSITIVITY_MAP["contact_phone"]
            elif any(w in lower for w in ["邮箱", "email"]):
                score += self.DATA_SENSITIVITY_MAP["contact_email"]
            else:
                score += 15
        elif resource == "customer":
            score += self.DATA_SENSITIVITY_MAP["customer_data"]
        elif resource == "finance":
            score += self.DATA_SENSITIVITY_MAP["finance_data"]
        else:
            score += self.DATA_SENSITIVITY_MAP.get(resource, self.DATA_SENSITIVITY_MAP["internal_doc"])

        if any(w in lower for w in ["个人信息", "隐私", "身份证", "银行卡"]):
            score += self.DATA_SENSITIVITY_MAP["personal_info"]

        return min(score, 50)

    def _compute_operation_danger(self, text: str, action: str) -> int:
        score = self.OPERATION_DANGER_MAP.get(action, 5)
        lower = text.lower()

        if any(w in lower for w in ["所有", "全部", "全量", "完整"]):
            if action in ("export", "read"):
                score = max(score, self.OPERATION_DANGER_MAP["export_full"])

        if any(w in lower for w in ["批量"]):
            score = max(score, self.OPERATION_DANGER_MAP.get("export_batch", 30))

        if action == "export" and any(w in lower for w in ["外部", "邮箱", "第三方", "个人", "发到", "发送到", "传到"]):
            score = max(score, 50)

        if action == "share" and any(w in lower for w in ["外部", "第三方", "个人邮箱"]):
            score = max(score, 45)

        return min(score, 50)

    def _compute_scope_risk(self, text: str, scope: str) -> int:
        if scope == "company":
            return 40
        elif scope == "cross_department":
            return 25
        elif scope == "department":
            return 10
        elif scope == "external":
            return 15
        elif scope == "self":
            return -10
        return 0

    def _compute_time_risk(self) -> int:
        hour = time.localtime().tm_hour
        if 22 <= hour or hour < 7:
            return 15
        return 0

    def _compute_history_risk(self, user_id: str) -> int:
        if not user_id or not self.db_path:
            return 0

        try:
            conn = self._get_conn()
            now = time.time()
            one_hour_ago = now - 3600

            deny_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE delegated_user = ? AND decision = 'DENY' AND timestamp > ?",
                (user_id, one_hour_ago),
            ).fetchone()
            deny_count = deny_row["cnt"] if deny_row else 0

            inj_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE delegated_user = ? AND injection_detected = 1 AND timestamp > ?",
                (user_id, one_hour_ago),
            ).fetchone()
            inj_count = inj_row["cnt"] if inj_row else 0

            self._return_conn(conn)

            risk = 0
            if deny_count > 0:
                risk += 20
            if inj_count > 0:
                risk += 40
            return min(risk, 60)
        except Exception as e:
            logger.warning("Risk computation failed: %s", e)
            return 0

    def _compute_confidence(self, text: str, action: str, resource: str, scope: str) -> float:
        confidence = 0.0

        if action != "unknown":
            confidence += 0.3
        if resource != "unknown":
            confidence += 0.3
        if scope != "self":
            confidence += 0.1

        if len(text) > 5:
            confidence += 0.1
        if action != "unknown" and resource != "unknown":
            confidence += 0.2

        return min(confidence, 1.0)

    def _extract_risk_keywords(self, text: str) -> dict:
        lower = text.lower()
        high = [kw for kw in self.HIGH_RISK_KEYWORDS if kw in lower]
        medium = [kw for kw in self.MEDIUM_RISK_KEYWORDS if kw in lower]
        low = [kw for kw in self.LOW_RISK_KEYWORDS if kw in lower]
        return {"high": high, "medium": medium, "low": low}

    def _risk_keyword_bonus(self, text: str, risk_keywords: dict) -> int:
        bonus = 0
        bonus += len(risk_keywords["high"]) * 10
        bonus += len(risk_keywords["medium"]) * 5
        if len(risk_keywords["medium"]) >= 2:
            bonus += 10
        bonus += len(risk_keywords["low"]) * 3
        return min(bonus, 40)

    def _detect_chain_request(self, text: str) -> dict:
        chain_indicators = ["然后", "之后", "接着", "再", "先.*后", "先.*再", "先.*然后"]
        is_chain = False
        sub_requests = []

        for indicator in chain_indicators:
            if re.search(indicator, text):
                is_chain = True
                break

        if is_chain:
            parts = re.split(r"[，,然后|之后|接着|再]", text)
            for part in parts:
                part = part.strip()
                if part:
                    sub_action = self._extract_action(part)
                    sub_resource = self._extract_resource(part)
                    sub_requests.append({
                        "text": part,
                        "action": sub_action,
                        "resource": sub_resource,
                    })

        return {"is_chain": is_chain, "sub_requests": sub_requests}

    def _detect_duplicate_request(self, text: str, user_id: str) -> dict:
        if not user_id:
            return {"is_duplicate": False, "count": 0}

        now = time.time()
        if user_id not in self._request_history:
            self._request_history[user_id] = []

        recent = [r for r in self._request_history[user_id] if now - r["timestamp"] < 600]

        normalized = re.sub(r"\s+", "", text.lower().strip())
        count = sum(1 for r in recent if r["normalized"] == normalized)

        recent.append({"text": text, "normalized": normalized, "timestamp": now})
        self._request_history[user_id] = recent[-50:]

        return {
            "is_duplicate": count > 0,
            "count": count + 1,
            "first_seen": next((r["timestamp"] for r in recent if r["normalized"] == normalized), now),
        }

    def _extract_business_reason(self, text: str) -> Optional[str]:
        reason_patterns = [
            r"因为(.{2,30}),?(?:需要|想|要)",
            r"为了(.{2,30}),?(?:需要|想|要)",
            r"由于(.{2,30}),?(?:需要|想|要)",
            r"做(.{2,15})(?:报告|总结|分析|汇总),?需要",
            r"准备(.{2,15}),?需要",
        ]
        for pattern in reason_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return None

    def _build_intent_triple(self, action: str, resource: str, scope: str, text: str) -> str:
        agent_map = {
            "document": "DocAgent",
            "bitable": "DataAgent",
            "contact": "DataAgent",
            "calendar": "DataAgent",
            "task": "DataAgent",
            "approval": "DataAgent",
            "salary": "DataAgent",
            "customer": "DataAgent",
            "finance": "DataAgent",
            "wiki": "DocAgent",
            "drive": "DocAgent",
        }

        action_map = {
            "read": "读取",
            "write": "创建",
            "delete": "删除",
            "export": "导出",
            "share": "分享",
            "approve": "审批",
            "unknown": "操作",
        }

        scope_map = {
            "self": "",
            "department": "本部门",
            "cross_department": "跨部门",
            "company": "全公司",
            "external": "外部",
        }

        agent = agent_map.get(resource, "主控Agent")
        action_cn = action_map.get(action, "操作")
        scope_cn = scope_map.get(scope, "")

        resource_cn_map = {
            "document": "文档",
            "bitable": "多维表格",
            "contact": "通讯录",
            "calendar": "日历",
            "task": "任务",
            "approval": "审批",
            "salary": "薪资数据",
            "customer": "客户数据",
            "finance": "财务数据",
            "wiki": "知识库",
            "drive": "云盘",
            "unknown": "资源",
        }
        resource_cn = resource_cn_map.get(resource, "资源")

        scope_prefix = f"{scope_cn}" if scope_cn else ""
        if scope == "cross_department" or scope == "company":
            scope_prefix = f"⚠️{scope_prefix}"

        return f"[{agent}] [{action_cn}] [{scope_prefix}{resource_cn}]"

    def _generate_clarification(self, text: str, action: str, resource: str, keywords: list) -> str:
        guesses = []

        if action != "unknown" and resource != "unknown":
            action_cn = {"read": "读取", "write": "创建", "delete": "删除", "export": "导出"}.get(action, "操作")
            resource_cn = {"document": "文档", "bitable": "表格", "contact": "通讯录", "calendar": "日程"}.get(resource, "数据")
            guesses.append(f"{action_cn}{resource_cn}")

        if keywords:
            for kw in keywords[:2]:
                guesses.append(f"与「{kw}」相关的操作")

        if not guesses:
            guesses.append("查询企业数据")
            guesses.append("生成报告文档")

        guess_str = "」或者「".join(guesses)
        return f"我理解您可能是想「{guess_str}」，请告诉我您具体想做什么？"

    SEARCH_AGENT_VIOLATION_PATTERNS = [
        r"搜索.*助手.*读取.*(?:表格|数据|通讯录|多维)",
        r"搜索.*agent.*(?:read|access).*(?:bitable|contact|data)",
        r"让.*搜索.*读取.*企业",
        r"让.*搜索.*访问.*内部",
        r"search.*agent.*(?:data|bitable|contact)",
        r"外部.*agent.*(?:企业|内部|飞书).*数据",
        r"搜索助手.*(?:企业|内部|飞书).*数据",
    ]

    INTERNAL_DATA_KEYWORDS = ["多维表格", "表格数据", "通讯录", "企业数据", "内部数据", "飞书", "bitable", "contact"]

    def _detect_search_agent_violation(self, text: str) -> dict:
        lower = text.lower()
        has_search_agent = any(kw in lower for kw in ["搜索助手", "搜索agent", "search agent", "searchagent", "外部助手", "外部agent"])
        has_internal_data = any(kw in lower for kw in self.INTERNAL_DATA_KEYWORDS)

        pattern_matched = False
        for pattern in self.SEARCH_AGENT_VIOLATION_PATTERNS:
            if re.search(pattern, lower):
                pattern_matched = True
                break

        is_violation = (has_search_agent and has_internal_data) or pattern_matched

        return {
            "is_violation": is_violation,
            "has_search_agent": has_search_agent,
            "has_internal_data": has_internal_data,
            "pattern_matched": pattern_matched,
        }

    def _normal_operation_bonus(self, text: str, action: str, resource: str) -> int:
        for pattern, expected_resource, expected_action, bonus in self.NORMAL_OPERATION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                if resource == expected_resource or expected_resource == "document":
                    if action == expected_action or expected_action == "read":
                        return bonus
        return 0
