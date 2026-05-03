import re
import time
import uuid


class ResponseEngine:

    FORBIDDEN_PHRASES = {
        "您的请求已收到": None,
        "权限不足，请联系管理员": None,
        "操作完成": None,
        "系统繁忙，请稍后重试": None,
        "此操作存在风险，请谨慎": None,
        "请求已处理": None,
        "操作失败": None,
    }

    REPLACEMENT_TEMPLATES = {
        "您的请求已收到": "正在处理您关于「{keywords}」的请求",
        "权限不足，请联系管理员": "您缺少「{missing_perm}」权限，可通过{how_to_apply}申请",
        "操作完成": "已完成{what_done}，结果：{result_summary}",
        "系统繁忙，请稍后重试": "{specific_error}，建议{specific_action}",
        "此操作存在风险，请谨慎": "您请求的「{resource}」包含{data_detail}，根据{policy_rule}，{required_action}",
        "请求已处理": "已{what_done}您关于「{keywords}」的请求",
        "操作失败": "{what_failed}失败，原因：{specific_reason}",
    }

    def format_allow_response(self, text: str, intent: dict, workflow_result: str,
                              trace_id: str, risk_score: float) -> str:
        keywords = intent.get("original_keywords", [])
        keywords_str = "」、「".join(keywords[:3]) if keywords else "您的操作"
        intent_triple = intent.get("intent_triple", "")

        result = f"✅ 正在处理您的请求\n\n"
        result += f"📋 意图分析：{intent_triple}\n"
        result += f"   用户请求涉及「{keywords_str}」\n"

        agents_involved = self._extract_agents_from_intent(intent)
        if agents_involved:
            result += f"🔐 权限验证："
            for agent, caps in agents_involved.items():
                cap_str = "、".join(caps[:3])
                result += f"\n   • {agent}: {cap_str} ✅"
            result += "\n"

        risk_level = self._risk_level_label(risk_score)
        result += f"⚠️ 风险评估：{int(risk_score)}/100（{risk_level}）\n"

        if workflow_result:
            result += f"📊 执行结果：\n{workflow_result}\n"
        else:
            result += f"📊 执行结果：处理中...\n"

        result += f"🔗 Trace ID：{trace_id}\n"

        if risk_score >= 31:
            result += f"\n💡 数据使用提示：本次操作涉及「{keywords_str}」，请确保遵守数据安全策略"

        return result

    def format_deny_response(self, text: str, intent: dict, risk_score: float,
                             trace_id: str, deny_reason: str = "",
                             detection: dict = None) -> str:
        keywords = intent.get("original_keywords", [])
        keywords_str = "」、「".join(keywords[:3]) if keywords else "该操作"
        user_quote = self._extract_user_quote(text)

        result = f"🚫 操作被安全策略拦截\n\n"
        result += f"📋 您的请求：「{user_quote}」\n"

        if deny_reason:
            specific_reason = self._make_specific_deny_reason(text, intent, deny_reason, detection)
            result += f"❌ 拒绝原因：{specific_reason}\n"
        else:
            result += f"❌ 拒绝原因：{self._infer_deny_reason(text, intent)}\n"

        result += f"📊 风险评分：{int(risk_score)}/100\n"

        alternatives = self._generate_alternatives(text, intent)
        result += f"\n🔄 建议替代方案：\n"
        for i, alt in enumerate(alternatives, 1):
            result += f"  {i}️⃣ {alt}\n"

        result += f"\n🔗 Trace ID：{trace_id}\n"
        result += f"📞 如有疑问，请联系：IT 安全部门"

        return result

    def format_injection_block_response(self, text: str, scan_result: dict,
                                        detection: dict, trace_id: str) -> str:
        threats = scan_result.get("threats", []) if scan_result else []
        threat_types = []
        threat_keywords = []
        for t in threats:
            if isinstance(t, dict):
                t_type = t.get("type", "unknown")
                t_matched = t.get("matched_text", "")
                if t_type not in threat_types:
                    threat_types.append(t_type)
                if t_matched and t_matched not in threat_keywords:
                    threat_keywords.append(t_matched)

        if detection:
            for cat in detection.get("threat_categories", [])[:3]:
                cat_type = cat.get("category", "")
                if cat_type and cat_type not in threat_types:
                    threat_types.append(cat_type)

        detection_layer = self._determine_detection_layer(scan_result, detection)

        sanitized = self._sanitize_content(text)

        result = f"🚨 安全威胁拦截\n\n"
        result += f"⚠️ 检测到：{', '.join(threat_types[:3]) if threat_types else '恶意输入'}\n"
        if threat_keywords:
            result += f"   触发关键词：「{'」、「'.join(threat_keywords[:3])}」\n"
        result += f"🛡️ 拦截层级：{detection_layer}\n"
        result += f"🧹 净化内容：{sanitized}\n"
        result += f"❌ 错误码：PROMPT_INJECTION_BLOCKED\n"
        result += f"🔗 Trace ID：{trace_id}\n"
        result += f"⚠️ 本次会话已标记为高风险，后续操作将受到额外审查"

        return result

    def format_confirmation_request(self, text: str, intent: dict,
                                    risk_score: float, trace_id: str) -> str:
        keywords = intent.get("original_keywords", [])
        keywords_str = "」、「".join(keywords[:3]) if keywords else "该操作"
        user_quote = self._extract_user_quote(text)
        intent_triple = intent.get("intent_triple", "")

        result = f"⚠️ 操作需要确认\n\n"
        result += f"📋 您的请求：「{user_quote}」\n"
        result += f"📋 意图分析：{intent_triple}\n"
        result += f"📊 风险评分：{int(risk_score)}/100（需要确认）\n\n"

        risk_details = self._explain_risk_factors(text, intent)
        if risk_details:
            result += f"🔍 风险因素：\n"
            for detail in risk_details:
                result += f"  • {detail}\n"
            result += "\n"

        result += f"请回复「确认」以继续执行，或回复「取消」以中止\n"
        result += f"🔗 Trace ID：{trace_id}"

        return result

    def format_clarification(self, text: str, intent: dict, trace_id: str) -> str:
        clarification = intent.get("clarification", "")
        keywords = intent.get("original_keywords", [])

        result = f"❓ 需要澄清您的意图\n\n"
        result += f"📋 您的输入：「{text[:80]}」\n\n"

        if clarification:
            result += f"{clarification}\n\n"
        else:
            result += f"我无法确定您想执行的操作，请更具体地描述您的需求。\n\n"

        if keywords:
            result += f"💡 我识别到以下关键词：「{'」、「'.join(keywords[:5])}」\n\n"

        suggestions = self._generate_intent_suggestions(text, intent)
        if suggestions:
            result += f"📝 推荐操作：\n"
            for s in suggestions[:4]:
                result += f"  • {s}\n"
            result += "\n"

        result += f"🔗 Trace ID：{trace_id}"
        return result

    def format_chain_request(self, text: str, intent: dict, trace_id: str) -> str:
        chain = intent.get("chain_request", {})
        sub_requests = chain.get("sub_requests", [])

        result = f"🔗 检测到链式请求\n\n"
        result += f"📋 您的请求包含多个操作，需要分别评估：\n\n"

        for i, sub in enumerate(sub_requests, 1):
            action_cn = {"read": "读取", "write": "写入", "delete": "删除",
                         "export": "导出", "share": "分享"}.get(sub.get("action", "unknown"), "操作")
            resource_cn = {"document": "文档", "bitable": "表格", "contact": "通讯录",
                           "calendar": "日程"}.get(sub.get("resource", "unknown"), "数据")
            result += f"  {i}️⃣ {action_cn}{resource_cn}：「{sub['text'][:40]}」\n"

        result += f"\n⚠️ 每个子操作都需要独立权限验证\n"
        result += f"🔗 Trace ID：{trace_id}"
        return result

    def format_duplicate_warning(self, text: str, intent: dict,
                                  duplicate_info: dict, trace_id: str) -> str:
        count = duplicate_info.get("count", 1)
        result = f"🔄 重复请求提醒\n\n"
        result += f"📋 您已第 {count} 次提交相同请求\n"

        if count >= 3:
            result += f"⚠️ 同一请求超过3次，已标记为异常行为\n"
            result += f"🔒 您的会话风险等级已提升\n"
        elif count == 2:
            result += f"💡 该请求已处理或处理失败，请检查之前的回复\n"

        result += f"🔗 Trace ID：{trace_id}"
        return result

    def format_delayed_execution(self, text: str, intent: dict,
                                  risk_score: float, trace_id: str) -> str:
        keywords = intent.get("original_keywords", [])
        keywords_str = "」、「".join(keywords[:3]) if keywords else "该操作"

        result = f"⏰ 操作已延迟执行\n\n"
        result += f"📋 您的请求：「{self._extract_user_quote(text)}」\n"
        result += f"📊 风险评分：{int(risk_score)}/100\n\n"
        result += f"🌙 当前为非工作时间（22:00-7:00），高风险操作将延迟到工作时间处理\n"
        result += f"📅 预计执行时间：明天 7:00 后自动重新评估\n"
        result += f"💡 如需紧急处理，请联系 IT 安全部门获取临时授权\n"
        result += f"🔗 Trace ID：{trace_id}"
        return result

    def _extract_user_quote(self, text: str) -> str:
        if len(text) <= 60:
            return text
        return text[:57] + "..."

    def _extract_agents_from_intent(self, intent: dict) -> dict:
        resource = intent.get("resource", "unknown")
        action = intent.get("action", "unknown")
        agents = {}

        if resource in ("document", "wiki", "drive"):
            caps = ["lark:doc:write"] if action in ("write", "delete") else ["lark:doc:read"]
            agents["DocAgent"] = caps
            if resource in ("bitable",) or action in ("read", "export"):
                agents["DataAgent"] = ["lark:bitable:read"]
        elif resource in ("bitable", "contact", "calendar", "task", "approval", "salary", "customer", "finance"):
            caps = []
            if action in ("read", "export"):
                caps = ["lark:bitable:read"]
            elif action in ("write",):
                caps = ["lark:bitable:write"]
            elif action in ("delete",):
                caps = ["lark:bitable:write"]
            if resource == "contact":
                caps = ["lark:contact:read"]
            agents["DataAgent"] = caps
        elif resource == "unknown" and action != "unknown":
            agents["主控Agent"] = ["安全网关"]

        return agents

    def _risk_level_label(self, score: float) -> str:
        if score >= 81:
            return "🔴 严重"
        elif score >= 61:
            return "🟠 高"
        elif score >= 31:
            return "🟡 中"
        else:
            return "🟢 低"

    def _make_specific_deny_reason(self, text: str, intent: dict,
                                    deny_reason: str, detection: dict = None) -> str:
        resource = intent.get("resource", "unknown")
        scope = intent.get("scope", "self")
        action = intent.get("action", "unknown")
        keywords = intent.get("original_keywords", [])

        reasons = []

        if scope in ("cross_department", "company"):
            dept_match = re.search(r"(财务部|技术部|市场部|销售部|HR|法务部)", text)
            dept = dept_match.group(1) if dept_match else "其他部门"
            reasons.append(f"跨部门访问{dept}数据需要直属主管确认")

        if resource == "salary":
            reasons.append("薪资/绩效数据属于 LEVEL 3 受限资源，需专用 HR Agent 处理")

        if resource == "contact" and scope in ("company", "cross_department"):
            reasons.append("批量读取通讯录需要数据所有者授权")

        if action == "delete":
            reasons.append("删除操作需要二次确认和主管审批")

        if action == "export" and scope in ("company", "cross_department"):
            reasons.append("全量数据导出违反最小权限原则")

        if detection:
            categories = detection.get("threat_categories", [])
            for cat in categories[:2]:
                reasons.append(f"安全检测：{cat.get('label', '未知威胁')}")

        if not reasons:
            if deny_reason:
                return deny_reason
            reasons.append(f"访问「{'」、「'.join(keywords[:2])}」超出当前权限范围")

        return "；".join(reasons)

    def _infer_deny_reason(self, text: str, intent: dict) -> str:
        resource = intent.get("resource", "unknown")
        scope = intent.get("scope", "self")
        action = intent.get("action", "unknown")
        keywords = intent.get("original_keywords", [])

        if resource == "salary":
            return "薪资数据属于 LEVEL 3 受限资源，当前无权访问"
        if scope == "company" and action in ("export", "read"):
            return f"全量读取/导出「{'」、「'.join(keywords[:2])}」需要审批"
        if scope == "cross_department":
            return "跨部门数据访问需要业务理由和主管确认"
        if action == "delete":
            return "删除操作需要二次确认"
        return f"访问「{'」、「'.join(keywords[:2])}」超出当前权限范围"

    def _generate_alternatives(self, text: str, intent: dict) -> list:
        alternatives = []
        resource = intent.get("resource", "unknown")
        scope = intent.get("scope", "self")
        action = intent.get("action", "unknown")
        keywords = intent.get("original_keywords", [])

        if scope in ("company", "cross_department"):
            alternatives.append(f"降低范围：仅查看您自己部门的{keywords[0] if keywords else '数据'}，无需审批")

        alternatives.append(f"走审批流程：提交数据访问申请，2个工作日内审批")

        if resource == "salary":
            alternatives.append("联系 HR 部门：通过专用 HR Agent 获取授权后访问薪资数据")
        elif resource == "contact":
            alternatives.append("联系数据所有者：直接联系部门负责人获取授权")
        else:
            alternatives.append(f"联系数据所有者：直接联系「{keywords[0] if keywords else '相关'}」负责人获取授权")

        return alternatives[:3]

    def _determine_detection_layer(self, scan_result: dict, detection: dict) -> str:
        layers = []
        if scan_result:
            scan_layers = scan_result.get("layers", {})
            if scan_layers.get("keyword_regex"):
                layers.append("第1层-关键词正则")
            if scan_layers.get("semantic_rules"):
                layers.append("第2层-语义规则")
            if scan_layers.get("encoding_bypass"):
                layers.append("第3层-编码绕过")
        if detection:
            details = detection.get("details", {})
            if details.get("semantic_matches"):
                layers.append("第4层-语义相似度")
            if details.get("implicit_matches"):
                layers.append("第5层-隐含模式")
            if details.get("ngram_matches"):
                layers.append("第6层-N-gram")

        if not layers:
            return "安全检测层"
        return " → ".join(layers)

    def _sanitize_content(self, text: str) -> str:
        sanitized = text[:60]
        sanitized = re.sub(r"(忽略|ignore|forget|删除|drop|管理员|admin|root|绕过|bypass)", "***", sanitized, flags=re.IGNORECASE)
        if len(text) > 60:
            sanitized += "..."
        return sanitized

    def _explain_risk_factors(self, text: str, intent: dict) -> list:
        factors = []
        risk_keywords = intent.get("risk_keywords", {})
        scope = intent.get("scope", "self")
        resource = intent.get("resource", "unknown")
        action = intent.get("action", "unknown")

        if risk_keywords.get("high"):
            factors.append(f"包含高风险词：「{'」、「'.join(risk_keywords['high'][:3])}」")
        if risk_keywords.get("medium"):
            factors.append(f"包含敏感词：「{'」、「'.join(risk_keywords['medium'][:3])}」")
        if scope == "cross_department":
            factors.append("涉及跨部门数据访问")
        if scope == "company":
            factors.append("涉及全公司范围数据")
        if resource == "salary":
            factors.append("薪资/绩效数据属于高度敏感信息")
        if action == "delete":
            factors.append("删除操作不可逆，需要额外确认")
        if action == "export" and scope in ("company", "cross_department"):
            factors.append("批量数据导出存在泄露风险")

        return factors[:5]

    def _generate_intent_suggestions(self, text: str, intent: dict) -> list:
        suggestions = []
        action = intent.get("action", "unknown")
        resource = intent.get("resource", "unknown")
        keywords = intent.get("original_keywords", [])

        resource_suggestions = {
            "contact": ["查看企业通讯录", "搜索特定联系人", "查看部门人员列表"],
            "bitable": ["查询多维表格数据", "查看销售数据汇总", "读取项目进度表"],
            "document": ["创建飞书文档", "查看最近文档", "生成工作报告"],
            "calendar": ["查看今日日程安排", "查看本周会议", "创建新会议"],
            "task": ["查看待办任务列表", "创建新任务", "查看项目进度"],
            "approval": ["查看待审批流程", "提交请假申请", "查看审批记录"],
            "salary": ["查看我的薪资信息", "生成绩效报告", "查看考核结果"],
            "customer": ["查看客户数据", "搜索客户信息", "查看CRM数据"],
            "finance": ["查看财务数据", "生成营收报告", "查看收支明细"],
            "wiki": ["搜索知识库", "查看操作手册", "查看最佳实践"],
            "drive": ["查看云盘文件", "上传文件", "查看共享文档"],
        }

        action_suggestions = {
            "read": ["查询企业数据", "查看我的信息", "搜索文档资料"],
            "write": ["创建新文档", "生成工作报告", "写入数据记录"],
            "delete": ["删除过期文档", "清理测试数据"],
            "export": ["导出部门数据报告", "下载数据汇总", "备份数据"],
            "share": ["分享文档给团队", "共享数据报告"],
        }

        if resource in resource_suggestions:
            suggestions.extend(resource_suggestions[resource][:2])

        if action in action_suggestions:
            for s in action_suggestions[action]:
                if s not in suggestions:
                    suggestions.append(s)
                    break

        if keywords:
            for kw in keywords[:2]:
                suggestions.append(f"搜索与「{kw}」相关的内容")

        if not suggestions:
            suggestions = ["查看企业通讯录", "生成季度销售报告", "查询多维表格数据", "查看日程安排"]

        return suggestions[:4]
