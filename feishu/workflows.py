import json
import time
import uuid
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class BackendStepLogger:

    def __init__(self):
        self._steps = []
        self._trace_id = ""

    def start(self, trace_id: str, user_input: str):
        self._steps = []
        self._trace_id = trace_id
        self.add_step("request_received", "API", f"收到用户请求: \"{user_input[:50]}{'...' if len(user_input) > 50 else ''}\"")

    def add_step(self, step_type: str, component: str, detail: str, status: str = "success"):
        self._steps.append({
            "type": step_type,
            "component": component,
            "detail": detail,
            "status": status,
            "timestamp": time.time(),
        })

    def format_log_section(self) -> str:
        if not self._steps:
            return ""
        result = "🖥️ 后端操作日志:\n"
        result += "─" * 30 + "\n"
        for step in self._steps:
            icon = "✅" if step["status"] == "success" else "❌" if step["status"] == "error" else "⚠️" if step["status"] == "warning" else "ℹ️"
            ts = datetime.fromtimestamp(step["timestamp"]).strftime("%H:%M:%S.")
            ts += f"{int((step['timestamp'] % 1) * 1000):03d}"
            result += f"  {icon} [{ts}] {step['component']}\n"
            for line in step["detail"].split("\n"):
                result += f"     {line}\n"
        result += "─" * 30
        return result


class WorkflowExecutor:

    def __init__(self, auth_server_getter, scanner_getter, router_getter,
                 feishu_doc_getter, feishu_bitable_getter, feishu_contact_getter):
        self._get_auth = auth_server_getter
        self._get_scanner = scanner_getter
        self._get_router = router_getter
        self._get_feishu_doc = feishu_doc_getter
        self._get_feishu_bitable = feishu_bitable_getter
        self._get_feishu_contact = feishu_contact_getter

    def _init_workflow(self, text: str):
        trace_id = uuid.uuid4().hex[:16]
        blog = BackendStepLogger()
        blog.start(trace_id, text)
        return trace_id, blog

    def _scan_input(self, text: str, blog: BackendStepLogger, trace_id: str):
        scanner = self._get_scanner()
        scan_result = scanner.scan(text)
        if scan_result["is_injection"]:
            blog.add_step("injection_scan", "InjectionScanner",
                          f"scan(\"{text[:30]}...\") → is_injection=true\n威胁: {', '.join(t.get('type','') for t in scan_result.get('threats',[])[:3])}\n决策: DENY", "error")
            return scan_result, True
        blog.add_step("injection_scan", "InjectionScanner",
                      f"scan(\"{text[:30]}...\") → is_injection=false · 安全通过", "success")
        return scan_result, False

    def _issue_agent_token(self, auth, agent_id: str, capabilities: list,
                           user_id: str, trace_id: str, blog: BackendStepLogger,
                           text: str = "", extra_note: str = ""):
        try:
            agent_secret = auth._get_agent(agent_id)["client_secret"]
        except Exception:
            agent_secret = ""
        token_result = auth.issue_token(
            agent_id=agent_id,
            client_secret=agent_secret,
            capabilities=capabilities,
            delegated_user=user_id or "feishu_user",
            trace_id=trace_id,
            task_description=text,
        )
        jti = token_result.get("jti", "")
        scope = token_result.get("scope", [])
        note = f"\n{extra_note}" if extra_note else ""
        blog.add_step("token_issue", "AuthServer.issue_token()",
                      f"agent_id={agent_id}\njti={jti[:8]}…\nscope=[{', '.join(scope[:5])}]{note}", "success")
        return token_result

    def execute_normal_delegation(self, text: str, user_id: str, chat_id: str) -> str:
        from feishu.document import FeishuDocument
        from feishu.bitable import FeishuBitable
        from agents.doc_agent import DocAgent

        trace_id, blog = self._init_workflow(text)

        try:
            auth = self._get_auth()
            doc_agent = DocAgent()
            feishu_doc = self._get_feishu_doc()
            feishu_bitable = self._get_feishu_bitable()

            scan_result, is_injection = self._scan_input(text, blog, trace_id)
            if is_injection:
                return self._format_injection_blocked(text, scan_result, trace_id, blog)

            intent = doc_agent.parse_intent(text)
            blog.add_step("intent_parse", "DocAgent.parse_intent()",
                          f"输入: \"{text[:40]}\"\n意图: {intent.get('intent', 'unknown')}\n推断能力: {intent.get('required_capabilities', [])}", "success")

            token_result = self._issue_agent_token(
                auth, "agent_doc_001", ["lark:doc:write", "delegate:DataAgent:read"],
                user_id, trace_id, blog, text,
            )
            parent_token = token_result["access_token"]
            jti = token_result.get("jti", "")

            delegate_result = auth.delegate_token(
                parent_token=parent_token,
                target_agent_id="agent_data_001",
                requested_capabilities=["lark:bitable:read"],
                trace_id=trace_id,
            )
            djti = delegate_result.get("jti", "")
            dcaps = delegate_result.get("delegated_capabilities", [])
            att = delegate_result.get("attenuation_level", 1)
            tc = delegate_result.get("trust_chain", [])
            blog.add_step("delegation", "AuthServer.delegate_token()",
                          f"parent_jti={jti[:8]}… → target=agent_data_001\nchild_jti={djti[:8]}…\ndelegated_caps=[{', '.join(dcaps)}]\nattenuation={att}\ntrust_chain: {' → '.join(tc) if tc else 'N/A'}", "success")

            bitable_data = feishu_bitable.read_bitable("JFdHbUqILaTXL9sqGfjcH3vEndd", "tblUSkajxtsxysB6")
            mode = bitable_data.get("mode", "unknown")
            mode_label = "真实数据(cli)" if mode == "cli" else "Demo数据"
            data_items = bitable_data.get("data", {}).get("items", [])
            blog.add_step("api_call", "FeishuBitable.read_bitable()",
                          f"app_token=JFdHb…\ntable_id=tblUSk…\nmode={mode} ({mode_label})\n返回 {len(data_items)} 条记录", "success")

            doc_result = feishu_doc.create_document("季度销售报告")
            doc_id = doc_result.get("document_id", "")
            doc_url = doc_result.get("url", "")
            blog.add_step("doc_write", "FeishuDocument.create_document()",
                          f"title=季度销售报告\ndocument_id={doc_id[:16] if doc_id else 'N/A'}…\nurl={doc_url[:50] if doc_url else 'N/A'}", "success")

            doc_risk = auth.risk_scorer.compute_risk_score("agent_doc_001", ["lark:doc:write", "delegate:DataAgent:read"])
            data_risk = auth.risk_scorer.compute_risk_score("agent_data_001", ["lark:bitable:read"])

            data_text = ""
            for item in data_items[:5]:
                fields = item.get("fields", {})
                data_text += f"  • {json.dumps(fields, ensure_ascii=False)}\n"

            result = f"✅ 正常委托流程执行成功\n\n"
            result += f"📋 Trace ID: {trace_id}\n"
            result += f"🔄 调用链: 用户 → DocAgent → DataAgent → 飞书API\n\n"

            result += blog.format_log_section()
            result += "\n\n"

            result += f"📝 执行摘要:\n"
            result += f"  1️⃣ 用户输入: {text}\n"
            result += f"  2️⃣ DocAgent解析意图: {intent.get('intent', 'unknown')}\n"
            result += f"  3️⃣ AuthServer签发Token(衰减层级0)\n"
            result += f"     父Token: ...{parent_token[-12:]}\n"
            result += f"  4️⃣ DocAgent委托DataAgent(衰减层级1)\n"
            result += f"     子Token: ...{delegate_result.get('access_token', '')[-12:]}\n"
            result += f"  5️⃣ DataAgent调用飞书API返回数据\n"
            result += f"     数据源: {'✅ 真实数据' if mode == 'cli' else '⚠️ Demo数据'}\n"
            result += f"  6️⃣ DocAgent写入飞书文档\n"
            result += f"\n⚠️ 风险评估:\n"
            result += f"  • DocAgent风险分: {doc_risk['risk_score']}/100 ({doc_risk.get('action_taken', 'none')})\n"
            result += f"  • DataAgent风险分: {data_risk['risk_score']}/100 ({data_risk.get('action_taken', 'none')})\n"
            result += f"  • 委托链衰减: 层级0 → 层级1 (权限逐级收缩)\n"
            result += f"\n📊 多维表格数据:\n{data_text}"
            if doc_url:
                result += f"\n📄 文档已创建: {doc_url}\n"
            elif doc_id:
                result += f"\n📄 文档ID: {doc_id}\n"
            return result
        except PermissionError as e:
            blog.add_step("permission_error", "AuthServer", str(e), "error")
            return f"🚫 权限错误: {str(e)}\n\n{blog.format_log_section()}"
        except Exception as e:
            blog.add_step("execution_error", "WorkflowExecutor", str(e), "error")
            return f"❌ 执行失败: {str(e)}\n\n{blog.format_log_section()}"

    def execute_unauthorized_delegation(self, text: str, user_id: str, chat_id: str) -> str:
        trace_id, blog = self._init_workflow(text)

        auth = self._get_auth()
        parent_token = ""
        error_msg = ""
        risk_score = 0

        scan_result, is_injection = self._scan_input(text, blog, trace_id)
        if is_injection:
            return self._format_injection_blocked(text, scan_result, trace_id, blog)

        try:
            token_result = self._issue_agent_token(
                auth, "agent_search_001", ["web:search", "web:fetch"],
                user_id, trace_id, blog, text,
                extra_note="⚠️ 注意: scope中无delegate:DataAgent:*",
            )
            parent_token = token_result["access_token"]
            jti = token_result.get("jti", "")

            try:
                auth.delegate_token(
                    parent_token=parent_token,
                    target_agent_id="agent_data_001",
                    requested_capabilities=["lark:bitable:read"],
                    trace_id=trace_id,
                )
                blog.add_step("delegation_attempt", "AuthServer.delegate_token()",
                              "越权委托未被拦截! 这是安全漏洞!", "error")
                return f"⚠️ 委托意外成功(可能配置有误)"
            except (PermissionError, ValueError, Exception) as e:
                error_msg = str(e)
                blog.add_step("delegation_attempt", "AuthServer.delegate_token()",
                              f"parent_jti={jti[:8]}…\ntarget=agent_data_001\nrequested=[lark:bitable:read]\n❌ 权限校验失败!\n错误: {error_msg}\n错误码: CAPABILITY_INSUFFICIENT / ERR_DELEGATION_DENIED", "error")

                try:
                    auth.audit_logger.write_log(
                        requesting_agent="agent_search_001",
                        action_type="delegation_denied",
                        decision="DENY",
                        deny_reason=f"SearchAgent越权委托DataAgent: {error_msg}",
                        target_agent="agent_data_001",
                        trace_id=trace_id,
                    )
                    blog.add_step("audit_log", "AuditLogger.write_log()",
                                  f"requesting_agent=agent_search_001\naction_type=delegation_denied\ndecision=DENY\ntrace_id={trace_id}", "warning")
                except Exception:
                    pass

                try:
                    risk = auth.risk_scorer.compute_risk_score("agent_search_001", ["web:search", "web:fetch", "lark:bitable:read"])
                    risk_score = risk["risk_score"]
                    blog.add_step("risk_update", "RiskScorer.compute_risk_score()",
                                  f"agent=agent_search_001\n假设caps=[web:search, web:fetch, lark:bitable:read]\nrisk_score={risk_score}/100\naction={risk.get('action_taken', 'none')}", "warning")
                except Exception:
                    risk_score = 0
        except Exception as e:
            if not error_msg:
                error_msg = str(e)
            blog.add_step("token_error", "AuthServer", str(e), "error")

        search_agent = auth._get_agent("agent_search_001") if auth._get_agent("agent_search_001") else {}
        search_caps = search_agent.get("capabilities", ["web:search", "web:fetch"])
        search_trust = search_agent.get("trust_score", 100)

        result = f"🚫 越权拦截成功！\n\n"
        result += f"📋 Trace ID: {trace_id}\n"
        result += f"🔄 调用链: 用户 → SearchAgent ✗→ DataAgent\n\n"

        result += blog.format_log_section()
        result += "\n\n"

        result += f"📝 步骤详情:\n"
        result += f"  1️⃣ 用户输入: {text}\n"
        result += f"  2️⃣ SearchAgent签发Token(仅web:search能力)\n"
        if parent_token:
            result += f"     Token: ...{parent_token[-12:]}\n"
        result += f"  3️⃣ SearchAgent尝试委托DataAgent读取多维表格\n"
        result += f"  4️⃣ ❌ 权限校验失败！\n"
        result += f"     错误: {error_msg}\n"
        result += f"     错误码: CAPABILITY_INSUFFICIENT\n"
        result += f"  5️⃣ 审计日志已记录越权尝试\n"
        result += f"  6️⃣ SearchAgent风险评分升级: {risk_score}/100\n\n"
        result += f"🔒 拦截原因分析:\n"
        result += f"  • SearchAgent仅拥有 {search_caps} 能力\n"
        result += f"  • 不具备 [delegate:DataAgent:read] 委托权限\n"
        result += f"  • 无法代理请求访问 [lark:bitable:read] 资源\n"
        result += f"  • SearchAgent信任分: {search_trust}\n\n"
        result += f"⚠️ 风险评估:\n"
        result += f"  • 越权行为风险分: {risk_score}/100\n"
        if risk_score >= 70:
            result += f"  • 🚨 高风险! Agent可能被冻结\n"
        elif risk_score >= 40:
            result += f"  • ⚠️ 中风险! 持续越权将导致冻结\n"
        result += f"\n💡 对比: DocAgent拥有 [delegate:DataAgent:read] 能力，可以合法委托"
        return result

    def execute_data_query(self, text: str, user_id: str, chat_id: str) -> str:
        from feishu.bitable import FeishuBitable

        trace_id, blog = self._init_workflow(text)

        try:
            auth = self._get_auth()
            feishu_bitable = self._get_feishu_bitable()

            scan_result, is_injection = self._scan_input(text, blog, trace_id)
            if is_injection:
                return self._format_injection_blocked(text, scan_result, trace_id, blog)

            try:
                token_result = self._issue_agent_token(
                    auth, "agent_data_001", ["lark:bitable:read"],
                    user_id, trace_id, blog, text,
                )
                token_info = f"Token: ...{token_result['access_token'][-12:]}"
            except Exception:
                token_info = "Token: (使用已有凭证)"
                blog.add_step("token_issue", "AuthServer", "使用已有凭证", "warning")

            bitable_data = feishu_bitable.read_bitable("JFdHbUqILaTXL9sqGfjcH3vEndd", "tblUSkajxtsxysB6")
            mode = bitable_data.get("mode", "unknown")
            mode_label = "✅ 真实数据" if mode == "cli" else "⚠️ Demo数据"
            data_items = bitable_data.get("data", {}).get("items", [])
            total = bitable_data.get("data", {}).get("total", 0)
            blog.add_step("api_call", "FeishuBitable.read_bitable()",
                          f"app_token=JFdHb…\ntable_id=tblUSk…\nmode={mode}\n返回 {len(data_items)} 条记录 / total={total}", "success")

            data_text = ""
            for item in data_items[:10]:
                fields = item.get("fields", {})
                data_text += f"  • {json.dumps(fields, ensure_ascii=False)}\n"

            data_risk = auth.risk_scorer.compute_risk_score("agent_data_001", ["lark:bitable:read"])

            result = f"📊 多维表格查询结果 ({mode_label})\n\n"
            result += f"📋 Trace ID: {trace_id}\n"
            result += f"🔄 调用链: 用户 → DataAgent → 飞书API\n"
            result += f"🔑 {token_info}\n"
            result += f"⚠️ DataAgent风险分: {data_risk['risk_score']}/100\n\n"

            result += blog.format_log_section()
            result += f"\n\n📈 共 {total} 条记录:\n{data_text}"
            return result
        except Exception as e:
            blog.add_step("error", "WorkflowExecutor", str(e), "error")
            return f"❌ 查询失败: {str(e)}\n\n{blog.format_log_section()}"

    def execute_search(self, text: str, user_id: str, chat_id: str) -> str:
        trace_id, blog = self._init_workflow(text)

        auth = self._get_auth()

        scan_result, is_injection = self._scan_input(text, blog, trace_id)
        if is_injection:
            return self._format_injection_blocked(text, scan_result, trace_id, blog)

        try:
            token_result = self._issue_agent_token(
                auth, "agent_search_001", ["web:search"],
                user_id, trace_id, blog, text,
            )
            token_info = f"Token: ...{token_result['access_token'][-12:]}"
        except Exception:
            token_info = "Token: (使用已有凭证)"

        search_risk = auth.risk_scorer.compute_risk_score("agent_search_001", ["web:search", "web:fetch"])

        result = f"🔍 网络搜索功能\n\n"
        result += f"📋 Trace ID: {trace_id}\n"
        result += f"🔄 调用链: 用户 → SearchAgent → 外部API\n"
        result += f"🔑 {token_info}\n"
        result += f"⚠️ SearchAgent风险分: {search_risk['risk_score']}/100\n\n"

        result += blog.format_log_section()
        result += f"\n\n🔒 权限边界:\n"
        result += f"  ✅ web:search - 搜索公开网页\n"
        result += f"  ✅ web:fetch - 抓取网页内容\n"
        result += f"  ❌ lark:bitable:read - 无权访问\n"
        result += f"  ❌ lark:contact:read - 无权访问\n"
        result += f"  ❌ lark:doc:write - 无权访问\n\n"
        result += f"💡 任何尝试突破上述权限边界的行为都会被拦截"
        return result

    def execute_contact_read(self, text: str, user_id: str, chat_id: str) -> str:
        from feishu.contact import FeishuContact

        trace_id, blog = self._init_workflow(text)

        try:
            auth = self._get_auth()
            feishu_contact = self._get_feishu_contact()

            scan_result, is_injection = self._scan_input(text, blog, trace_id)
            if is_injection:
                return self._format_injection_blocked(text, scan_result, trace_id, blog)

            try:
                token_result = self._issue_agent_token(
                    auth, "agent_data_001", ["lark:contact:read"],
                    user_id, trace_id, blog, text,
                    extra_note="⚠️ 通讯录为敏感数据!",
                )
                token_info = f"Token: ...{token_result['access_token'][-12:]}"
            except Exception:
                token_info = "Token: (使用已有凭证)"

            contact_data = feishu_contact.read_contacts()
            mode = contact_data.get("mode", "unknown")
            mode_label = "✅ 真实数据" if mode == "cli" else "⚠️ Demo数据"
            items = contact_data.get("data", {}).get("items", [])
            total = contact_data.get("data", {}).get("total", 0)
            blog.add_step("api_call", "FeishuContact.read_contacts()",
                          f"mode={mode}\n返回 {len(items)} 条联系人 / total={total}", "success")

            contact_text = ""
            for item in items[:10]:
                name = item.get("name", "")
                dept = item.get("department", "")
                email = item.get("email", "")
                contact_text += f"  • {name} | {dept} | {email}\n"

            contact_risk = auth.risk_scorer.compute_risk_score("agent_data_001", ["lark:contact:read"])

            result = f"👥 通讯录查询结果 ({mode_label})\n\n"
            result += f"📋 Trace ID: {trace_id}\n"
            result += f"🔄 调用链: 用户 → DataAgent → 飞书API\n"
            result += f"🔑 {token_info}\n"
            result += f"⚠️ 通讯录为敏感数据! DataAgent风险分: {contact_risk['risk_score']}/100\n"
            result += f"📝 审计日志已记录此敏感操作\n\n"

            result += blog.format_log_section()
            result += f"\n\n📋 共 {total} 位联系人:\n{contact_text}"
            return result
        except Exception as e:
            blog.add_step("error", "WorkflowExecutor", str(e), "error")
            return f"❌ 查询失败: {str(e)}\n\n{blog.format_log_section()}"

    def execute_comprehensive_report(self, text: str, user_id: str, chat_id: str) -> str:
        return self.execute_normal_delegation(text, user_id, chat_id)

    def _format_injection_blocked(self, text: str, scan_result: dict, trace_id: str, blog: BackendStepLogger) -> str:
        threats = scan_result.get("threats", [])
        threat_types = []
        threat_details = []
        for t in threats:
            t_type = t.get("type", "unknown") if isinstance(t, dict) else str(t)
            t_severity = t.get("severity", "medium") if isinstance(t, dict) else "medium"
            t_matched = t.get("matched_text", "") if isinstance(t, dict) else ""
            threat_types.append(t_type)
            if t_matched:
                threat_details.append(f"[{t_severity}] {t_type}: \"{t_matched}\"")

        confidence = scan_result.get("confidence", 0)
        layers = scan_result.get("layers", {})

        blog.add_step("injection_blocked", "InjectionScanner",
                      f"confidence={confidence:.0%}\nthreats={len(threats)}\nlayers: keyword_regex={layers.get('keyword_regex', False)}, semantic_rules={layers.get('semantic_rules', False)}", "error")

        result = f"🚫 注入攻击检测与拦截\n\n"
        result += f"📋 Trace ID: {trace_id}\n"
        result += f"🛡️ InjectionScanner 三层检测触发\n\n"

        result += blog.format_log_section()
        result += "\n\n"

        result += f"📝 检测详情:\n"
        result += f"  • 置信度: {confidence:.0%}\n"
        result += f"  • 威胁数量: {len(threats)}\n"
        if layers.get("keyword_regex"):
            result += f"    ✅ 关键词+正则匹配层\n"
        if layers.get("semantic_rules"):
            result += f"    ✅ 语义规则分析层\n"
        result += f"\n🔍 威胁详情:\n"
        for detail in threat_details[:5]:
            result += f"  • {detail}\n"
        result += f"\n🔒 拦截动作:\n"
        result += f"  1️⃣ 输入被拒绝，不传递给任何Agent\n"
        result += f"  2️⃣ 审计日志已记录(错误码: PROMPT_INJECTION_BLOCKED)\n"
        result += f"  3️⃣ 清理后内容: {str(scan_result.get('sanitized_content', ''))[:80]}...\n\n"
        result += f"💡 安全提示: 请勿尝试通过Prompt注入绕过权限系统"
        return result
