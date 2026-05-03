from datetime import datetime
from core.response_engine import ResponseEngine


class ResponseFormatter(ResponseEngine):

    def format_security_response(self, trace_id: str, risk_score: float, agent_chain: str, content: str) -> str:
        if risk_score >= 90:
            level = "⛔ 已拦截"
        elif risk_score >= 70:
            level = "🔴 高风险"
        elif risk_score >= 40:
            level = "🟡 关注"
        else:
            level = "🟢 安全"
        ts = datetime.now().strftime("%H:%M:%S")
        return (
            f"🔒 AgentPass 安全响应\n\n"
            f"📋 Trace ID: {trace_id}\n"
            f"⚡ 风险评分: {risk_score}/100 [{level}]\n"
            f"🔄 执行路径: {agent_chain}\n\n"
            f"{content}\n\n"
            f"─────────────────\n"
            f"📊 审计：已记录 | 🕐 {ts}"
        )
