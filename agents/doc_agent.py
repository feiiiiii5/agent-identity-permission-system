from agents.base_agent import BaseAgent


class DocAgent(BaseAgent):

    DEFAULT_CAPABILITIES = [
        "lark:doc:write",
        "lark:doc:read",
        "delegate:DataAgent:read",
        "delegate:DataAgent:write",
        "delegate:SearchAgent:read",
    ]

    DEFAULT_SKILL_DESCRIPTIONS = [
        {"name": "write_document", "description": "创建和编辑飞书文档"},
        {"name": "read_document", "description": "读取飞书文档内容"},
        {"name": "delegate_data_read", "description": "委托DataAgent读取企业数据"},
        {"name": "delegate_data_write", "description": "委托DataAgent写入企业数据"},
        {"name": "delegate_search", "description": "委托SearchAgent搜索外部信息"},
    ]

    def __init__(self, agent_id: str = "agent_doc_001", agent_name: str = "DocAgent",
                 capabilities: list = None):
        super().__init__(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_type="doc_assistant",
            capabilities=capabilities or self.DEFAULT_CAPABILITIES,
        )
        self.skill_descriptions = self.DEFAULT_SKILL_DESCRIPTIONS

    def parse_intent(self, user_input: str) -> dict:
        text = user_input.lower()
        if any(kw in text for kw in ["报告", "汇总", "生成", "季度", "report"]):
            return {
                "intent": "generate_report",
                "required_capabilities": ["lark:doc:write", "delegate:DataAgent:read"],
                "confidence": 0.9,
            }
        if any(kw in text for kw in ["读取", "查看", "文档", "read", "doc"]):
            return {
                "intent": "read_document",
                "required_capabilities": ["lark:doc:read"],
                "confidence": 0.85,
            }
        return {
            "intent": "unknown",
            "required_capabilities": [],
            "confidence": 0.0,
        }
