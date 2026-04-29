from agents.base_agent import BaseAgent


class DataAgent(BaseAgent):

    DEFAULT_CAPABILITIES = [
        "lark:bitable:read",
        "lark:bitable:write",
        "lark:contact:read",
        "lark:calendar:read",
    ]

    DEFAULT_SKILL_DESCRIPTIONS = [
        {"name": "read_bitable", "description": "读取多维表格数据"},
        {"name": "write_bitable", "description": "写入多维表格数据"},
        {"name": "read_contact", "description": "读取企业通讯录"},
        {"name": "read_calendar", "description": "读取日历日程"},
    ]

    def __init__(self, agent_id: str = "agent_data_001", agent_name: str = "DataAgent",
                 capabilities: list = None):
        super().__init__(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_type="data_assistant",
            capabilities=capabilities or self.DEFAULT_CAPABILITIES,
        )
        self.skill_descriptions = self.DEFAULT_SKILL_DESCRIPTIONS

    def check_sensitive_operation(self, capability: str, record_count: int = 0) -> dict:
        is_sensitive = False
        reason = ""

        if capability == "lark:contact:read" and record_count > 100:
            is_sensitive = True
            reason = f"读取通讯录记录数({record_count})超过阈值(100)"
        elif capability == "lark:bitable:write":
            is_sensitive = True
            reason = "写入多维表格属于敏感操作"

        return {
            "is_sensitive": is_sensitive,
            "reason": reason,
            "requires_human_approval": is_sensitive,
        }
