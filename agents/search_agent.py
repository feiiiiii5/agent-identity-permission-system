from agents.base_agent import BaseAgent


class SearchAgent(BaseAgent):

    DEFAULT_CAPABILITIES = [
        "web:search",
        "web:fetch",
    ]

    DEFAULT_SKILL_DESCRIPTIONS = [
        {"name": "search_web", "description": "搜索互联网公开信息"},
        {"name": "fetch_web", "description": "抓取指定网页内容"},
    ]

    def __init__(self, agent_id: str = "agent_search_001", agent_name: str = "SearchAgent",
                 capabilities: list = None):
        super().__init__(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_type="search_assistant",
            capabilities=capabilities or self.DEFAULT_CAPABILITIES,
        )
        self.skill_descriptions = self.DEFAULT_SKILL_DESCRIPTIONS
