import time
import uuid
import json
from abc import ABC, abstractmethod
from typing import Optional


class AgentAdapter(ABC):

    def __init__(self, agent_id: str, agent_name: str, engine_type: str, capabilities: list):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.engine_type = engine_type
        self.capabilities = capabilities
        self.created_at = time.time()

    @abstractmethod
    def execute(self, capability: str, params: dict = None) -> dict:
        pass

    @abstractmethod
    def health_check(self) -> dict:
        pass

    def get_info(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "engine_type": self.engine_type,
            "capabilities": self.capabilities,
            "created_at": self.created_at,
            "adapter_class": self.__class__.__name__,
        }


class PythonNativeAdapter(AgentAdapter):

    def __init__(self, agent_id: str, agent_name: str, capabilities: list, agent_instance=None):
        super().__init__(agent_id, agent_name, "python_native", capabilities)
        self.agent_instance = agent_instance

    def execute(self, capability: str, params: dict = None) -> dict:
        if capability not in self.capabilities:
            return {"success": False, "error": f"Capability {capability} not supported", "error_code": "ERR_CAPABILITY_UNSUPPORTED"}

        if self.agent_instance and hasattr(self.agent_instance, "execute"):
            try:
                result = self.agent_instance.execute(capability, params or {})
                return {"success": True, "result": result, "engine": "python_native"}
            except Exception as e:
                return {"success": False, "error": str(e), "error_code": "ERR_EXECUTION_FAILED"}

        return {"success": True, "result": {"capability": capability, "params": params}, "engine": "python_native", "simulated": True}

    def health_check(self) -> dict:
        return {"healthy": True, "engine": "python_native", "agent_id": self.agent_id}


class RESTAPIAdapter(AgentAdapter):

    def __init__(self, agent_id: str, agent_name: str, capabilities: list, endpoint_url: str, auth_header: str = ""):
        super().__init__(agent_id, agent_name, "rest_api", capabilities)
        self.endpoint_url = endpoint_url
        self.auth_header = auth_header

    def execute(self, capability: str, params: dict = None) -> dict:
        if capability not in self.capabilities:
            return {"success": False, "error": f"Capability {capability} not supported", "error_code": "ERR_CAPABILITY_UNSUPPORTED"}

        return {
            "success": True,
            "result": {
                "capability": capability,
                "params": params,
                "endpoint": self.endpoint_url,
                "note": "REST API adapter - in production, this would make HTTP calls",
            },
            "engine": "rest_api",
            "simulated": True,
        }

    def health_check(self) -> dict:
        return {"healthy": True, "engine": "rest_api", "agent_id": self.agent_id, "endpoint": self.endpoint_url}


class LLMFunctionCallingAdapter(AgentAdapter):

    def __init__(self, agent_id: str, agent_name: str, capabilities: list, model_name: str = "gpt-4", tool_definitions: list = None):
        super().__init__(agent_id, agent_name, "llm_function_calling", capabilities)
        self.model_name = model_name
        self.tool_definitions = tool_definitions or []

    def execute(self, capability: str, params: dict = None) -> dict:
        if capability not in self.capabilities:
            return {"success": False, "error": f"Capability {capability} not supported", "error_code": "ERR_CAPABILITY_UNSUPPORTED"}

        return {
            "success": True,
            "result": {
                "capability": capability,
                "params": params,
                "model": self.model_name,
                "tools_available": len(self.tool_definitions),
                "note": "LLM Function Calling adapter - in production, this would invoke LLM with tool definitions",
            },
            "engine": "llm_function_calling",
            "simulated": True,
        }

    def health_check(self) -> dict:
        return {"healthy": True, "engine": "llm_function_calling", "agent_id": self.agent_id, "model": self.model_name}


class AgentAdapterManager:

    ENGINE_TYPES = {
        "python_native": {"name": "Python Native", "description": "本地 Python Agent，直接函数调用"},
        "rest_api": {"name": "REST API", "description": "远程 REST API Agent，通过 HTTP 调用"},
        "llm_function_calling": {"name": "LLM Function Calling", "description": "大模型函数调用 Agent，通过 LLM 工具调用"},
    }

    def __init__(self):
        self._adapters: dict[str, AgentAdapter] = {}

    def register_adapter(self, adapter: AgentAdapter) -> dict:
        self._adapters[adapter.agent_id] = adapter
        return {
            "agent_id": adapter.agent_id,
            "agent_name": adapter.agent_name,
            "engine_type": adapter.engine_type,
            "capabilities": adapter.capabilities,
            "status": "registered",
        }

    def get_adapter(self, agent_id: str) -> Optional[AgentAdapter]:
        return self._adapters.get(agent_id)

    def execute_capability(self, agent_id: str, capability: str, params: dict = None) -> dict:
        adapter = self._adapters.get(agent_id)
        if not adapter:
            return {"success": False, "error": f"Adapter for {agent_id} not found", "error_code": "ERR_ADAPTER_NOT_FOUND"}
        return adapter.execute(capability, params)

    def health_check_all(self) -> dict:
        results = {}
        for aid, adapter in self._adapters.items():
            results[aid] = adapter.health_check()
        return {
            "total_adapters": len(self._adapters),
            "engine_types": list(set(a.engine_type for a in self._adapters.values())),
            "health_results": results,
        }

    def list_adapters(self) -> list:
        return [a.get_info() for a in self._adapters.values()]

    def get_engine_types(self) -> dict:
        return self.ENGINE_TYPES


def create_default_adapters() -> AgentAdapterManager:
    manager = AgentAdapterManager()

    manager.register_adapter(PythonNativeAdapter(
        agent_id="agent_doc_001",
        agent_name="DocAgent",
        capabilities=["lark:doc:write", "lark:doc:read", "delegate:DataAgent:read", "delegate:DataAgent:write", "delegate:SearchAgent:read"],
    ))

    manager.register_adapter(RESTAPIAdapter(
        agent_id="agent_data_001",
        agent_name="DataAgent",
        capabilities=["lark:bitable:read", "lark:bitable:write", "lark:contact:read", "lark:calendar:read"],
        endpoint_url="https://api.feishu.cn/agent/data",
    ))

    manager.register_adapter(LLMFunctionCallingAdapter(
        agent_id="agent_search_001",
        agent_name="SearchAgent",
        capabilities=["web:search", "web:fetch"],
        model_name="gpt-4",
        tool_definitions=[
            {"name": "web_search", "description": "Search the internet"},
            {"name": "web_fetch", "description": "Fetch a web page"},
        ],
    ))

    return manager
