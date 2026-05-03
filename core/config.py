import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


_BASE_DIR = Path(__file__).parent.parent
_DATA_DIR = _BASE_DIR / "data"
_REPORTS_DIR = _BASE_DIR / "reports"
_FRONTEND_DIR = _BASE_DIR / "frontend"


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    log_level: str = "info"
    cors_origins: list = field(default_factory=lambda: ["http://localhost:8000", "http://127.0.0.1:8000"])
    max_request_size: int = 10 * 1024 * 1024
    request_timeout: float = 30.0
    graceful_shutdown_timeout: float = 15.0


@dataclass
class DatabaseConfig:
    path: str = ""
    busy_timeout: int = 5000
    journal_mode: str = "WAL"
    connection_timeout: float = 10.0
    max_connections: int = 20
    cleanup_interval_seconds: int = 3600

    def __post_init__(self):
        if not self.path:
            _DATA_DIR.mkdir(exist_ok=True)
            self.path = str(_DATA_DIR / "agentiam.db")


@dataclass
class TokenConfig:
    default_ttl_seconds: int = 3600
    max_ttl_seconds: int = 86400
    human_approval_ttl_seconds: int = 300
    human_approval_timeout_seconds: int = 30
    auto_cleanup_expired: bool = True
    cleanup_interval_seconds: int = 600
    max_uses_default: int = 0
    max_attenuation_level: int = 5


@dataclass
class SecurityConfig:
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 100
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60
    injection_scan_enabled: bool = True
    input_max_length: int = 2000
    sensitive_capabilities: list = field(default_factory=lambda: ["lark:contact:read", "lark:bitable:write"])
    max_concurrent_sessions: int = 1000


@dataclass
class FeishuConfig:
    app_id: str = ""
    app_secret: str = ""
    verification_token: str = ""
    encrypt_key: str = ""
    bot_name: str = "AgentPass"
    poll_interval: float = 2.0
    max_poll_chat_ids: int = 50
    max_processed_messages: int = 1000
    message_retry_count: int = 3
    message_retry_delay: float = 1.0

    def __post_init__(self):
        self.app_id = os.environ.get("FEISHU_APP_ID", self.app_id)
        self.app_secret = os.environ.get("FEISHU_APP_SECRET", self.app_secret)
        self.verification_token = os.environ.get("FEISHU_VERIFICATION_TOKEN", self.verification_token)
        self.encrypt_key = os.environ.get("FEISHU_ENCRYPT_KEY", self.encrypt_key)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    structured_format: bool = True
    log_requests: bool = True
    log_request_bodies: bool = False
    log_response_bodies: bool = False
    slow_request_threshold: float = 5.0
    trace_header: str = "X-Trace-ID"


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    token: TokenConfig = field(default_factory=TokenConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    feishu: FeishuConfig = field(default_factory=FeishuConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    data_dir: Path = _DATA_DIR
    reports_dir: Path = _REPORTS_DIR
    frontend_dir: Path = _FRONTEND_DIR
    version: str = "2.0.0"
    environment: str = "development"

    def __post_init__(self):
        self.data_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        self.environment = os.environ.get("AGENTPASS_ENV", "development")


_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def reload_config() -> AppConfig:
    global _config
    _config = AppConfig()
    return _config
