import time
from dataclasses import dataclass
from core.db_pool import get_pool


@dataclass
class RateLimitResult:
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int
    retry_after: float = 0
    remaining: int = 0


class SlidingWindowRateLimiter:

    LIMITS = {
        "token_issue": {"window_seconds": 60, "max_requests": 20},
        "token_delegate": {"window_seconds": 60, "max_requests": 30},
        "token_verify": {"window_seconds": 60, "max_requests": 100},
        "feishu_api": {"window_seconds": 60, "max_requests": 10},
    }

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = get_pool(db_path)
        self._init_db()

    def _get_conn(self):
        return self._pool.get_connection()

    def _return_conn(self, conn):
        if conn and self._pool:
            self._pool.return_connection(conn)

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rl_agent_action ON rate_limit_events(agent_id, action_type);
            CREATE INDEX IF NOT EXISTS idx_rl_timestamp ON rate_limit_events(timestamp);
        """)
        conn.commit()
        self._return_conn(conn)

    def check_rate_limit(self, agent_id: str, action_type: str) -> RateLimitResult:
        limit_cfg = self.LIMITS.get(action_type)
        if not limit_cfg:
            return RateLimitResult(
                allowed=True, current_count=0, limit=0,
                window_seconds=0, remaining=999,
            )

        window = limit_cfg["window_seconds"]
        max_req = limit_cfg["max_requests"]
        now = time.time()
        window_start = now - window

        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM rate_limit_events WHERE agent_id = ? AND action_type = ? AND timestamp > ?",
            (agent_id, action_type, window_start),
        ).fetchone()
        self._return_conn(conn)

        current_count = row["cnt"] if row else 0

        if current_count >= max_req:
            oldest = self._get_oldest_in_window(agent_id, action_type, window_start)
            retry_after = (oldest + window - now) if oldest else window
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=max_req,
                window_seconds=window,
                retry_after=max(0, retry_after),
                remaining=0,
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=max_req,
            window_seconds=window,
            remaining=max_req - current_count,
        )

    def _get_oldest_in_window(self, agent_id: str, action_type: str, window_start: float) -> float:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT MIN(timestamp) as oldest FROM rate_limit_events WHERE agent_id = ? AND action_type = ? AND timestamp > ?",
            (agent_id, action_type, window_start),
        ).fetchone()
        self._return_conn(conn)
        return row["oldest"] if row and row["oldest"] else 0

    def record_request(self, agent_id: str, action_type: str):
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO rate_limit_events (agent_id, action_type, timestamp) VALUES (?, ?, ?)",
            (agent_id, action_type, now),
        )
        conn.commit()

        max_window = max(cfg["window_seconds"] for cfg in self.LIMITS.values())
        cutoff = now - max_window * 2
        conn.execute(
            "DELETE FROM rate_limit_events WHERE timestamp < ?",
            (cutoff,),
        )
        conn.commit()
        self._return_conn(conn)

    def get_agent_rate_stats(self, agent_id: str) -> dict:
        stats = {}
        now = time.time()
        conn = self._get_conn()

        for action_type, cfg in self.LIMITS.items():
            window = cfg["window_seconds"]
            window_start = now - window
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM rate_limit_events WHERE agent_id = ? AND action_type = ? AND timestamp > ?",
                (agent_id, action_type, window_start),
            ).fetchone()
            count = row["cnt"] if row else 0
            stats[action_type] = {
                "current_count": count,
                "limit": cfg["max_requests"],
                "window_seconds": window,
                "remaining": max(0, cfg["max_requests"] - count),
            }

        self._return_conn(conn)
        return stats
