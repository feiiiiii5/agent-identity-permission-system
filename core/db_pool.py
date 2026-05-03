import sqlite3
import threading
import time
import logging
from contextlib import contextmanager
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class ConnectionPool:
    def __init__(self, db_path: str, max_connections: int = 20, busy_timeout: int = 5000):
        self.db_path = db_path
        self.max_connections = max_connections
        self.busy_timeout = busy_timeout
        self._pool = Queue(maxsize=max_connections)
        self._created = 0
        self._lock = threading.Lock()
        self._init_pragmas = True
        self._wait_count = 0
        self._hit_count = 0
        self._miss_count = 0

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute(f"PRAGMA busy_timeout={self.busy_timeout}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.row_factory = sqlite3.Row
        return conn

    def get_connection(self, timeout: float = 10.0) -> sqlite3.Connection:
        try:
            conn = self._pool.get(block=False)
            self._hit_count += 1
            try:
                conn.execute("SELECT 1")
                return conn
            except sqlite3.Error:
                with self._lock:
                    self._created -= 1
                self._hit_count -= 1
                return self._create_new(timeout)
        except Empty:
            self._miss_count += 1
            return self._create_new(timeout)

    def _create_new(self, timeout: float = 10.0) -> sqlite3.Connection:
        with self._lock:
            if self._created < self.max_connections:
                self._created += 1
                return self._create_connection()
        self._wait_count += 1
        try:
            conn = self._pool.get(block=True, timeout=timeout)
            try:
                conn.execute("SELECT 1")
                return conn
            except sqlite3.Error:
                with self._lock:
                    self._created -= 1
                return self._create_new(timeout)
        except Empty:
            raise sqlite3.OperationalError("Connection pool exhausted")

    def return_connection(self, conn: sqlite3.Connection):
        try:
            conn.rollback()
            self._pool.put(conn, block=False)
        except Exception:
            with self._lock:
                self._created -= 1
            try:
                conn.close()
            except Exception:
                pass

    @contextmanager
    def connection(self, timeout: float = 10.0):
        conn = self.get_connection(timeout)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.return_connection(conn)

    @contextmanager
    def readonly(self, timeout: float = 10.0):
        conn = self.get_connection(timeout)
        try:
            yield conn
        finally:
            self.return_connection(conn)

    def close_all(self):
        while True:
            try:
                conn = self._pool.get(block=False)
                try:
                    conn.close()
                except Exception:
                    pass
            except Empty:
                break
        with self._lock:
            self._created = 0

    def stats(self) -> dict:
        return {
            "db_path": self.db_path,
            "max_connections": self.max_connections,
            "created": self._created,
            "available": self._pool.qsize(),
            "wait_count": self._wait_count,
            "hit_count": self._hit_count,
            "miss_count": self._miss_count,
            "hit_rate": round(self._hit_count / max(1, self._hit_count + self._miss_count) * 100, 1),
        }


_pools: dict = {}
_pools_lock = threading.Lock()


def get_pool(db_path: str, max_connections: int = 20) -> ConnectionPool:
    with _pools_lock:
        if db_path not in _pools:
            _pools[db_path] = ConnectionPool(db_path, max_connections)
        return _pools[db_path]


def close_all_pools():
    with _pools_lock:
        for pool in _pools.values():
            pool.close_all()
        _pools.clear()


def reset_pools():
    close_all_pools()
