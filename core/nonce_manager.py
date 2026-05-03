import json
import time
import uuid
import logging
import sqlite3
import threading
from typing import Optional
from dataclasses import dataclass
from collections import OrderedDict

from core.db_pool import get_pool

logger = logging.getLogger(__name__)


@dataclass
class NonceResult:
    valid: bool
    error_code: str = ""


class NonceManager:

    _instance = None

    @classmethod
    def reset_instance(cls):
        cls._instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = None):
        if hasattr(self, "_initialized") and self._initialized:
            return
        self._initialized = True
        self._issued_nonces = {}
        self._used_nonces = OrderedDict()
        self.MAX_USED_NONCES = 10000
        self.nonce_ttl = 300
        self.db_path = db_path or ":memory:"
        self._pool = get_pool(self.db_path) if self.db_path != ":memory:" else None
        self._init_db()

    def _get_conn(self):
        if self._pool:
            return self._pool.get_connection()
        # Fallback for :memory: databases
        import sqlite3
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _return_conn(self, conn):
        if self._pool:
            self._pool.return_connection(conn)
        else:
            conn.close()

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                issued_at REAL NOT NULL,
                consumed INTEGER DEFAULT 0,
                consumed_at REAL DEFAULT 0
            );
        """)
        conn.commit()
        self._return_conn(conn)

    def issue_nonce(self, agent_id: str) -> str:
        nonce = uuid.uuid4().hex + uuid.uuid4().hex
        now = time.time()
        self._issued_nonces[nonce] = {"agent_id": agent_id, "issued_at": now}

        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO nonces (nonce, agent_id, issued_at) VALUES (?, ?, ?)",
                (nonce, agent_id, now),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to persist nonce: {e}")
        finally:
            self._return_conn(conn)

        return nonce

    def consume_nonce(self, nonce: str, agent_id: str) -> NonceResult:
        if nonce in self._used_nonces:
            return NonceResult(valid=False, error_code="ERR_NONCE_ALREADY_USED")

        if nonce not in self._issued_nonces:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT * FROM nonces WHERE nonce = ?",
                (nonce,),
            ).fetchone()
            self._return_conn(conn)

            if not row:
                return NonceResult(valid=False, error_code="ERR_NONCE_NOT_FOUND")

            if row["consumed"]:
                self._used_nonces[nonce] = True
                return NonceResult(valid=False, error_code="ERR_NONCE_ALREADY_USED")

            stored_agent = row["agent_id"]
            issued_at = row["issued_at"]
        else:
            stored = self._issued_nonces[nonce]
            stored_agent = stored["agent_id"]
            issued_at = stored["issued_at"]

        if stored_agent != agent_id:
            return NonceResult(valid=False, error_code="ERR_NONCE_AGENT_MISMATCH")

        if time.time() - issued_at > self.nonce_ttl:
            return NonceResult(valid=False, error_code="ERR_NONCE_EXPIRED")

        self._used_nonces[nonce] = True
        if len(self._used_nonces) > self.MAX_USED_NONCES:
            self._used_nonces.popitem(last=False)

        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE nonces SET consumed = 1, consumed_at = ? WHERE nonce = ?",
                (time.time(), nonce),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to mark nonce consumed: {e}")
        finally:
            self._return_conn(conn)

        return NonceResult(valid=True)

    def cleanup_expired(self):
        now = time.time()
        expired = [
            n for n, data in self._issued_nonces.items()
            if now - data["issued_at"] > self.nonce_ttl
        ]
        for n in expired:
            del self._issued_nonces[n]

        conn = self._get_conn()
        try:
            cutoff = now - self.nonce_ttl * 2
            conn.execute("DELETE FROM nonces WHERE issued_at < ? AND consumed = 0", (cutoff,))
            conn.commit()
        except Exception as e:
            logger.warning("Nonce cleanup failed: %s", e)
        finally:
            self._return_conn(conn)
