import time
import uuid
import sqlite3
from dataclasses import dataclass


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
        self._used_nonces = set()
        self.nonce_ttl = 300
        self.db_path = db_path or ":memory:"
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

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
        conn.close()

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
        except Exception:
            pass
        finally:
            conn.close()

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
            conn.close()

            if not row:
                return NonceResult(valid=False, error_code="ERR_NONCE_NOT_FOUND")

            if row["consumed"]:
                self._used_nonces.add(nonce)
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

        self._used_nonces.add(nonce)

        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE nonces SET consumed = 1, consumed_at = ? WHERE nonce = ?",
                (time.time(), nonce),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

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
        except Exception:
            pass
        finally:
            conn.close()
