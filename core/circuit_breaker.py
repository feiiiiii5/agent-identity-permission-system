import time
import logging
import threading
from typing import Dict

logger = logging.getLogger(__name__)


class CircuitBreaker:

    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(self):
        self._states: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self.failure_threshold = 5
        self.recovery_timeout = 60
        self.success_threshold = 2
        self._ws_notify = None

    def set_ws_notify(self, func):
        self._ws_notify = func

    def _notify(self, event_type: str, data: dict):
        if self._ws_notify:
            try:
                self._ws_notify(event_type, data)
            except Exception as e:
                logger.warning("WebSocket notification failed: %s", e)

    def _get_state(self, agent_id: str) -> dict:
        if agent_id not in self._states:
            self._states[agent_id] = {
                "state": self.STATE_CLOSED,
                "failure_count": 0,
                "success_count": 0,
                "last_failure_time": 0,
                "last_failure_type": "",
                "opened_at": 0,
            }
        return self._states[agent_id]

    def record_success(self, agent_id: str):
        with self._lock:
            state = self._get_state(agent_id)

            if state["state"] == self.STATE_HALF_OPEN:
                state["success_count"] += 1
                if state["success_count"] >= self.success_threshold:
                    old_state = state["state"]
                    state["state"] = self.STATE_CLOSED
                    state["failure_count"] = 0
                    state["success_count"] = 0
                    self._notify("circuit_breaker_state_change", {
                        "agent_id": agent_id,
                        "old_state": old_state,
                        "new_state": self.STATE_CLOSED,
                    })
            elif state["state"] == self.STATE_CLOSED:
                state["failure_count"] = 0
                state["success_count"] += 1

    def record_failure(self, agent_id: str, error_type: str = ""):
        with self._lock:
            state = self._get_state(agent_id)
            state["failure_count"] += 1
            state["last_failure_time"] = time.time()
            state["last_failure_type"] = error_type

            if state["state"] == self.STATE_HALF_OPEN:
                old_state = state["state"]
                state["state"] = self.STATE_OPEN
                state["opened_at"] = time.time()
                state["success_count"] = 0
                self._notify("circuit_breaker_state_change", {
                    "agent_id": agent_id,
                    "old_state": old_state,
                    "new_state": self.STATE_OPEN,
                    "error_type": error_type,
                })
            elif state["state"] == self.STATE_CLOSED:
                if state["failure_count"] >= self.failure_threshold:
                    old_state = state["state"]
                    state["state"] = self.STATE_OPEN
                    state["opened_at"] = time.time()
                    self._notify("circuit_breaker_state_change", {
                        "agent_id": agent_id,
                        "old_state": old_state,
                        "new_state": self.STATE_OPEN,
                        "failure_count": state["failure_count"],
                    })

    def can_proceed(self, agent_id: str) -> dict:
        with self._lock:
            state = self._get_state(agent_id)

            if state["state"] == self.STATE_CLOSED:
                return {
                    "allowed": True,
                    "state": self.STATE_CLOSED,
                    "failure_count": state["failure_count"],
                    "recovery_at": 0,
                }

            if state["state"] == self.STATE_OPEN:
                elapsed = time.time() - state["opened_at"]
                if elapsed >= self.recovery_timeout:
                    old_state = state["state"]
                    state["state"] = self.STATE_HALF_OPEN
                    state["success_count"] = 0
                    self._notify("circuit_breaker_state_change", {
                        "agent_id": agent_id,
                        "old_state": old_state,
                        "new_state": self.STATE_HALF_OPEN,
                    })
                    return {
                        "allowed": True,
                        "state": self.STATE_HALF_OPEN,
                        "failure_count": state["failure_count"],
                        "recovery_at": 0,
                    }
                recovery_at = state["opened_at"] + self.recovery_timeout
                return {
                    "allowed": False,
                    "state": self.STATE_OPEN,
                    "failure_count": state["failure_count"],
                    "recovery_at": recovery_at,
                }

            if state["state"] == self.STATE_HALF_OPEN:
                return {
                    "allowed": True,
                    "state": self.STATE_HALF_OPEN,
                    "failure_count": state["failure_count"],
                    "recovery_at": 0,
                }

            return {"allowed": True, "state": self.STATE_CLOSED, "failure_count": 0, "recovery_at": 0}

    def get_all_states(self) -> Dict[str, dict]:
        result = {}
        for agent_id, state in self._states.items():
            current = self.can_proceed(agent_id)
            result[agent_id] = {
                "state": current["state"],
                "allowed": current["allowed"],
                "failure_count": state["failure_count"],
                "last_failure_type": state["last_failure_type"],
                "recovery_at": current.get("recovery_at", 0),
            }
        return result

    def reset(self, agent_id: str):
        with self._lock:
            if agent_id in self._states:
                old_state = self._states[agent_id]["state"]
                self._states[agent_id] = {
                    "state": self.STATE_CLOSED,
                    "failure_count": 0,
                    "success_count": 0,
                    "last_failure_time": 0,
                    "last_failure_type": "",
                    "opened_at": 0,
                }
                self._notify("circuit_breaker_state_change", {
                    "agent_id": agent_id,
                    "old_state": old_state,
                    "new_state": self.STATE_CLOSED,
                })
