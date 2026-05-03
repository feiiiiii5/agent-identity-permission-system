import time
import uuid
import json
import threading
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)


class RequestTraceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-ID", uuid.uuid4().hex[:16])
        request.state.trace_id = trace_id
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Response-Time"] = f"{duration:.3f}s"
        if duration > 5.0:
            logger.warning(f"Slow request: {request.method} {request.url.path} took {duration:.3f}s [trace_id={trace_id}]")
        return response


class InputValidationMiddleware(BaseHTTPMiddleware):
    MAX_BODY_SIZE = 10 * 1024 * 1024
    BLOCKED_PATHS = ["/admin", "/phpmyadmin", "/wp-admin", "/.env", "/config.yml"]

    async def dispatch(self, request: Request, call_next):
        for blocked in self.BLOCKED_PATHS:
            if request.url.path.lower().startswith(blocked):
                return JSONResponse(
                    status_code=404,
                    content={"error": "Not Found", "trace_id": getattr(request.state, "trace_id", "")},
                )

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "max_size": self.MAX_BODY_SIZE},
            )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    SKIP_PATHS = {"/ws", "/api/health", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        trace_id = getattr(request.state, "trace_id", "")
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"

        try:
            response = await call_next(request)
            duration = time.time() - start_time
            logger.info(
                f"[{trace_id}] {request.method} {request.url.path} "
                f"{response.status_code} {duration:.3f}s "
                f"ip={client_ip}"
            )
            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"[{trace_id}] {request.method} {request.url.path} "
                f"500 {duration:.3f}s ip={client_ip} error={str(e)[:200]}"
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "trace_id": trace_id,
                },
            )


class InProcessRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, window_seconds: int = 60, max_requests: int = 300):
        super().__init__(app)
        self._lock = threading.Lock()
        self._request_counts: dict = {}
        self._window_start: float = 0
        self._window_seconds: int = window_seconds
        self._max_requests: int = max_requests

    async def dispatch(self, request: Request, call_next):
        if request.url.path in ("/ws", "/api/health", "/api/system/health", "/"):
            return await call_next(request)

        now = time.time()
        with self._lock:
            if now - self._window_start > self._window_seconds:
                self._request_counts = {}
                self._window_start = now

            client_ip = request.client.host if request.client else "unknown"
            key = f"{client_ip}:{request.url.path}"
            self._request_counts[key] = self._request_counts.get(key, 0) + 1
            current_count = self._request_counts[key]

        if current_count > self._max_requests:
            trace_id = getattr(request.state, "trace_id", "")
            logger.warning(f"Rate limit exceeded: {key} [{current_count}/{self._max_requests}] [trace_id={trace_id}]")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "retry_after": self._window_seconds,
                    "trace_id": trace_id,
                },
            )

        return await call_next(request)
