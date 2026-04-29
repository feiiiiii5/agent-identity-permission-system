import os
import time
import httpx


class FeishuClient:

    MAX_RETRIES = 3
    REQUEST_TIMEOUT = 10.0

    def __init__(self):
        self.app_id = os.environ.get("FEISHU_APP_ID", "")
        self.app_secret = os.environ.get("FEISHU_APP_SECRET", "")
        self.is_demo_mode = not (self.app_id and self.app_secret)
        self._token = None
        self._token_expires = 0

    def _get_access_token(self) -> str:
        if self.is_demo_mode:
            return "demo_token_" + str(int(time.time()))

        if self._token and time.time() < self._token_expires:
            return self._token

        for attempt in range(self.MAX_RETRIES):
            try:
                resp = httpx.post(
                    "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
                    json={
                        "app_id": self.app_id,
                        "app_secret": self.app_secret,
                    },
                    timeout=self.REQUEST_TIMEOUT,
                )
                data = resp.json()
                if data.get("code") == 0:
                    self._token = data["tenant_access_token"]
                    self._token_expires = time.time() + data.get("expire", 7200) - 60
                    return self._token
            except Exception:
                if attempt == self.MAX_RETRIES - 1:
                    break
                time.sleep(0.5 * (attempt + 1))

        return "demo_token_fallback"

    def get_demo_status(self) -> dict:
        return {
            "is_demo_mode": self.is_demo_mode,
            "app_id_configured": bool(self.app_id),
            "app_secret_configured": bool(self.app_secret),
            "message": "Demo模式: 使用模拟数据" if self.is_demo_mode else "已配置飞书应用凭证",
        }

    def _request_with_retry(self, method: str, url: str, **kwargs) -> dict:
        kwargs.setdefault("timeout", self.REQUEST_TIMEOUT)
        for attempt in range(self.MAX_RETRIES):
            try:
                token = self._get_access_token()
                headers = kwargs.pop("headers", {})
                headers["Authorization"] = f"Bearer {token}"
                resp = httpx.request(method, url, headers=headers, **kwargs)
                return resp.json()
            except Exception:
                if attempt == self.MAX_RETRIES - 1:
                    return {"error": f"Request failed after {self.MAX_RETRIES} retries", "mode": "api_error"}
                time.sleep(0.5 * (attempt + 1))
        return {"error": "Max retries exceeded", "mode": "api_error"}
