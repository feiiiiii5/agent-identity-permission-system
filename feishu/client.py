import os
import json
import time
import shutil
import subprocess
import httpx


class FeishuClient:

    MAX_RETRIES = 3
    REQUEST_TIMEOUT = 10.0

    def __init__(self):
        self.app_id = os.environ.get("FEISHU_APP_ID", "")
        self.app_secret = os.environ.get("FEISHU_APP_SECRET", "")
        self._cli_available = shutil.which("lark-cli") is not None
        self._cli_configured = False
        if self._cli_available:
            try:
                result = subprocess.run(
                    ["lark-cli", "config", "show"],
                    capture_output=True, text=True, timeout=5,
                )
                config = json.loads(result.stdout)
                if config.get("appId"):
                    self._cli_configured = True
                    self.app_id = config["appId"]
            except Exception:
                pass
        self.is_demo_mode = not (self.app_id and self.app_secret) and not self._cli_configured
        self._token = None
        self._token_expires = 0

    def _cli_call(self, args: list, use_json_format: bool = True) -> dict:
        if use_json_format and "--format" not in args and "config" not in args and "auth" not in args:
            test_args = args + ["--format", "json"]
        else:
            test_args = args
        try:
            result = subprocess.run(
                ["lark-cli"] + test_args,
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0 and use_json_format and "--format" not in args:
                result = subprocess.run(
                    ["lark-cli"] + args,
                    capture_output=True, text=True, timeout=15,
                )
            output = result.stdout.strip()
            if not output:
                return {"error": "Empty response from CLI", "mode": "cli_error"}
            for line_idx, line in enumerate(output.split("\n")):
                line_stripped = line.strip()
                if line_stripped.startswith("{") or line_stripped.startswith("["):
                    output = "\n".join(output.split("\n")[line_idx:])
                    break
            data = json.loads(output)
            if isinstance(data, dict) and data.get("ok"):
                return data.get("data", data)
            if isinstance(data, dict) and "error" in data:
                return {"error": data.get("error", {}).get("message", "CLI call failed"), "mode": "cli_error"}
            return data
        except subprocess.TimeoutExpired:
            return {"error": "CLI call timed out", "mode": "cli_error"}
        except json.JSONDecodeError as e:
            return {"error": f"JSON parse error: {e}", "mode": "cli_error", "raw": result.stdout[:200] if result else ""}
        except Exception as e:
            return {"error": str(e), "mode": "cli_error"}

    def _get_access_token(self) -> str:
        if self.is_demo_mode:
            return "demo_token_" + str(int(time.time()))

        if self._token and time.time() < self._token_expires:
            return self._token

        if self._cli_configured:
            try:
                result = subprocess.run(
                    ["lark-cli", "auth", "status"],
                    capture_output=True, text=True, timeout=5,
                )
                status = json.loads(result.stdout)
                if status.get("tokenStatus") == "valid":
                    self._token = "cli_managed"
                    self._token_expires = time.time() + 3600
                    return self._token
            except Exception:
                pass

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
        mode = "Demo模式: 使用模拟数据"
        if self._cli_configured:
            mode = "已通过 lark-cli 配置飞书应用 (推荐)"
        elif self.app_id and self.app_secret:
            mode = "已配置飞书应用凭证 (环境变量)"
        return {
            "is_demo_mode": self.is_demo_mode,
            "app_id_configured": bool(self.app_id),
            "app_secret_configured": bool(self.app_secret),
            "cli_configured": self._cli_configured,
            "message": mode,
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
