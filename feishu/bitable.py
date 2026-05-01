from feishu.client import FeishuClient


class FeishuBitable(FeishuClient):

    def read_bitable(self, app_token: str, table_id: str, page_size: int = 20) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "app_token": app_token,
                "table_id": table_id,
                "data": {
                    "items": [
                        {"record_id": "rec_001", "fields": {"季度": "Q1", "销售额": 1250000, "增长率": "12%"}},
                        {"record_id": "rec_002", "fields": {"季度": "Q2", "销售额": 1580000, "增长率": "26%"}},
                        {"record_id": "rec_003", "fields": {"季度": "Q3", "销售额": 980000, "增长率": "-38%"}},
                        {"record_id": "rec_004", "fields": {"季度": "Q4", "销售额": 2100000, "增长率": "114%"}},
                    ],
                    "total": 4,
                },
            }
        if self._cli_configured:
            result = self._cli_call([
                "base", "+record-list",
                "--base-token", app_token,
                "--table-id", table_id,
                "--format", "json",
            ])
            if isinstance(result, dict) and "error" not in result:
                fields = result.get("fields", [])
                rows = result.get("data", [])
                record_ids = result.get("record_id_list", [])
                items = []
                for i, row in enumerate(rows):
                    item = {"record_id": record_ids[i] if i < len(record_ids) else f"rec_{i}"}
                    if fields and isinstance(row, list):
                        item["fields"] = {}
                        for j, val in enumerate(row):
                            if j < len(fields) and val is not None:
                                item["fields"][fields[j]] = val
                    elif isinstance(row, dict):
                        item["fields"] = row
                    else:
                        item["fields"] = {}
                    items.append(item)
                return {
                    "mode": "cli",
                    "app_token": app_token,
                    "table_id": table_id,
                    "data": {"items": items, "total": len(items)},
                }
            return {"mode": "cli_error", "app_token": app_token, "error": result.get("error", "")}
        return self._request_with_retry(
            "GET",
            f"https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records",
            params={"page_size": page_size},
        )

    def write_bitable(self, app_token: str, table_id: str, fields: dict) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "app_token": app_token,
                "table_id": table_id,
                "record_id": "rec_new_" + str(int(__import__("time").time())),
                "fields": fields,
                "message": "多维表格写入成功(Demo模式)",
            }
        if self._cli_configured:
            field_names = list(fields.keys())
            row_values = list(fields.values())
            result = self._cli_call([
                "base", "+record-batch-create",
                "--base-token", app_token,
                "--table-id", table_id,
                "--format", "json",
                "--json", __import__("json").dumps({"fields": field_names, "rows": [row_values]}),
            ])
            if isinstance(result, dict) and "error" not in result:
                record_ids = result.get("record_id_list", [])
                return {
                    "mode": "cli",
                    "app_token": app_token,
                    "table_id": table_id,
                    "record_id": record_ids[0] if record_ids else "",
                    "fields": fields,
                    "message": "多维表格写入成功(CLI模式)",
                }
            return {"mode": "cli_error", "app_token": app_token, "error": result.get("error", "")}
        return self._request_with_retry(
            "POST",
            f"https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records",
            json={"fields": fields},
        )
