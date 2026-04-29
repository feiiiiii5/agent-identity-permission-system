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
        return self._request_with_retry(
            "POST",
            f"https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records",
            json={"fields": fields},
        )
