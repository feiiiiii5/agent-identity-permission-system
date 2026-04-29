from feishu.client import FeishuClient


class FeishuDocument(FeishuClient):

    def create_document(self, title: str = "新建文档") -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "document_id": "demo_doc_" + str(int(__import__("time").time())),
                "title": title,
                "message": "文档创建成功(Demo模式)",
            }
        return self._request_with_retry(
            "POST",
            "https://open.feishu.cn/open-apis/docx/v1/documents",
            json={"title": title},
        )

    def write_document(self, doc_id: str, content: str) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "doc_id": doc_id,
                "content_length": len(content),
                "message": "文档写入成功(Demo模式)",
            }
        return self._request_with_retry(
            "POST",
            f"https://open.feishu.cn/open-apis/docx/v1/documents/{doc_id}/blocks",
            json={"content": content},
        )

    def read_document(self, doc_id: str) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "doc_id": doc_id,
                "content": {
                    "title": "季度销售报告",
                    "sections": [
                        {"heading": "Q1 销售数据", "content": "Q1总销售额: 1,250,000元"},
                        {"heading": "Q2 销售数据", "content": "Q2总销售额: 1,580,000元"},
                    ],
                },
            }
        return self._request_with_retry(
            "GET",
            f"https://open.feishu.cn/open-apis/docx/v1/documents/{doc_id}",
        )
