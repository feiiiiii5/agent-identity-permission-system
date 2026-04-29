from feishu.client import FeishuClient


class FeishuContact(FeishuClient):

    def read_contacts(self, user_id: str = None, page_size: int = 50) -> dict:
        if self.is_demo_mode:
            contacts = [
                {"user_id": "u_001", "name": "张三", "department": "销售部", "email": "zhangsan@example.com"},
                {"user_id": "u_002", "name": "李四", "department": "技术部", "email": "lisi@example.com"},
                {"user_id": "u_003", "name": "王五", "department": "市场部", "email": "wangwu@example.com"},
                {"user_id": "u_004", "name": "赵六", "department": "财务部", "email": "zhaoliu@example.com"},
                {"user_id": "u_005", "name": "钱七", "department": "人事部", "email": "qianqi@example.com"},
            ]
            return {
                "mode": "demo",
                "data": {
                    "items": contacts[:page_size],
                    "total": len(contacts),
                    "has_more": False,
                },
            }
        return self._request_with_retry(
            "GET",
            "https://open.feishu.cn/open-apis/contact/v3/users",
            params={"page_size": page_size, "user_id": user_id or ""},
        )

    def read_contact_by_id(self, user_id: str) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "data": {
                    "user_id": user_id,
                    "name": "张三",
                    "department": "销售部",
                    "mobile": "+86-138****1234",
                    "email": "zhangsan@example.com",
                },
            }
        return self._request_with_retry(
            "GET",
            f"https://open.feishu.cn/open-apis/contact/v3/users/{user_id}",
        )
