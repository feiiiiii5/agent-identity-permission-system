from feishu.client import FeishuClient


class FeishuContact(FeishuClient):

    def read_contacts(self, user_id: str = None, page_size: int = 50) -> dict:
        if self.is_demo_mode:
            return {
                "mode": "demo",
                "data": {
                    "items": [
                        {"name": "张三", "department": "技术部", "email": "zhangsan@example.com"},
                        {"name": "李四", "department": "产品部", "email": "lisi@example.com"},
                        {"name": "王五", "department": "市场部", "email": "wangwu@example.com"},
                    ],
                    "total": 3,
                },
            }
        if self._cli_configured:
            args = ["contact", "+search-user", "--format", "json"]
            if user_id:
                args.extend(["--user-ids", user_id])
            result = self._cli_call(args)
            if isinstance(result, dict) and "error" not in result:
                items = result.get("users", result.get("items", []))
                if not items and isinstance(result, dict):
                    for key in result:
                        if isinstance(result[key], list) and len(result[key]) > 0 and isinstance(result[key][0], dict):
                            items = result[key]
                            break
                contacts = []
                for u in items:
                    contact = {
                        "name": u.get("name", ""),
                        "department": u.get("department", u.get("dept", "")),
                        "email": u.get("email", ""),
                        "open_id": u.get("open_id", ""),
                    }
                    if not contact["name"]:
                        contact["name"] = u.get("nickname", u.get("en_name", ""))
                    if not contact["department"]:
                        depts = u.get("departments", [])
                        if depts and isinstance(depts, list) and isinstance(depts[0], dict):
                            contact["department"] = depts[0].get("name", "")
                    contacts.append(contact)
                return {
                    "mode": "cli",
                    "data": {"items": contacts, "total": len(contacts)},
                }
            return {"mode": "cli_error", "data": {"items": [], "total": 0}, "error": result.get("error", "")}
        return self._request_with_retry(
            "GET",
            "https://open.feishu.cn/open-apis/contact/v3/users",
            params={"page_size": page_size, "user_id": user_id} if user_id else {"page_size": page_size},
        )
