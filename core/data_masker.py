import re


class DataMasker:

    PHONE_PATTERN = re.compile(r'(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)')
    EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    ID_CARD_PATTERN = re.compile(r'(?<!\d)(\d{3})\d{11}(\d{4})(?!\d)')
    BANK_CARD_PATTERN = re.compile(r'(?<!\d)(\d{4})\d{8,12}(\d{4})(?!\d)')
    NAME_PATTERN = re.compile(r'([\u4e00-\u9fff]{1})([\u4e00-\u9fff]{1,2})(的|先生|女士|经理|总监)')

    TOKEN_PATTERN = re.compile(r'(eyJ[a-zA-Z0-9_-]+)\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    API_KEY_PATTERN = re.compile(r'(sk-|ak-|key-|token-)([a-zA-Z0-9]{4})[a-zA-Z0-9]+')
    PASSWORD_PATTERN = re.compile(r'(password|passwd|pwd|secret)["\s:=]+(["\']?)([^"\s\'{]{3})[^"\s\'}]+(["\']?)', re.IGNORECASE)

    MAX_AUDIT_CONTENT_LENGTH = 200

    def mask_phone(self, text: str) -> str:
        return self.PHONE_PATTERN.sub(r'\1****\2', text)

    def mask_email(self, text: str) -> str:
        return self.EMAIL_PATTERN.sub(r'\1***@\2', text)

    def mask_id_card(self, text: str) -> str:
        return self.ID_CARD_PATTERN.sub(r'\1***********\2', text)

    def mask_bank_card(self, text: str) -> str:
        return self.BANK_CARD_PATTERN.sub(r'\1********\2', text)

    def mask_name(self, text: str) -> str:
        def _replace(m):
            return m.group(1) + '*' * len(m.group(2)) + m.group(3)
        return self.NAME_PATTERN.sub(_replace, text)

    def mask_token(self, text: str) -> str:
        return self.TOKEN_PATTERN.sub(r'\1.***.***', text)

    def mask_api_key(self, text: str) -> str:
        return self.API_KEY_PATTERN.sub(r'\1\2***', text)

    def mask_password(self, text: str) -> str:
        def _replace(m):
            return f'{m.group(1)}{m.group(2)}{m.group(3)}***{m.group(4)}'
        return self.PASSWORD_PATTERN.sub(_replace, text)

    def mask_all(self, text: str) -> str:
        result = text
        result = self.mask_phone(result)
        result = self.mask_email(result)
        result = self.mask_id_card(result)
        result = self.mask_bank_card(result)
        result = self.mask_name(result)
        result = self.mask_token(result)
        result = self.mask_api_key(result)
        result = self.mask_password(result)
        return result

    def mask_contact_data(self, data: dict) -> dict:
        if not isinstance(data, dict):
            return data

        masked = dict(data)

        if "mobile" in masked or "phone" in masked:
            phone = masked.get("mobile") or masked.get("phone", "")
            if phone:
                masked["mobile"] = self.mask_phone(str(phone))
                masked["phone"] = masked["mobile"]

        if "email" in masked:
            email = masked.get("email", "")
            if email:
                masked["email"] = self.mask_email(str(email))

        if "id_card" in masked:
            id_card = masked.get("id_card", "")
            if id_card:
                masked["id_card"] = self.mask_id_card(str(id_card))

        if "name" in masked:
            name = masked.get("name", "")
            if name and len(name) >= 2:
                masked["name"] = name[0] + "*" * (len(name) - 1)

        return masked

    def mask_contact_list(self, contacts: list) -> list:
        return [self.mask_contact_data(c) for c in contacts]

    def sanitize_for_audit(self, content: str) -> str:
        if not content:
            return content

        sanitized = self.mask_all(content)

        if len(sanitized) > self.MAX_AUDIT_CONTENT_LENGTH:
            sanitized = sanitized[:self.MAX_AUDIT_CONTENT_LENGTH - 3] + "..."

        return sanitized

    def sanitize_audit_record(self, record: dict) -> dict:
        sanitized = dict(record)

        for field in ["original_input", "deny_reason", "description", "delegated_user"]:
            if field in sanitized and isinstance(sanitized[field], str):
                sanitized[field] = self.sanitize_for_audit(sanitized[field])

        if "granted_capabilities" in sanitized:
            pass

        for field in ["access_token", "client_secret", "token"]:
            if field in sanitized:
                val = str(sanitized[field])
                if len(val) > 8:
                    sanitized[field] = val[:4] + "***" + val[-4:]
                elif len(val) > 0:
                    sanitized[field] = "***"

        return sanitized

    def check_contains_pii(self, text: str) -> dict:
        findings = []

        if self.PHONE_PATTERN.search(text):
            findings.append({"type": "phone", "description": "包含手机号码"})

        if self.EMAIL_PATTERN.search(text):
            findings.append({"type": "email", "description": "包含邮箱地址"})

        if self.ID_CARD_PATTERN.search(text):
            findings.append({"type": "id_card", "description": "包含身份证号"})

        if self.BANK_CARD_PATTERN.search(text):
            findings.append({"type": "bank_card", "description": "包含银行卡号"})

        if self.TOKEN_PATTERN.search(text):
            findings.append({"type": "token", "description": "包含JWT Token"})

        if self.API_KEY_PATTERN.search(text):
            findings.append({"type": "api_key", "description": "包含API密钥"})

        if self.PASSWORD_PATTERN.search(text):
            findings.append({"type": "password", "description": "包含密码/密钥"})

        return {
            "has_pii": len(findings) > 0,
            "findings": findings,
            "masked_content": self.mask_all(text) if findings else text,
        }
