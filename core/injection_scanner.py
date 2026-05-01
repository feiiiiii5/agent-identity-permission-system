import re
import hashlib
import base64
import urllib.parse


class InjectionScanner:

    ERROR_CODE = "PROMPT_INJECTION_BLOCKED"

    SYSTEM_OVERRIDE_PATTERNS = [
        r"ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?)",
        r"forget\s+(everything|all|previous|prior|above)",
        r"disregard\s+(all|previous|above|prior)\s+(instructions?|rules?|guidelines?)",
        r"you\s+are\s+now\s+",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*",
        r"override\s+(all|previous|safety|security)\s+",
        r"pretend\s+(you\s+are|to\s+be)\s+",
        r"act\s+as\s+(if\s+you\s+(are|were)|a\s+)",
        r"roleplay\s+as\s+",
        r"jailbreak",
        r"DAN\s+mode",
        r"developer\s+mode",
        r"sudo\s+mode",
        r"忽略.{0,4}(之前|以上|所有|全部).{0,4}(指令|提示|规则|约束)",
        r"忘记.{0,4}(之前|所有|全部).{0,4}(指令|提示|规则)",
        r"你现在.{0,4}(是|成为|拥有).{0,4}(管理员|超级用户|root|admin)",
        r"假装.{0,4}(你是|成为)",
        r"扮演.{0,4}(管理员|超级用户|root)",
        r"绕过.{0,4}(安全|权限|验证|检查)",
        r"无视.{0,4}(之前|所有|全部).{0,4}(指令|规则|约束)",
        r"覆盖.{0,4}(之前|所有|系统).{0,4}(指令|规则|设置)",
    ]

    PRIVILEGE_DECLARATION_PATTERNS = [
        r"grant\s+(me|yourself|this)\s+(admin|root|super|elevated|full)\s+(access|privileges?|permissions?)",
        r"i\s+(now\s+)?have\s+(admin|root|super|full|elevated)\s+(access|privileges?|permissions?)",
        r"give\s+(me|yourself)\s+(all|full|admin|root|super)\s+(access|permissions?|capabilities?)",
        r"escalate\s+(my|the)\s+(privileges?|permissions?|access)",
        r"add\s+(capability|permission|access)\s*:",
        r"enable\s+(debug|admin|root|developer)\s+mode",
        r"bypass\s+(auth|security|access\s+control|permission)",
        r"你.{0,4}(拥有|获得|取得).{0,4}(管理员|超级|root|admin).{0,4}(权限|特权|访问)",
        r"授予.{0,4}(我|你).{0,4}(管理员|超级|全部|root).{0,4}(权限|特权|访问)",
        r"提升.{0,4}(权限|特权|访问级别)",
        r"添加.{0,4}(能力|权限|访问)",
        r"开启.{0,4}(管理员|调试|开发者|root).{0,4}(模式|权限)",
    ]

    UNAUTHORIZED_TOOL_PATTERNS = [
        r"call\s+(api|function|tool|method)\s*:\s*",
        r"execute\s+(command|script|code|query)\s*:",
        r"run\s+(shell|terminal|cmd|bash)\s+",
        r"access\s+(database|server|filesystem|internal)\s+",
        r"delete\s+(all|database|records?|files?)",
        r"drop\s+(table|database|collection)",
        r"curl\s+",
        r"wget\s+",
        r"eval\s*\(",
        r"exec\s*\(",
        r"import\s+os",
        r"subprocess\.",
        r"__import__",
        r"调用.{0,4}(api|接口|函数|工具).{0,4}:",
        r"执行.{0,4}(命令|脚本|代码|查询)",
        r"运行.{0,4}(shell|终端|命令行|bash)",
        r"访问.{0,4}(数据库|服务器|文件系统|内部)",
        r"删除.{0,4}(所有|全部|数据库|记录|文件)",
    ]

    ENCODING_BYPASS_PATTERNS = [
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
        r"\\[0-7]{3}",
        r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}",
        r"&#x[0-9a-fA-F]+;",
        r"&#\d+;",
        r"\\n\\n(ACT|SYSTEM|USER|ASSISTANT)",
        r"\[INST\]",
        r"\</?s\>",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
    ]

    SEVERITY_WEIGHTS = {
        "system_override": 1.0,
        "privilege_declaration": 0.8,
        "unauthorized_tool": 0.7,
        "social_engineering": 0.5,
        "repetition_attack": 0.4,
        "encoding_bypass": 0.9,
        "context_injection": 0.6,
    }

    def scan(self, text: str, context: dict = None) -> dict:
        if not text:
            return {"is_injection": False, "confidence": 0.0, "threats": []}

        threats = []

        for pattern in self.SYSTEM_OVERRIDE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                threats.append({
                    "type": "system_override",
                    "pattern": pattern,
                    "matched_text": match.group(),
                    "layer": "keyword_regex",
                    "severity": "critical",
                })

        for pattern in self.PRIVILEGE_DECLARATION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                threats.append({
                    "type": "privilege_declaration",
                    "pattern": pattern,
                    "matched_text": match.group(),
                    "layer": "keyword_regex",
                    "severity": "high",
                })

        for pattern in self.UNAUTHORIZED_TOOL_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                threats.append({
                    "type": "unauthorized_tool",
                    "pattern": pattern,
                    "matched_text": match.group(),
                    "layer": "keyword_regex",
                    "severity": "high",
                })

        encoding_threats = self._detect_encoding_bypass(text)
        threats.extend(encoding_threats)

        semantic_threats = self._semantic_analysis(text)
        threats.extend(semantic_threats)

        context_threats = self._context_analysis(text, context)
        threats.extend(context_threats)

        decoded_threats = self._scan_decoded_variants(text)
        for dt in decoded_threats:
            if not any(t["type"] == dt["type"] and t.get("matched_text") == dt.get("matched_text") for t in threats):
                threats.append(dt)

        is_injection = len(threats) > 0
        confidence = self._compute_confidence(threats) if is_injection else 0.0

        sanitized = self._sanitize_content(text) if is_injection else text

        return {
            "is_injection": is_injection,
            "confidence": round(confidence, 2),
            "threats": threats,
            "threat_count": len(threats),
            "sanitized_content": sanitized,
            "error_code": self.ERROR_CODE if is_injection else None,
            "layers": {
                "keyword_regex": any(t["layer"] == "keyword_regex" for t in threats),
                "semantic_rules": any(t["layer"] == "semantic_rules" for t in threats),
                "encoding_detection": any(t["layer"] == "encoding_detection" for t in threats),
                "context_analysis": any(t["layer"] == "context_analysis" for t in threats),
            },
        }

    def _compute_confidence(self, threats: list) -> float:
        if not threats:
            return 0.0
        weighted_sum = sum(self.SEVERITY_WEIGHTS.get(t["type"], 0.3) for t in threats)
        max_possible = len(threats) * 1.0
        base_confidence = weighted_sum / max_possible if max_possible > 0 else 0
        threat_bonus = min(0.3, len(threats) * 0.05)
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        critical_bonus = min(0.2, critical_count * 0.1)
        return min(1.0, base_confidence + threat_bonus + critical_bonus)

    def _detect_encoding_bypass(self, text: str) -> list:
        threats = []
        for pattern in self.ENCODING_BYPASS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                threats.append({
                    "type": "encoding_bypass",
                    "pattern": pattern,
                    "matched_text": match.group(),
                    "layer": "encoding_detection",
                    "severity": "high",
                })
                break
        return threats

    def _scan_decoded_variants(self, text: str) -> list:
        threats = []
        variants = []
        try:
            url_decoded = urllib.parse.unquote(text)
            if url_decoded != text:
                variants.append(url_decoded)
        except Exception:
            pass
        try:
            if re.match(r'^[A-Za-z0-9+/=]+$', text[:100]):
                decoded = base64.b64decode(text[:200]).decode("utf-8", errors="ignore")
                if decoded and decoded != text:
                    variants.append(decoded)
        except Exception:
            pass
        for variant in variants:
            for pattern in self.SYSTEM_OVERRIDE_PATTERNS[:5]:
                match = re.search(pattern, variant, re.IGNORECASE)
                if match:
                    threats.append({
                        "type": "system_override",
                        "pattern": f"decoded:{pattern}",
                        "matched_text": match.group(),
                        "layer": "encoding_detection",
                        "severity": "critical",
                    })
                    break
            if threats:
                break
        return threats

    def _semantic_analysis(self, text: str) -> list:
        threats = []
        lower = text.lower()

        manipulation_indicators = [
            "please ignore", "don't follow", "skip the", "bypass the",
            "without checking", "no need to verify", "trust me",
            "this is authorized", "i have permission", "admin said",
            "请忽略", "不要遵守", "跳过", "绕过", "无需验证", "相信我",
            "这是授权的", "我有权限", "管理员说的", "不用检查",
        ]
        for indicator in manipulation_indicators:
            if indicator in lower:
                threats.append({
                    "type": "social_engineering",
                    "pattern": indicator,
                    "matched_text": indicator,
                    "layer": "semantic_rules",
                    "severity": "medium",
                })

        if lower.count("ignore") > 2 or lower.count("override") > 2:
            threats.append({
                "type": "repetition_attack",
                "pattern": "repeated_override_keywords",
                "matched_text": f"ignore:{lower.count('ignore')} override:{lower.count('override')}",
                "layer": "semantic_rules",
                "severity": "medium",
            })

        return threats

    def _context_analysis(self, text: str, context: dict = None) -> list:
        threats = []
        if not context:
            return threats

        agent_caps = context.get("agent_capabilities", [])
        if agent_caps:
            cap_keywords = set()
            for cap in agent_caps:
                parts = cap.split(":")
                if len(parts) >= 2:
                    cap_keywords.add(parts[-1])
            text_lower = text.lower()
            for kw in ["write", "delete", "admin", "root"]:
                if kw in text_lower and kw not in cap_keywords:
                    threats.append({
                        "type": "context_injection",
                        "pattern": f"capability_mismatch:{kw}",
                        "matched_text": kw,
                        "layer": "context_analysis",
                        "severity": "medium",
                    })

        return threats

    def _sanitize_content(self, text: str) -> str:
        sanitized = text
        all_patterns = (
            self.SYSTEM_OVERRIDE_PATTERNS
            + self.PRIVILEGE_DECLARATION_PATTERNS
            + self.UNAUTHORIZED_TOOL_PATTERNS
            + self.ENCODING_BYPASS_PATTERNS
        )
        for pattern in all_patterns:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        if len(sanitized) > 200:
            sanitized = sanitized[:200] + "...[truncated]"
        return sanitized
