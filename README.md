# AgentPass - AI Agent 身份与权限管理系统

面向飞书企业场景的 AI Agent IAM 系统，实现零信任 Agent 身份管理、衰减式 Token 链、跨 Agent 特权升级防御等 12 项创新安全机制。

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend (index.html)                     │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌───────────────┐  │
│  │状态栏    │ │调用链Canvas  │ │Token检视 │ │审计日志流     │  │
│  └──────────┘ └──────────────┘ └──────────┘ └───────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              演示控制台 (6个场景按钮)                      │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ WebSocket + REST API
┌──────────────────────────▼──────────────────────────────────────┐
│                      FastAPI (main.py)                           │
│  /api/health  /api/agents  /api/tokens/*  /api/audit/*          │
│  /api/demo/*  /api/export/*  /api/injection/*  /ws              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Core Security Modules                         │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐          │
│  │ AuthServer   │ │ TokenManager │ │ AuditLogger     │          │
│  │ (Agent Card, │ │ (JWT+RSA-PSS │ │ (Chain Hash,    │          │
│  │  Delegation, │ │  Attenuation │ │  Integrity      │          │
│  │  mTLS)       │ │  Chain)      │ │  Verify)        │          │
│  └──────┬──────┘ └──────────────┘ └─────────────────┘          │
│  ┌──────┴──────┐ ┌──────────────┐ ┌─────────────────┐          │
│  │ Capability  │ │ RiskScorer   │ │ Injection       │          │
│  │ Engine      │ │ (5-Dim Score)│ │ Scanner         │          │
│  │ (Least      │ │ (70↓/90🔒)   │ │ (3-Layer)       │          │
│  │  Privilege) │ │              │ │                 │          │
│  └─────────────┘ └──────────────┘ └─────────────────┘          │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐          │
│  │ Behavior    │ │ Session      │ │ Privilege       │          │
│  │ Analyzer    │ │ Verifier     │ │ Detector        │          │
│  │ (Baseline,  │ │ (Fingerprint │ │ (Escalation     │          │
│  │  2σ/3σ)     │ │  Verify)     │ │  Detection)     │          │
│  └─────────────┘ └──────────────┘ └─────────────────┘          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Agent Layer                                   │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐          │
│  │ DocAgent    │ │ DataAgent    │ │ SearchAgent     │          │
│  │ (RSA Key,   │ │ (Sensitive   │ │ (Web Search,    │          │
│  │  Intent     │ │  Operation   │ │  Limited        │          │
│  │  Parse)     │ │  Check)      │ │  Capability)    │          │
│  └─────────────┘ └──────────────┘ └─────────────────┘          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Feishu Integration                            │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐          │
│  │ Document    │ │ Bitable      │ │ Contact         │          │
│  │ (Create/    │ │ (Read/Write  │ │ (Read Contacts, │          │
│  │  Write)     │ │  Tables)     │ │  Sensitive)     │          │
│  └─────────────┘ └──────────────┘ └─────────────────┘          │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ FeishuClient (Token Refresh, 3x Retry, 10s Timeout) │        │
│  └─────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## 环境变量配置

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `FEISHU_APP_ID` | 否 | 空 | 飞书应用 App ID，未配置则进入 Demo 模式 |
| `FEISHU_APP_SECRET` | 否 | 空 | 飞书应用 App Secret，未配置则进入 Demo 模式 |

## 快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. (可选) 配置飞书凭证
cp env.example .env
# 编辑 .env 填入 FEISHU_APP_ID 和 FEISHU_APP_SECRET

# 3. 启动服务
python3 main.py
# 或
bash start.sh
```

访问 http://localhost:8000 打开前端界面。

## 演示场景

### 场景一：正常委托流程 (7步)
1. 点击「正常委托流程」按钮
2. 用户输入"生成季度销售报告"
3. DocAgent 解析意图，推断权限集合
4. AuthServer 签发 Token（衰减层级 0）
5. DocAgent 携带 Token 调用 DataAgent
6. DataAgent mTLS 签名验证通过
7. DataAgent 调用飞书 API，DocAgent 写入文档

**预期结果**：7 条审计日志逐条出现，全部为 ALLOW 决策

### 场景二：越权拦截流程 (4步)
1. 点击「越权拦截流程」按钮
2. SearchAgent 携带自身 Token 发起调用
3. 能力不匹配，委托被拒绝（ERR_DELEGATION_DENIED）
4. 审计日志出现 DENY 条目，risk_score 自动升级

**预期结果**：500ms 内完成拦截，前端边变红

### 场景三：Token 盗用检测 (4步)
1. 点击「Token盗用检测」按钮
2. 模拟使用盗用 Token 验证
3. mTLS 签名验证失败（ERR_IDENTITY_UNVERIFIABLE）
4. 安全事件已记录

**预期结果**：即使 Token 被截获，因无私钥无法伪造合法请求

### 场景四：Prompt Injection 防御 (3步)
1. 点击「Prompt Injection防御」按钮
2. InjectionScanner 三层检测（关键词+正则+语义）
3. 返回 PROMPT_INJECTION_BLOCKED 错误码

**预期结果**：注入内容被脱敏记录到审计日志

### 场景五：人工审批流程 (4步)
1. 点击「人工审批流程」按钮
2. 涉及敏感操作，系统自动置为 PENDING_HUMAN_APPROVAL
3. 前端显示审批弹窗，30 秒倒计时
4. 批准后签发 5 分钟单次使用 Token

**预期结果**：超时自动拒绝，单次 Token 使用后立即失效

### 场景六：特权升级防御 (4步)
1. 点击「特权升级防御」按钮
2. PrivilegeEscalationDetector 检测到特权升级
3. 该 Agent 所有活跃 Token 被撤销
4. 生成 PRIVILEGE_ESCALATION_ALERT 审计日志

**预期结果**：升级检测后立即撤销所有 Token

## 十二个创新点技术说明

### 1. Agent Card 能力声明标准
参考 Google A2A 协议，为每个 Agent 生成结构化 JSON 能力名片，包含 `agent_id`、`display_name`、`supported_capabilities`、`trust_level`、`endpoint_url`、`authentication_schemes`、`skill_descriptions` 字段。委托前必须先获取目标 Agent Card 进行能力比对，不匹配时在 Token 签发阶段直接拒绝。

### 2. 衰减式 Token 链
参考 IETF 草案 draft-niyikiza-oauth-attenuating-agent-tokens，每次 Token 向下传递时权限范围单调收缩。系统自动计算用户权限 ∩ Agent 能力 ∩ 目标 Agent 能力的交集作为新 Token 的 scope。Token 链中每层的 `max_scope` 字段记录权限上界，任何超过上界的请求立即拒绝并触发告警。

### 3. 跨 Agent 特权升级防御
参考 Johann Rehberger 的 Cross-Agent Privilege Escalation 攻击手法，`PrivilegeEscalationDetector` 在每次 A2A 调用时检测请求 Agent 当前权限是否高于注册基线。检测到异常立刻撤销该 Agent 所有活跃 Token 并生成 `PRIVILEGE_ESCALATION_ALERT` 级别审计日志。

### 4. Agent 会话走私防御
参考 Palo Alto Networks Unit 42 的 Agent Session Smuggling 研究，`SessionIntegrityVerifier` 对每个 A2A 会话绑定不可伪造的会话指纹（时间戳 + 调用链哈希 + 随机 nonce），服务端验证指纹连续性，检测到注入立刻终止会话。

### 5. 人工审批熔断机制
涉及敏感操作（读取 >100 条通讯录、写入多维表格）时自动置为 `PENDING_HUMAN_APPROVAL`，30 秒超时自动拒绝并记录 `TIMEOUT_REJECTION` 日志。批准后签发 5 分钟单次使用 Token，使用后立即失效。

### 6. 实时风险评分引擎
每次授权决策计算 0-100 的 `risk_score`，五维评分：请求频率异常(20%)、调用链深度(20%)、请求时段(15%)、能力组合危险度(25%)、历史违规次数(20%)。≥70 降级只读，≥90 冻结 Agent 300 秒。阈值以可配置常量定义。

### 7. Prompt Injection 语义防御层
`InjectionScanner` 使用关键词匹配 + 正则 + 语义规则三层检测，检测目标包括系统提示词覆盖、权限声明、未授权工具调用。检测到注入返回 `PROMPT_INJECTION_BLOCKED` 错误码，审计日志记录脱敏摘要。

### 8. 不可变审计日志链
参考区块链链式哈希思想，每条审计日志包含 `prev_log_hash` 字段，形成不可篡改日志链。`verify_audit_chain` 接口可验证从系统启动至今所有日志完整性，断裂返回 `CHAIN_BROKEN` 和具体位置。

### 9. Agent 行为基线与异常检测
Agent 注册后前 10 次调用自动建立行为基线（平均请求间隔、常用 capability 组合、典型调用链深度、请求高峰时段）。偏差 >2σ 触发 `BEHAVIOR_ANOMALY` 告警，>3σ 触发 Token 实时撤销。基线每 24 小时滚动更新并持久化到 SQLite。

### 10. 动态最小权限计算
每次 Token 签发时分析任务意图描述文本，关键词提取识别最小 capability 集合。Token 的 scope 始终是用户权限 ∩ Agent 能力 ∩ 任务意图推断权限三者的交集。

### 11. 零信任 mTLS Agent 身份绑定
参考 NIST SP 800-207A，每个 Agent 启动时生成 RSA 密钥对，公钥注册到 AuthServer。每次 A2A 调用请求方用私钥签名请求体，服务端用注册公钥验签。签名验证失败返回 `IDENTITY_UNVERIFIABLE` 错误。

### 12. 可导出的完整演示报告
`export_demo_report` 接口生成独立 HTML 报告，包含调用链图谱、Token 完整字段、审计日志、风险评分曲线、拦截事件摘要，无需联网即可打开。

## 与传统 IAM 的本质差异

| 维度 | 传统 IAM | AgentPass |
|------|----------|-----------|
| 身份主体 | 人类用户 | AI Agent（含 RSA 密钥绑定） |
| 权限模型 | 静态角色(RBAC) | 动态最小权限（意图推断 + 三层交集） |
| Token 特性 | 固定 scope | 衰减式 Token 链（权限单调收缩） |
| 委托机制 | OAuth2 固定 scope | A2A 委托 + Agent Card 能力比对 |
| 安全检测 | 事后审计 | 实时风险评分 + 行为基线异常检测 |
| 会话安全 | Cookie/Session ID | 不可伪造会话指纹 |
| 审计日志 | 可篡改数据库 | 链式哈希不可篡改日志链 |
| 注入防御 | 无 | 三层 Prompt Injection 检测 |
| 特权防御 | 无 | 跨 Agent 特权升级检测 + 自动撤销 |
| 人工审批 | 无 | 熔断机制 + 30s 超时 + 单次 Token |

## OWASP Agentic Top 10 对应关系

| OWASP 编号 | 威胁 | AgentPass 对策 |
|------------|------|----------------|
| Agent-01 | Prompt Injection | InjectionScanner 三层检测 |
| Agent-02 | Sensitive Data Disclosure | 动态最小权限 + 敏感操作审批 |
| Agent-03 | Supply Chain | Agent Card 能力声明 + mTLS 验签 |
| Agent-04 | Denial of Service | 风险评分引擎 + 请求频率异常检测 |
| Agent-05 | Authorization | 衰减式 Token 链 + 三层交集 |
| Agent-06 | Integrity | 链式哈希审计日志 + 会话指纹 |
| Agent-07 | Excessive Agency | 行为基线 + 异常检测 + 2σ/3σ 阈值 |
| Agent-08 | Untrusted Data | Prompt Injection 防御 + 输入验证 |
| Agent-09 | Insecure Output | 脱敏摘要 + 敏感数据保护 |
| Agent-10 | Privilege Escalation | PrivilegeDetector + 自动撤销 Token |

## 已知局限性与扩展路径

**局限性**：
- 单机 SQLite 存储，不支持分布式部署
- 行为基线需要至少 10 次调用才能建立
- 飞书 API 仅实现核心接口
- 前端为单文件 HTML，复杂交互有限

**扩展路径**：
- 替换 SQLite 为 PostgreSQL 支持分布式
- 引入 Redis 缓存提升 Token 验证性能
- 增加更多 Agent 类型（CalendarAgent、EmailAgent）
- 实现 OAuth2 标准协议对接
- 添加 Prometheus 指标导出
- 支持多租户隔离

## 目录结构

```
agentiam/
├── main.py                 # FastAPI 启动入口
├── requirements.txt        # Python 依赖
├── env.example             # 环境变量模板
├── start.sh                # 启动脚本
├── verify_chain.py         # 独立验证审计链完整性
├── core/
│   ├── auth_server.py      # 认证授权核心
│   ├── token_manager.py    # JWT+RSA-PSS Token 管理
│   ├── capability_engine.py # 动态最小权限引擎
│   ├── audit_logger.py     # 链式哈希审计日志
│   ├── behavior_analyzer.py # 行为基线与异常检测
│   ├── risk_scorer.py      # 五维风险评分引擎
│   ├── injection_scanner.py # Prompt Injection 三层检测
│   ├── session_verifier.py  # 会话指纹验证
│   └── privilege_detector.py # 特权升级检测
├── agents/
│   ├── base_agent.py       # Agent 基类（RSA 密钥对）
│   ├── doc_agent.py        # 文档 Agent
│   ├── data_agent.py       # 数据 Agent
│   └── search_agent.py     # 搜索 Agent
├── feishu/
│   ├── client.py           # 飞书 API 客户端
│   ├── document.py         # 飞书文档 API
│   ├── bitable.py          # 飞书多维表格 API
│   └── contact.py          # 飞书通讯录 API
├── frontend/
│   └── index.html          # 单文件前端界面
├── reports/                # 导出报告目录
└── data/                   # SQLite 数据目录
```
