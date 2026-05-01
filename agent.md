# AgentPass 竞赛项目全面增强指令

## 角色定位
你是一位资深全栈安全工程师，同时具备顶级 UI/UX 设计能力。你的任务是将现有 AgentPass 项目改造成参赛级最优秀作品。**所有改动必须在不破坏现有已通过功能的前提下叠加**。

---

## 第一阶段：后端核心安全能力增强

### 1.1 创建 `core/policy_engine.py` — OPA 风格策略即代码引擎

实现一个轻量级但功能完整的策略引擎，灵感来自 OPA/Rego，但用纯 Python 实现，**无需安装 opa 二进制**。

```
功能要求：
- PolicyEngine 类，支持从 YAML 文件加载策略
- 每条策略结构：{ name, description, subjects(list), actions(list), resources(list), conditions(dict), effect: allow|deny }
- conditions 支持: time_range({"from":"09:00","to":"18:00"}), max_attenuation_level(int), 
  required_trust_score(float), deny_if_injection_history(bool), 
  required_delegated_user(bool), max_daily_calls(int)
- evaluate(subject_id, action, resource, context) -> PolicyDecision
- PolicyDecision 包含: allowed(bool), matched_policy(str), reason(str), 
  applicable_policies(list), evaluation_trace(list of steps)
- 支持策略优先级: deny 优先于 allow（类似 AWS IAM）
- 支持通配符匹配: "lark:*:read" 匹配所有 lark read 操作
- 所有策略求值过程写入 evaluation_trace，便于审计
- get_all_policies() -> list  
- reload_policies() 热重载（不重启服务）
- PolicyEngine 作为 AuthServer 的新决策层，在 capability_engine 之后执行
```

同时创建 `policies/` 目录，包含以下 YAML 策略文件：

**`policies/base_policies.yaml`**:
```yaml
policies:
  - name: doc_agent_read_only_after_hours
    description: "DocAgent 非工作时间只允许只读操作"
    subjects: ["agent_doc_001"]
    actions: ["lark:doc:write", "lark:bitable:write"]
    resources: ["*"]
    effect: deny
    conditions:
      time_range_outside: {"from": "09:00", "to": "18:00"}
    priority: 100

  - name: search_agent_no_feishu
    description: "SearchAgent 永远不能访问飞书内部数据"
    subjects: ["agent_search_001"]
    actions: ["lark:*"]
    resources: ["feishu_internal"]
    effect: deny
    priority: 200

  - name: high_risk_readonly
    description: "风险分 >= 70 降级为只读"
    subjects: ["*"]
    actions: ["*:write", "*:delete"]
    resources: ["*"]
    effect: deny
    conditions:
      min_risk_score: 70
    priority: 150

  - name: max_delegation_depth
    description: "委托链深度不超过3层"
    subjects: ["*"]
    actions: ["delegate:*"]
    resources: ["*"]
    effect: deny
    conditions:
      min_attenuation_level: 3
    priority: 300

  - name: require_delegated_user_for_sensitive
    description: "敏感操作必须有委托用户上下文"
    subjects: ["*"]
    actions: ["lark:contact:read", "lark:bitable:write"]
    resources: ["*"]
    effect: deny
    conditions:
      missing_delegated_user: true
    priority: 120
```

**`policies/data_agent_policies.yaml`**:
```yaml
policies:
  - name: data_agent_allow_doc_delegation
    description: "DataAgent 允许来自 DocAgent 的委托"
    subjects: ["agent_doc_001"]
    actions: ["lark:bitable:read", "lark:contact:read", "lark:calendar:read"]
    resources: ["feishu_internal"]
    effect: allow
    priority: 50

  - name: data_agent_block_external_delegation
    description: "DataAgent 拒绝来自 SearchAgent 的所有飞书访问委托"
    subjects: ["agent_search_001"]
    actions: ["lark:*"]
    resources: ["feishu_internal"]
    effect: deny
    priority: 500
```

### 1.2 创建 `core/svid_manager.py` — SPIFFE 风格工作负载身份

参考 SPIFFE/SPIRE 标准，实现 Agent 身份证书体系，**纯 Python，使用 cryptography 库**：

```
SVIDManager 类：
  __init__(trust_domain="agentpass.local")
    - 初始化信任域 CA（自签名 RSA-2048 根证书）
    - _ca_key, _ca_cert
    - _svids: Dict[agent_id, SVID]

  issue_svid(agent_id, agent_type, ttl_seconds=3600) -> SVID
    - 生成 SPIFFE ID: spiffe://{trust_domain}/ns/prod/agent/{agent_id}
    - 为该 Agent 生成独立 RSA-2048 密钥对
    - 签发 X.509 证书，SAN 字段嵌入 SPIFFE URI
    - 证书 Subject: CN=agentpass-{agent_id}
    - 返回 SVID(spiffe_id, cert_pem, private_key_pem, expires_at, agent_id)
    
  verify_svid(cert_pem) -> SVIDVerifyResult
    - 验证证书由本 CA 签发（链验证）
    - 验证证书未过期
    - 提取 SPIFFE ID
    - 返回 SVIDVerifyResult(valid, spiffe_id, agent_id, error)
    
  get_svid(agent_id) -> Optional[SVID]
  
  rotate_svid(agent_id) -> SVID
    - 吊销旧证书，签发新证书，触发 svid_rotated 事件
    
  get_trust_bundle() -> dict
    - 返回信任域 CA 公钥（JSON 格式，类似 SPIRE trust bundle）
    - {"trust_domain": "agentpass.local", "x509_authorities": [ca_cert_pem], "refresh_hint": 3600}
    
  attest_agent(agent_id, agent_type, public_key_pem) -> AttestationResult
    - 工作负载证明流程：
      1. 验证 agent_id 格式合法
      2. 验证 public_key_pem 是合法 RSA/EC 公钥
      3. 检查 agent_id 是否已在 AuthServer 注册
      4. 签发 SVID
    - 返回 AttestationResult(attested, svid, spiffe_id, attestation_token)
    - attestation_token 是短期令牌（30秒），用于后续首次 Token 申请

SVID dataclass:
  spiffe_id: str
  cert_pem: str  
  private_key_pem: str
  expires_at: float
  agent_id: str
  trust_domain: str
  issued_at: float
  serial_number: str
```

### 1.3 创建 `core/dpop_verifier.py` — DPoP 令牌绑定防盗用

参考 RFC 9449 (DPoP)，实现演示性的 Proof-of-Possession 绑定：

```
DPoPVerifier 类：
  __init__()
    - _used_jti: set (已使用的 DPoP proof jti，防重放)
    - _cleanup_interval = 300 秒
    
  create_dpop_proof(private_key_pem, htm, htu, access_token=None) -> str
    - 生成 DPoP Proof JWT（头部 typ=dpop+jwt, alg=RS256）
    - payload: {jti(随机), htm(HTTP方法), htu(URL), iat(当前时间), 
                ath(access_token SHA-256 哈希，可选)}
    - 用私钥签名
    
  verify_dpop_proof(dpop_proof_jwt, public_key_pem, htm, htu, 
                    access_token=None, max_age_seconds=60) -> DPoPResult
    - 验证签名（RS256）
    - 验证 jti 未被使用（防重放），使用后加入 _used_jti
    - 验证 htm 匹配当前 HTTP 方法
    - 验证 htu 匹配当前 URL  
    - 验证 iat 在 max_age_seconds 内
    - 如有 ath，验证与 access_token 哈希匹配
    - 失败返回 DPoPResult(valid=False, error_code="DPOP_*")
    
  bind_token_to_key(jti, public_key_thumbprint) -> bool
    - 将 Token JTI 绑定到公钥指纹
    - 存储在内存 dict: _token_key_bindings
    
  verify_token_binding(jti, public_key_pem) -> bool
    - 检查 Token JTI 是否与提供的公钥绑定匹配

DPoPResult dataclass:
  valid: bool
  agent_id: str = ""
  jti: str = ""
  error_code: str = ""
  error_message: str = ""
```

### 1.4 创建 `core/rate_limiter.py` — 滑动窗口速率限制

```
SlidingWindowRateLimiter 类：
  __init__(db_path)
    - 初始化 SQLite 表 rate_limit_events
    - 预定义限制配置（可被策略引擎覆盖）：
      LIMITS = {
        "token_issue": {"window_seconds": 60, "max_requests": 20},
        "token_delegate": {"window_seconds": 60, "max_requests": 30},
        "token_verify": {"window_seconds": 60, "max_requests": 100},
        "feishu_api": {"window_seconds": 60, "max_requests": 10},
      }
    
  check_rate_limit(agent_id, action_type) -> RateLimitResult
    - 滑动窗口算法：统计 window 内请求数
    - 超限返回 RateLimitResult(allowed=False, retry_after=N, current_count=M, limit=L)
    - 允许返回 RateLimitResult(allowed=True, current_count=M, remaining=L-M)
    
  record_request(agent_id, action_type)
    - 写入 rate_limit_events 表
    - 异步清理过期记录（超过最大 window 的）
    
  get_agent_rate_stats(agent_id) -> dict
    - 返回各 action_type 的当前统计

RateLimitResult dataclass:
  allowed: bool
  current_count: int
  limit: int
  window_seconds: int
  retry_after: float = 0
  remaining: int = 0
```

将 `check_rate_limit` 调用插入 `AuthServer.issue_token`、`delegate_token`、`verify_token` 的最开头。速率超限时写审计日志 `action_type="rate_limit_exceeded"`, `decision="DENY"`, `error_code="ERR_RATE_LIMITED"`。

### 1.5 创建 `core/circuit_breaker.py` — Agent 调用链熔断器

```
CircuitBreaker 类：
  状态机：CLOSED -> OPEN -> HALF_OPEN -> CLOSED
  
  每个 agent_id 独立维护一个熔断状态。
  
  配置：
    failure_threshold = 5      # 连续失败 N 次触发开路
    recovery_timeout = 60      # 开路后等待 N 秒进入半开
    success_threshold = 2      # 半开状态成功 N 次恢复闭路
    
  record_success(agent_id)
  record_failure(agent_id, error_type)
  can_proceed(agent_id) -> CircuitBreakerState
    - 返回: {allowed: bool, state: "CLOSED|OPEN|HALF_OPEN", 
             failure_count: int, recovery_at: float}
  get_all_states() -> Dict[str, dict]
  reset(agent_id)
  
  状态变化时通过 ws_notify 推送 "circuit_breaker_state_change" 事件
```

在 `AuthServer.delegate_token` 中，成功委托调用 `circuit_breaker.record_success(target_agent_id)`，失败调用 `circuit_breaker.record_failure(target_agent_id, error_type)`。每次调用前先 `can_proceed(target_agent_id)`，OPEN 状态直接返回 `ERR_CIRCUIT_OPEN`。

### 1.6 创建 `core/nonce_manager.py` — 防重放攻击 Nonce 管理

```
NonceManager 类（单例模式）：
  __init__()
    - _issued_nonces: Dict[str, float]  # nonce -> issued_at
    - _used_nonces: set
    - nonce_ttl = 300  # 5分钟内必须使用
    
  issue_nonce(agent_id) -> str
    - 生成 32 字节随机 nonce（hex）
    - 关联 agent_id 和 issued_at，存入 _issued_nonces
    - 同时记录到 SQLite nonces 表（持久化）
    
  consume_nonce(nonce, agent_id) -> NonceResult
    - 验证 nonce 存在且未使用
    - 验证 agent_id 匹配
    - 验证未超过 nonce_ttl
    - 消费后加入 _used_nonces
    - 返回 NonceResult(valid, error_code)
    
  cleanup_expired()
    - 定期清理过期 nonce（由后台任务调用）
```

在 `AuthServer` 中新增 API 端点 `/api/nonce` (GET) 供 Agent 申请 Nonce，在 `issue_token` 中可选验证 nonce（若请求中携带 nonce 字段则强制验证）。

### 1.7 增强 `core/auth_server.py`

在现有代码基础上叠加以下功能（不删除任何现有逻辑）：

```python
# 新增成员变量（在 __init__ 中初始化）:
from core.policy_engine import PolicyEngine
from core.svid_manager import SVIDManager
from core.dpop_verifier import DPoPVerifier
from core.rate_limiter import SlidingWindowRateLimiter
from core.circuit_breaker import CircuitBreaker
from core.nonce_manager import NonceManager

self.policy_engine = PolicyEngine("policies/")
self.svid_manager = SVIDManager(trust_domain="agentpass.local")
self.dpop_verifier = DPoPVerifier()
self.rate_limiter = SlidingWindowRateLimiter(db_path)
self.circuit_breaker = CircuitBreaker()
self.nonce_manager = NonceManager()
```

**在 `register_agent` 中叠加**：
```python
# 注册成功后，为 Agent 签发 SVID
svid = self.svid_manager.issue_svid(agent_id, agent_type)
# 存储 SPIFFE ID 到 agents 表（需在 _init_db 中新增 spiffe_id 列）
# 将 SVID 信息一并返回给调用方
result["spiffe_id"] = svid.spiffe_id
result["svid_expires_at"] = svid.expires_at
```

**在 `issue_token` 中叠加（在最开头，在现有逻辑之前）**：
```python
# 1. 速率限制检查
rl = self.rate_limiter.check_rate_limit(agent_id, "token_issue")
if not rl.allowed:
    self.audit_logger.write_log(action_type="token_issue", decision="DENY",
        error_code="ERR_RATE_LIMITED", ...)
    raise PermissionError(f"Rate limit exceeded. Retry after {rl.retry_after:.0f}s [ERR_RATE_LIMITED]")

# 2. 策略引擎检查（在 capability_engine 后插入）
for cap in granted_caps:
    policy_decision = self.policy_engine.evaluate(
        subject_id=agent_id,
        action=cap,
        resource="feishu_internal" if cap.startswith("lark:") else "web",
        context={"risk_score": risk_score, "attenuation_level": 0,
                 "delegated_user": delegated_user or "",
                 "hour": time.localtime().tm_hour}
    )
    if not policy_decision.allowed:
        # 记录审计日志，抛出策略拒绝异常
        ...
```

**在 `delegate_token` 中叠加**：
```python
# 1. 速率限制
# 2. 熔断器检查 can_proceed(target_agent_id)
# 3. 策略引擎评估（针对 parent_agent_id 执行委托动作）
# 4. 成功后 circuit_breaker.record_success
# 5. 失败后 circuit_breaker.record_failure
```

**新增方法 `get_svid(agent_id)` 和 `rotate_svid(agent_id)`**。

### 1.8 增强 `main.py` — 新增 API 端点

在现有路由基础上叠加以下端点（绝对不删除任何现有路由）：

```python
# SVID 相关
GET  /api/svid/{agent_id}              # 获取 Agent 的 SVID 信息
POST /api/svid/{agent_id}/rotate       # 轮换 SVID
GET  /api/trust-bundle                 # 获取信任域 CA 公钥 bundle

# 策略引擎相关
GET  /api/policies                     # 列出所有策略
POST /api/policies/evaluate            # 手动测试策略评估（需 subject/action/resource/context）
POST /api/policies/reload              # 热重载策略文件
GET  /api/policies/simulation          # 策略模拟（dry-run，不实际执行）

# 速率限制
GET  /api/rate-limits/{agent_id}       # 查看 Agent 当前速率统计
GET  /api/rate-limits                  # 所有 Agent 速率概览

# 熔断器
GET  /api/circuit-breakers             # 所有熔断器状态
POST /api/circuit-breakers/{agent_id}/reset  # 重置熔断器

# Nonce
GET  /api/nonce?agent_id=xxx           # 申请 Nonce

# DPoP
POST /api/tokens/verify-dpop           # 含 DPoP 验证的 Token 验证

# 系统
GET  /api/system/capabilities-matrix  # 能力矩阵（所有Agent x 所有Capabilities）
GET  /api/system/threat-summary       # 威胁汇总（最近注入/升级/盗用事件）
GET  /api/system/timeline             # 全局事件时间线（最近 100 事件）

# 后台任务（启动时开始）：
# - 每 10 秒：check_and_timeout_approvals + cleanup_nonces
# - 每 30 秒：刷新 Agent 风险评分到 agents 表
# - 每 60 秒：熔断器状态广播
```

**在 `startup` 事件中叠加**（不替换现有逻辑）：
```python
# 1. 为所有 Agent 签发初始 SVID
# 2. 加载策略引擎
# 3. 启动后台任务（使用 asyncio.create_task + 无限循环）
```

### 1.9 增强 `core/audit_logger.py`

在 `_init_db` 中增加新表（现有表结构不变）：

```sql
CREATE TABLE IF NOT EXISTS policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    subject_id TEXT DEFAULT '',
    action TEXT DEFAULT '',
    resource TEXT DEFAULT '',
    matched_policy TEXT DEFAULT '',
    effect TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    evaluation_trace TEXT DEFAULT '[]',
    context TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS svid_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    agent_id TEXT NOT NULL,
    event_type TEXT DEFAULT '',  -- issued/rotated/expired/verified
    spiffe_id TEXT DEFAULT '',
    expires_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    consumed INTEGER DEFAULT 0,
    consumed_at REAL DEFAULT 0
);
```

新增方法：
```python
def write_policy_decision(self, subject_id, action, resource, matched_policy, 
                           effect, reason, evaluation_trace, context) -> dict
def get_policy_decisions(self, limit=50) -> list
def write_svid_event(self, agent_id, event_type, spiffe_id, expires_at) -> dict  
def get_threat_summary(self) -> dict
    # 返回: {
    #   injection_events: last 10,
    #   privilege_escalation_events: last 10,
    #   token_theft_events: last 10,
    #   rate_limit_events: last 10,
    #   circuit_breaker_events: last 10,
    #   summary: {total_threats_24h, critical_count, high_count}
    # }
def get_global_timeline(self, limit=100) -> list
    # 合并所有表的事件，按时间排序返回统一格式
def get_capabilities_matrix(self, agents: list) -> dict
    # 返回所有 Agent × 所有 Capability 的权限矩阵
    # {agents: [...], capabilities: [...], matrix: [[bool]]}
```

---

## 第二阶段：前端彻底重构

### 2.1 全面重写 `frontend/index.html`

**设计规范**：
- **风格**：企业级"赛博安全指挥中心"风，深邃太空蓝+电光绿+警戒红，玻璃拟态卡片，微粒子背景
- **布局**：全屏三列自适应网格，顶部状态栏 + 左侧 Agent 列 + 中央主视图 + 右侧详情面板
- **动效**：Token 在 Agent 之间流动的粒子动画，风险评分实时动态仪表盘，审计日志逐条滑入
- **字体**：正文 `Inter` / `Noto Sans SC`，等宽 `JetBrains Mono`
- **外部依赖（全部从 CDN 加载，无需 npm）**：
  - `https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js`
  - `https://cdn.tailwindcss.com`
  - `https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js`

**页面结构（严格按以下顺序实现）**：

#### 2.1.1 顶部导航栏 `<header>`

```
[🛡️ AgentPass]  [系统状态: ● 正常]  [活跃Token: N]  [今日拦截: N]  
[审计链: ✓完整]  [威胁等级: 🟢低/🟡中/🔴高]  [WS: ●连接中]
[右侧：演示模式横幅 Demo Mode / 导出报告按钮]
```

威胁等级根据 `deny_count + injection_count + alert_count` 动态计算。

#### 2.1.2 左侧面板 `<aside>` — Agent 状态列

三个 Agent 卡片，每张卡片包含：
- Agent 图标（根据 type 显示不同 SVG 图标）
- `display_name` + `agent_type`
- SPIFFE ID（灰色小字，可复制）
- 实时风险评分：带颜色的圆形 SVG 仪表（0-100，<40绿/40-70黄/>70红）
- 信任分趋势迷你折线图（用 Chart.js 或纯 SVG）
- 能力标签列表（每个 capability 一个 badge，颜色按域区分：lark:*蓝/web:*紫/delegate:*橙）
- 熔断器状态指示灯（CLOSED绿/OPEN红/HALF_OPEN黄）
- 「查看详情」按钮，展开详情抽屉

Agent 卡片在以下情况有特效：
- 收到 token_issued 事件：卡片边框绿光闪烁一次
- 收到 delegation_denied 事件：卡片边框红光闪烁
- 收到 privilege_escalation 事件：卡片整体震动动画（CSS `@keyframes shake`）

#### 2.1.3 中央主视图区域 `<main>` — 选项卡切换

实现六个选项卡，通过顶部选项卡栏切换，**默认显示"调用链"**：

**选项卡 1：调用链（D3 力导向图）**

用 D3.js v7 实现交互式力导向图：

```javascript
// 节点渲染：
// - 每个 Agent 是一个圆形节点（radius=40）
// - 外圈是旋转的虚线圆（risk_score越高旋转越快，>70时变红色）
// - 节点内显示 Agent 名称缩写 + 信任分
// - 节点颜色：DocAgent=电光蓝，DataAgent=电光绿，SearchAgent=紫色

// 边渲染：
// - 成功委托：实线绿色箭头，线宽=success_count/10（最大4px）
// - 失败委托：虚线红色箭头
// - 双向委托：分开渲染两条略微弯曲的贝塞尔曲线

// Token 流动粒子动画（D3 transition）：
// - Token 签发后：一个发光点从 "AuthServer" 中心节点沿边飞向目标 Agent
// - 委托成功后：一个绿色粒子沿边从 parent -> target 滑动（1.5秒动画）
// - 拦截事件后：一个红色粒子在边中途消失（爆炸效果：scale 0.1->2->0）

// "AuthServer" 特殊节点：
// - 八边形形状，放置在图的中心
// - 带 spinning 光环动画

// 交互：
// - 点击节点：在右侧详情面板展示该 Agent 完整信息 + SVID + 历史 Token
// - 点击边：展示该委托关系的所有审计记录
// - 右键节点：显示上下文菜单（查看 Token/撤销所有 Token/重置熔断器）
// - 拖拽节点：可手动调整布局（drag.on("end") 固定节点位置）
// - 双击空白：重置布局
```

**选项卡 2：Token 检视台**

左右分栏布局：
- 左栏：Token 列表（可筛选 agent_id、按 active/revoked/expired 过滤）
  - 每条 Token 显示：jti 前8位 / agent_id / scope / attenuation_level / 剩余时间进度条 / 状态标签
  - 点击 Token 在右栏展示详情
- 右栏：JWT 解析器
  - Header / Payload / Signature 三个标签页
  - 每个字段彩色高亮（key=青色，string=绿色，number=橙色，bool=紫色）
  - 特殊字段说明气泡（鼠标悬停 `attenuation_level` 显示"令牌衰减层级，值越大权限越小"）
  - `trust_chain` 字段展示为水平箭头链：`DocAgent → DataAgent`
  - `max_scope` vs `scope` 对比展示（高亮差异，说明权限衰减了哪些）
  - 底部：「撤销此 Token」红色按钮 + 「查看委托 Token」按钮

**选项卡 3：策略控制台**

策略即代码可视化编辑器：
- 左侧：策略列表（按文件分组，每条策略卡片显示 name/effect/subjects/actions）
  - effect=allow 卡片左边绿色竖条
  - effect=deny 卡片左边红色竖条
  - 每条策略右上角「编辑」/「禁用」/「删除」按钮
- 中央：策略模拟器
  ```
  Subject:  [下拉选择 Agent]
  Action:   [下拉选择 Capability]
  Resource: [下拉 feishu_internal/web]
  Context:  [JSON 编辑框，pre-fill 当前时间/风险分]
  [▶ 模拟评估] 按钮
  ```
  点击后调用 `/api/policies/evaluate`，展示：
  - `ALLOW / DENY` 大字结果（绿/红）
  - 匹配策略名 + 匹配原因
  - evaluation_trace 步骤列表（每步骤显示"检查策略X → 跳过/命中"）
- 右侧：策略统计图（Pie Chart：各 effect 的策略数量）
- 底部：「热重载策略」按钮（调用 `/api/policies/reload`）

**选项卡 4：审计链查证**

完整的审计日志可视化界面：
- 顶部筛选栏：[Agent选择] [决策(ALLOW/DENY/ALERT)] [时间范围(1h/24h/7d)] [Trace ID] [🔍搜索]
- 审计链完整性验证横幅：实时显示 `✓ 审计链完整 (N条记录)` 或 `⚠ 链断裂于第N条`
- 日志流（虚拟化滚动，支持大量条目）：
  每条日志展示：
  ```
  [时间戳] [决策标记] [Agent] → [目标Agent] [动作类型]
  ┌─────────────────────────────────────────────┐
  │ log_id: ...  prev_hash: ...8f  curr_hash: ...3a │
  │ 风险分: N  注入检测: ✓/✗  特权升级: ✓/✗        │
  │ [Trace: xxxxxxxx] [错误码: ERR_XXX]            │
  └─────────────────────────────────────────────┘
  ```
  点击展开完整 JSON
- Trace ID 视图：按 trace_id 分组，展示完整调用链时间线（水平步骤图）
- 右侧统计栏：允许/拒绝/告警比例饼图 + 最近 24h 趋势折线图（每小时粒度）
- 导出按钮：CSV 导出 + JSON 导出 + 调用 `/api/export/demo-report` 生成 HTML 报告

**选项卡 5：安全威胁地图**

威胁可视化面板：
- 顶部：威胁等级仪表（半圆弧形，绿→黄→红，指针动态指向当前等级）
- 威胁类型卡片网格（2行3列）：
  每类卡片包含：图标、威胁类型名、近24h计数、趋势箭头、最近事件摘要
  - Prompt Injection（🧬图标）
  - 特权升级（⚡图标）
  - Token 盗用（🔑图标）
  - 速率异常（📈图标）
  - 熔断触发（🔌图标）
  - 人工审批超时（⏳图标）
- 威胁时间线：横向时间轴，不同颜色的事件点，悬停显示详情
- 安全告警列表：未确认告警标红，「确认」按钮（调用 `/api/security/alerts/:id/acknowledge`）

**选项卡 6：能力矩阵**

调用 `/api/system/capabilities-matrix` 展示：
- X轴：所有注册 Capability
- Y轴：所有注册 Agent
- 交叉格：绿色✓（拥有）/ 灰色✗（不拥有）/ 橙色⚠（委托权限）
- 悬停格显示：权限来源（直接注册/委托获得）
- 点击行：高亮该 Agent 的所有权限
- 点击列：高亮拥有该 Capability 的所有 Agent

#### 2.1.4 右侧详情面板 `<aside>` — 上下文详情抽屉

默认显示系统总览，当用户点击图节点/Token/日志后，滑入对应详情：

**默认状态（系统总览）**：
- 实时更新的关键指标数字（Counter 动画）：
  - 总注册 Agent / 活跃 Token / 已撤销 Token
  - 今日授权 ALLOW / DENY / ALERT 数
  - Prompt Injection 拦截次数
  - 特权升级检测次数
- 系统运行时长
- 最近 3 条安全告警（可点击跳转到威胁地图）

**Agent 详情状态（点击节点后）**：
- Agent 基础信息（ID / Name / Type / Status）
- SPIFFE ID + 证书有效期（含进度条）
- 信任分趋势图（最近 20 次操作的时序图）
- 风险评分五维雷达图（用 Chart.js Radar）：
  - 维度：请求频率/链深度/时段/能力组合/违规历史
- 活跃 Token 列表（含衰减层级）
- 最近 10 条审计记录
- 操作按钮：「撤销所有 Token」「重置熔断器」「查看 SVID」

#### 2.1.5 演示控制台（底部固定栏，可折叠）

```
[正常委托] [越权拦截] [Token盗用] [Prompt注入] [人工审批] [特权升级]
[自定义场景：输入框 + 运行按钮]
---
步骤流（水平时间线模式，每步骤一个卡片，成功绿/失败红/告警黄）
每步卡片包含：步骤编号 + 描述 + 子标题 + jti/error 详情
```

「自定义场景」输入框允许用户输入自然语言指令，调用 LLM（可选）或预设解析逻辑运行演示。

### 2.2 JavaScript 核心逻辑要求

所有 JS 写在单个 `<script>` 块中，组织为模块对象：

```javascript
const App = {
  state: {
    agents: [],
    activeTokens: [],
    auditLogs: [],
    graphData: {nodes: [], edges: []},
    policies: [],
    threatSummary: {},
    circuitBreakers: {},
    rateStats: {},
    svidData: {},
    capabilitiesMatrix: {},
    currentTab: 'callgraph',
    selectedAgent: null,
    selectedToken: null,
    ws: null,
    charts: {},
    d3Graph: null,
    refreshIntervals: {}
  },
  
  api: { /* 所有 fetch 调用 */ },
  ws: { /* WebSocket 管理，自动重连 */ },
  ui: { /* DOM 操作辅助函数 */ },
  graph: { /* D3 力导向图逻辑 */ },
  charts: { /* Chart.js 初始化和更新 */ },
  particles: { /* Token 流动粒子动画 */ },
  demo: { /* 演示场景控制 */ },
  init: async function() { /* 启动入口 */ }
};
```

**WebSocket 事件处理映射**（所有现有事件 + 新增事件）：
```javascript
const WS_HANDLERS = {
  'token_issued': (data) => {
    App.particles.animateTokenFlow('auth_server', data.agent_id, 'success');
    App.graph.flashNode(data.agent_id, 'success');
    App.ui.refreshTokenPanel();
  },
  'delegation_success': (data) => {
    App.particles.animateTokenFlow(data.from, data.to, 'delegate');
    App.graph.animateEdge(data.from, data.to, 'success');
  },
  'delegation_denied': (data) => {
    App.particles.animateTokenFlow(data.from, data.to, 'blocked');
    App.graph.flashEdge(data.from, data.to, 'error');
    App.ui.showToast(`委托被拦截: ${data.from} → ${data.to}`, 'error');
  },
  'privilege_escalation': (data) => {
    App.ui.shakeNode(data.agent_id);
    App.ui.showThreatAlert('PRIVILEGE_ESCALATION', data);
  },
  'circuit_breaker_state_change': (data) => {
    App.ui.updateCircuitBreakerIndicator(data.agent_id, data.state);
  },
  'human_approval_required': showApprovalModal,
  'rate_limit_exceeded': (data) => App.ui.showRateLimitWarning(data),
  'svid_rotated': (data) => App.ui.refreshSVIDDisplay(data.agent_id),
  'injection_detected': (data) => App.ui.flashThreatCard('injection'),
};
```

**粒子动画实现（重要）**：
```javascript
// 在 D3 SVG 图层上实现粒子效果
// 粒子：一个带发光效果的圆点（r=4, filter: blur + glow）
// 运动：沿贝塞尔曲线运动，duration=1500ms，easing=d3.easeCubicInOut
// 类型：
//   success -> 绿色粒子，到达目标后展开波纹
//   blocked -> 红色粒子，在边中点爆炸（scale→3 + opacity→0）
//   delegate -> 蓝色粒子，尾迹效果（前2帧保留灰色残影）
// 同时支持多个粒子并发（push到粒子队列，异步执行）
```

### 2.3 CSS 设计系统

在 `<style>` 中定义完整设计系统（覆盖现有，全部重写）：

```css
/* 色彩系统 */
:root {
  /* 背景层次（从深到浅） */
  --void: #020408;
  --base: #060d19;
  --surface: #0b1526;
  --elevated: #111e35;
  --overlay: #172541;
  
  /* 玻璃态效果 */
  --glass-bg: rgba(11, 21, 38, 0.7);
  --glass-border: rgba(56, 189, 248, 0.12);
  --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  --glass-blur: blur(16px);
  
  /* 语义颜色 */
  --success: #10b981;
  --success-glow: rgba(16, 185, 129, 0.3);
  --danger: #ef4444;
  --danger-glow: rgba(239, 68, 68, 0.3);
  --warning: #f59e0b;
  --warning-glow: rgba(245, 158, 11, 0.3);
  --info: #3b82f6;
  --info-glow: rgba(59, 130, 246, 0.3);
  
  /* 品牌色 */
  --brand-primary: #38bdf8;
  --brand-secondary: #818cf8;
  --brand-accent: #34d399;
  
  /* 文字 */
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #475569;
  --text-code: #7dd3fc;
  
  /* 动效 */
  --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-base: 300ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 500ms cubic-bezier(0.4, 0, 0.2, 1);
}

/* 玻璃卡片 */
.glass-card {
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  border-radius: 16px;
  backdrop-filter: var(--glass-blur);
  box-shadow: var(--glass-shadow);
}

/* 发光边框 */
.glow-blue { box-shadow: 0 0 0 1px var(--brand-primary), 0 0 20px rgba(56,189,248,0.2); }
.glow-green { box-shadow: 0 0 0 1px var(--success), 0 0 20px var(--success-glow); }
.glow-red { box-shadow: 0 0 0 1px var(--danger), 0 0 20px var(--danger-glow); }

/* 节点震动动画 */
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  10%, 50%, 90% { transform: translateX(-4px); }
  30%, 70% { transform: translateX(4px); }
}

/* 扫描线效果（背景装饰） */
@keyframes scanline {
  0% { transform: translateY(-100%); }
  100% { transform: translateY(100vh); }
}

/* 数字滚动动画 */
@keyframes countUp {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* 危险状态脉冲 */
@keyframes danger-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.4); }
  50% { box-shadow: 0 0 0 12px rgba(239,68,68,0); }
}

/* 所有 transition 使用 CSS 变量 */
```

---

## 第三阶段：CLI 演示工具

### 3.1 创建 `cli/demo_cli.py` — Rich 终端演示工具

安装依赖：`rich` （已在 requirements.txt 中添加）

```python
"""
用 Rich 库实现一个精美的终端演示工具，支持：
  python3 cli/demo_cli.py                    # 交互式菜单
  python3 cli/demo_cli.py run normal         # 运行正常委托
  python3 cli/demo_cli.py run all            # 运行所有6个场景
  python3 cli/demo_cli.py agents             # 列出所有 Agent
  python3 cli/demo_cli.py audit --tail 20    # 查看审计日志
  python3 cli/demo_cli.py verify-chain       # 验证审计链
  python3 cli/demo_cli.py policies           # 列出所有策略
  python3 cli/demo_cli.py token decode <jwt> # 解码 JWT
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
import httpx, json, sys, time

BASE_URL = "http://localhost:8000"
console = Console()

# 关键实现要求：
# 1. 运行演示场景时，使用 Live + Layout 实时展示步骤进度
#    左侧：步骤列表（成功✅/失败❌/进行中🔄）
#    右侧：当前步骤的 Token 或错误详情（JSON 语法高亮）
# 2. Agent 列表用 Rich Table，包含彩色风险评分
# 3. 审计日志用彩色 Table，ALLOW 绿/DENY 红/ALERT 黄
# 4. JWT 解码用 Syntax 高亮 JSON
# 5. 审计链验证显示每条记录的哈希链
# 6. 交互菜单用 Prompt（rich 的 Prompt.ask 或 questionary）
# 7. 所有错误有友好的 Panel 错误展示，而非 traceback
```

---

## 第四阶段：增强 requirements.txt

在现有依赖基础上**追加**（不替换任何现有依赖）：

```
rich==13.7.1
pyyaml==6.0.1
pytest==7.4.3
pytest-asyncio==0.23.2
httpx==0.25.2    # 已存在，保留
```

---

## 第五阶段：更新 README.md

在现有 README 内容末尾**追加**以下章节（不替换任何现有内容）：

### 5.1 新增"策略即代码"章节

````markdown
## 策略即代码 (Policy-as-Code)

策略文件位于 `policies/` 目录，YAML 格式，**无需重启服务**即可热重载：

```bash
# 修改策略文件后热重载
curl -X POST http://localhost:8000/api/policies/reload

# 模拟策略评估（不实际执行）
curl -X POST http://localhost:8000/api/policies/evaluate \
  -H "Content-Type: application/json" \
  -d '{"subject_id":"agent_search_001","action":"lark:bitable:read","resource":"feishu_internal","context":{}}'
```

策略求值顺序：deny 优先于 allow，高优先级优先于低优先级。
````

### 5.2 新增"SPIFFE 工作负载身份"章节

````markdown
## SPIFFE 风格工作负载身份

每个 Agent 在注册时自动获得 SPIFFE 身份文档（SVID）：

```
spiffe://agentpass.local/ns/prod/agent/agent_doc_001
```

查询 Agent SVID：
```bash
curl http://localhost:8000/api/svid/agent_doc_001
```

获取信任域 CA Bundle：
```bash
curl http://localhost:8000/api/trust-bundle
```
````

### 5.3 新增"扩展性架构"章节说明

```markdown
## 扩展性路径（生产级）

| 组件 | 当前实现 | 生产替换方案 |
|------|----------|------------|
| 存储 | SQLite | PostgreSQL + Redis 缓存 |
| Token 验证 | 内存+DB | Redis 分布式缓存，<1ms |
| 策略引擎 | 内置 YAML | 集成真实 OPA，Rego 语言 |
| 工作负载身份 | 模拟 SVID | 真实 SPIRE server |
| 速率限制 | SQLite 滑窗 | Redis + Lua 脚本原子操作 |
| 审计日志 | SQLite 链式哈希 | Kafka + 不可变存储（S3/GCS） |
| 监控 | WebSocket 实时 | Prometheus + Grafana |
| 多租户 | 单实例 | 命名空间隔离 + 独立 DB |
```

---

## 第六阶段：工程质量保障

### 6.1 创建 `tests/` 目录

```
tests/
  __init__.py
  test_token_manager.py    # TokenManager 单元测试
  test_capability_engine.py # CapabilityEngine 单元测试  
  test_injection_scanner.py # InjectionScanner 测试（包含绕过尝试）
  test_privilege_detector.py # PrivilegeDetector 测试
  test_policy_engine.py    # PolicyEngine 测试
  test_audit_chain.py      # 审计链完整性测试
  test_rate_limiter.py     # 速率限制测试
  test_auth_server_e2e.py  # 端到端流程测试（正常委托/越权拦截/Token盗用）
```

每个测试文件最少包含 5 个测试用例，全部使用 pytest，关键用例：
- `test_token_attenuation_chain`: 验证委托 Token 的 scope 单调收缩
- `test_injection_bypass_attempts`: 用 10 个真实 Prompt Injection 样本测试
- `test_audit_chain_integrity`: 写入 50 条日志后验证链完整性
- `test_privilege_escalation_detection`: 测试各种升级场景
- `test_policy_engine_deny_override_allow`: 验证 deny 优先级

### 6.2 创建 `Makefile`

```makefile
.PHONY: install run test lint clean

install:
	pip3 install -r requirements.txt --break-system-packages

run:
	python3 main.py

test:
	python3 -m pytest tests/ -v --tb=short

lint:
	python3 -m py_compile main.py core/*.py agents/*.py feishu/*.py
	echo "Syntax check passed"

demo-all:
	python3 cli/demo_cli.py run all

verify:
	python3 verify_chain.py

clean:
	rm -rf data/*.db reports/*.html __pycache__ */__pycache__
```

### 6.3 更新 `start.sh`

在现有脚本基础上**叠加**：
```bash
# 依赖检查
python3 -c "import fastapi, uvicorn, jwt, cryptography, yaml, rich" 2>/dev/null || {
  echo "安装依赖..."
  pip3 install -r requirements.txt --break-system-packages -q
}

# 创建 policies 目录
mkdir -p policies data reports

# 初始化检查
echo "AgentPass v2.1.0 启动中..."
echo "访问地址: http://localhost:8000"
echo "演示 CLI:  python3 cli/demo_cli.py"
```

---

## 执行顺序与验收标准

**严格按以下顺序执行**：

1. **先创建所有新 Python 文件**（`policy_engine.py`, `svid_manager.py`, `dpop_verifier.py`, `rate_limiter.py`, `circuit_breaker.py`, `nonce_manager.py`），每个文件创建后立即用 `python3 -c "from core.xxx import XXX; print('OK')"` 验证导入无误。

2. **更新 `core/auth_server.py`** — 仅添加，不删除现有方法。完成后运行：
   ```bash
   python3 -c "from core.auth_server import AuthServer; a=AuthServer(':memory:'); print(a.health())"
   ```

3. **更新 `core/audit_logger.py`** — 仅添加新方法和新表，不修改现有方法签名。

4. **更新 `main.py`** — 仅追加新路由，保留所有现有路由。完成后运行：
   ```bash
   python3 -m py_compile main.py && echo "Syntax OK"
   ```

5. **创建 YAML 策略文件**。

6. **重写 `frontend/index.html`** — 完整替换，但保留所有现有 API 调用地址不变。

7. **创建 `cli/demo_cli.py`** 和 `tests/` 目录。

8. **更新 `requirements.txt`**（追加 `rich` 和 `pyyaml`）。

9. **完整测试**：
   ```bash
   # 启动服务
   python3 main.py &
   sleep 3
   
   # 验证所有现有功能仍正常
   curl http://localhost:8000/api/health
   curl -X POST http://localhost:8000/api/demo/normal-delegation | python3 -m json.tool
   curl -X POST http://localhost:8000/api/demo/capability-mismatch | python3 -m json.tool
   
   # 验证新功能
   curl http://localhost:8000/api/policies
   curl http://localhost:8000/api/trust-bundle
   curl http://localhost:8000/api/circuit-breakers
   curl http://localhost:8000/api/system/capabilities-matrix
   ```

---

## 关键约束（绝对不能违反）

1. **向后兼容**：所有现有 `/api/demo/*` 端点的响应格式不变，前端所有现有 API 调用路径不变。
2. **不引入新的外部服务依赖**（不需要 Redis、PostgreSQL、OPA 二进制等），所有功能纯 Python 实现。
3. **单文件前端**：`frontend/index.html` 保持为单文件，不拆分为多文件。所有 CSS 和 JS 内联。
4. **D3 加载方式**：通过 `<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js">` 加载，不使用 `import`。
5. **Python 3.9+ 兼容**：不使用 3.10+ 的 `match/case` 语法。
6. **SQLite PRAGMA**：所有新数据库连接保留 `PRAGMA busy_timeout=5000`，避免并发写入冲突。
7. **错误码一致性**：所有新错误码以 `ERR_` 开头，与现有错误码风格保持一致。
8. **日志完整性**：所有新的安全决策（策略拒绝、速率限制、熔断）都必须写入 `audit_logs` 表。

---

## 附：实现质量检查清单

完成所有实现后，对照检查：

- [ ] `python3 main.py` 无报错启动
- [ ] 访问 `http://localhost:8000` 前端正常加载，D3 图可见
- [ ] 6个演示按钮均可正常触发，步骤卡片正常显示
- [ ] WebSocket 实时推送可见（粒子动画在委托成功后触发）
- [ ] Token 检视台可展示完整 JWT 解析
- [ ] 策略控制台可列出策略 + 模拟评估返回结果
- [ ] SVID 信息可在 Agent 详情中查看
- [ ] 熔断器状态在 Agent 卡片上可见
- [ ] 审计链验证接口返回 `valid: true`
- [ ] `python3 -m pytest tests/ -v` 通过率 > 90%
- [ ] `python3 cli/demo_cli.py agents` 正常输出表格
- [ ] `python3 verify_chain.py` 输出 ✅ 通过
- [ ] `curl http://localhost:8000/api/system/capabilities-matrix` 返回矩阵数据
