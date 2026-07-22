# Mailbox Service

用于集中维护邮箱凭证与 `mail_read` 租约的单实例服务。当前已接入 Provider：

| Provider | 供给 | 能力 | 说明 |
| --- | --- | --- | --- |
| `microsoft` | inventory 导入 | AT / RT / mail_read | **有所有权**凭证；写入 `mailboxes`；四段文本导入；无额外 scope 时随机池仅此 |
| `smsbower_gmail` | inventory 补货 | mail_read | **非所有权**付费租号；只写 `mailbox_provider_resources`，**不**进 `mailboxes`；需 `providers:smsbower_gmail:acquire` |
| `cloudflare_temp_email` | on_demand | mail_read | **非所有权**临时邮箱；领取时即时开箱，只写 provider 资源表，**不**进 `mailboxes` |
| `ddg_mail` | on_demand | mail_read | DDG 别名 + CF 兼容收件箱 |
| `cloudmail_gen` | on_demand | mail_read | 管理台配置 |
| `tempmail_lol` | on_demand | mail_read | 管理台配置 |
| `duckmail` | on_demand | mail_read | 管理台配置 |
| `gptmail` | on_demand | mail_read | 管理台配置 |
| `moemail` | on_demand | mail_read | 管理台配置 |
| `inbucket` | on_demand | mail_read | 自建 Inbucket |
| `yyds_mail` | on_demand | mail_read | 管理台配置 |

管理台能力摘要：

| 页面 | 能力 |
| --- | --- |
| **邮箱 Provider** | 各类型启停、API Base、域名与密钥（加密保存、不回显明文）；SMSBower 补货；**检测全部服务 / 域名探测** |
| **联调工作台** | Admin 对 on-demand Provider 开箱、刷新收件、提取/复制验证码、释放会话（不写 `mailboxes`） |
| **Client Key** | 创建 / **编辑名称与权限** / 停用；明文仅创建时显示一次；编辑弹窗支持固定高度内滚动 |
| **邮箱 / 租约 / 注册站点 / 站点占用 / 出口代理** | 见下文管理 API 与管理台说明 |

**`mailboxes` 语义：** 仅维护有所有权的邮箱（当前为 Microsoft OAuth 导入）。临时邮箱（on-demand）与付费租赁（SMSBower）落在 `mailbox_provider_resources`，lease 绑定 `provider_resource_id`，`mailbox_id` 为空。管理台「邮箱管理」只展示所有权邮箱。

非 Microsoft 领取须 Client Key 具备 `providers:{type}:acquire`。  
`POST /mailboxes/acquire` 多类型与 plus 语义见 [外部服务 API · mail_read 领取](#mail_read-领取可用邮箱账号) 与对接文档 [docs/external-mailboxes-acquire-integration.md](docs/external-mailboxes-acquire-integration.md)。

同时实现了全局出口代理池：OAuth Token 刷新和 XOAUTH2 IMAP 连接按邮箱粘性地复用同一健康代理，并在代理链路失败后切换至备用代理。

## 已实现的出口代理能力

- HTTP CONNECT 与 SOCKS5 全局代理池，代理认证凭证使用 AES-GCM 加密保存。
- 邮箱级粘性绑定，使用 MySQL 行锁与 `FOR UPDATE SKIP LOCKED` 防止并发绑定冲突。
- 按优先级和当前绑定数选择候选代理；代理被禁用、失败冷却或不可用时自动重选。
- 强制代理模式：没有健康代理时返回 `NO_HEALTHY_EGRESS_PROXY`，不会静默直连。
- OAuth Token 与 XOAUTH2 IMAP 共用同一个解析器和代理传输层；代理链路错误最多重试一次。
- 代理健康探测、冷却、恢复、审计、Dashboard 指标与管理 API。
- React 管理页提供代理添加、启停、测试、恢复、删除和全局策略配置。

## 开发启动

运行时统一为 **Python 3.14**（与 Docker 镜像、`.python-version` 一致）。请使用 3.14 创建虚拟环境，避免与生产 stdlib 行为不一致。

1. 创建 MySQL 数据库（schema 迁移可交给服务启动时自动执行）：

   ```bash
   mysql -u root -p -e "CREATE DATABASE mailbox_service CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
   ```

   默认开启 `AUTO_MIGRATE_ON_STARTUP=true`：进程启动时会扫描 `migrations/*.sql`，对照 `schema_migrations` 表只执行尚未记录的版本。也可手动执行：

   ```bash
   for migration_file in migrations/*.sql; do
     mysql -u root -p mailbox_service < "$migration_file"
   done
   ```

2. 复制并填写环境配置。生产环境必须使用随机的管理员 Token 和 32 字节 AES-GCM 密钥：

   ```bash
   cp .env.example .env
   python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
   ```

3. 使用虚拟环境安装并运行后端（需 Python 3.14）：

   ```bash
   python3.14 -m venv .venv
   .venv/bin/python -V   # 应输出 Python 3.14.x
   .venv/bin/python -m pip install -e ".[dev]"
   .venv/bin/python -m uvicorn mailbox_service.main:app --reload
   ```

4. 启动管理台：

   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

打开 `http://localhost:5173` 后，输入 `.env` 中的 `ADMIN_API_TOKEN`。Token 仅保存在浏览器当前页面内存。

> Docker 镜像部署时管理台已打进同一镜像，浏览器访问服务根路径即可，无需单独跑 Vite。

## 网页版 API 文档

公开文档只展示面向外部调用方的服务接口，不包含任何 `/api/v1/admin/*` 管理路径：

- Swagger UI：`http://localhost:8000/docs`，偏向开发与在线调试，可直接填写参数并发送请求。
- ReDoc：`http://localhost:8000/redoc`，偏向阅读，适合连续浏览接口、数据模型和说明。
- OpenAPI JSON 查看器：`http://localhost:8000/openapi-viewer`，使用固定深色背景和浅色文字，适合人工查看原始定义。
- OpenAPI JSON：`http://localhost:8000/openapi.json`，是给代码生成器和其他工具读取的标准机器格式，不建议作为人工阅读页面。

在公开 Swagger UI 中点击右上角 **Authorize**，输入管理员创建后仅显示一次的 Client API Key。Swagger 会自动通过 `X-API-Key` 请求头调用外部接口。管理台左侧导航的“API 文档”也打开这份公开文档。

管理接口不会生成可访问的 Swagger、ReDoc 或 OpenAPI JSON 页面。内部控制台仍通过 `X-Admin-Token` 调用 `/api/v1/admin/*`；Client API Key 不能调用管理接口。

项目提供的文档标题、接口分组、接口摘要、接口说明和主要数据模型说明均使用中文。Swagger UI 与 ReDoc 自身的通用按钮文字由对应第三方界面提供，可能仍显示英文。

## 管理 Client Key（创建 / 修改 / 停用）

使用管理员 Token 管理外部 Client Key。`api_key` **明文只在创建响应中返回一次**，数据库仅保存 SHA-256 摘要；修改名称或权限**不会**轮换密钥明文。

### 创建

```bash
curl -X POST http://localhost:8000/api/v1/admin/client-keys \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Token: <ADMIN_API_TOKEN>' \
  -d '{
    "name": "registration-worker",
    "scopes": [
      "leases:release",
      "mailboxes:acquire",
      "mailboxes:reacquire",
      "mail:verification-code:read",
      "providers:gptmail:acquire",
      "providers:duckmail:acquire"
    ]
  }'
```

### 修改名称与权限（不轮换密钥）

```bash
curl -X PATCH http://localhost:8000/api/v1/admin/client-keys/<client_key_id> \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Token: <ADMIN_API_TOKEN>' \
  -d '{
    "name": "registration-worker-v2",
    "scopes": [
      "leases:release",
      "mailboxes:acquire",
      "mail:verification-code:read",
      "providers:gptmail:acquire"
    ]
  }'
```

- 名称全局唯一；冲突返回 `409 CLIENT_KEY_NAME_CONFLICT`
- 至少保留一个合法 scope
- 已停用的 Key 修改后**仍保持停用**（不会自动启用）
- 管理台 **Client Key** 页：列表可 **编辑**（名称 + scopes 勾选）/ **停用**；创建与编辑弹窗固定视口高度、中间可滚动、底部按钮常驻

### 可用 scope

| scope | 说明 |
| --- | --- |
| `leases:acquire` | 领取 AT / RT mode 租约（`POST /leases/acquire`） |
| `leases:release` | 释放租约 |
| `tokens:access:read` | 领取或读取 AT mode 租约 |
| `tokens:refresh:read` | 领取 RT mode 并读取当前 RT |
| `tokens:refresh:write` | 在 RT mode 租约内 CAS 回写新 RT |
| `mailboxes:acquire` | 领取 mail_read 邮箱（`POST /mailboxes/acquire`） |
| `mailboxes:reacquire` | 按历史业务地址重新领取 |
| `mail:verification-code:read` | 读取收件箱验证码 |
| `providers:{type}:acquire` | 允许该 `provider_type` 进入 mail_read 候选池 / 显式领取 |

`providers:{type}:acquire` 中 `{type}` 为非默认类型，例如：

- `providers:smsbower_gmail:acquire`
- `providers:cloudflare_temp_email:acquire` / `ddg_mail` / `cloudmail_gen` / `tempmail_lol` / `duckmail` / `gptmail` / `moemail` / `inbucket` / `yyds_mail`

**默认新建 Key 不含任何 `providers:*:acquire`。**  
因此仅有 `mailboxes:acquire` 时，`provider` 省略或 `all` **只会落到 `microsoft`**；要随机/指定临时邮箱等类型，必须在 Key 上勾选对应 provider scope。

读码场景最小建议 scopes：

```text
mailboxes:acquire + leases:release + mail:verification-code:read
（需要 reacquire 时再加 mailboxes:reacquire）
（需要某非 Microsoft 类型时再加 providers:{type}:acquire）
```

## 外部服务 API

所有外部服务接口使用请求头 `X-API-Key`，路径不带 `/admin`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/api/v1/leases/acquire` | 领取 AT 或 RT mode 邮箱租约（**仅 Microsoft**） |
| `POST` | `/api/v1/leases/{lease_id}/release` | 幂等释放租约 |
| `POST` | `/api/v1/leases/{lease_id}/access-token` | 获取未过期缓存 AT，过期时自动刷新 |
| `POST` | `/api/v1/leases/{lease_id}/refresh-token` | 按 `expected_token_version` CAS 回写 RT |
| `POST` | `/api/v1/mailboxes/acquire` | 领取 mail_read 可用邮箱（多类型 / 排除 / plus，见下节） |
| `GET` | `/api/v1/usage-sites` | 查询启用中的注册站点白名单（需 `mailboxes:acquire`） |
| `POST` | `/api/v1/mailboxes/reacquire` | 按历史业务地址（主邮箱或 plus 别名）重新领取 mail_read 租约 |
| `POST` | `/api/v1/leases/{lease_id}/verification-code` | 在 mail_read 租约下提取收件箱验证码 |

调用方完整对接说明（含错误码、示例、适配清单）：  
**[docs/external-mailboxes-acquire-integration.md](docs/external-mailboxes-acquire-integration.md)**

### mail_read 领取可用邮箱账号

`POST /api/v1/mailboxes/acquire`

#### 请求字段（摘要）

| 字段 | 说明 |
| --- | --- |
| `provider` | 省略 / `null` / `"all"`：在 **Client Key 已授权** 的类型中随机；单字符串或字符串数组：仅在列表内随机 |
| `exclude_providers` | 单值或数组；**优先级最高**，先从候选池剔除再随机 |
| `lease_ttl_seconds` | 租约秒数，默认 `600`，范围 `60–86400` |
| `usage_site` | 注册站点 code；**microsoft 主邮箱路径必填**；plus 别名可选；多数非 microsoft 可不传 |
| `use_plus_alias` | 仅当**实际命中 microsoft** 时生效：分配 `user+xxxx@domain` 作为 `allocated_email`；命中非 microsoft 时**忽略**，不会强制改走 microsoft |
| `alias_suffix` | 可选 plus 后缀（小写字母数字）；传入时对 microsoft 等价于启用 plus |
| `preferred_email` / `client_tag` / `purpose` | 优先邮箱、调用方标签、用途说明 |

#### 类型选择规则

1. 构造候选池（`all`/省略 → 全 catalog；显式列表 → 仅列表）  
2. 减去 `exclude_providers`  
3. 减去当前 Key **未授权**的类型（`all`/省略时静默跳过；显式写了未授权类型 → `403 CLIENT_SCOPE_REQUIRED`）  
4. 候选打乱后依次尝试领取；库存空 / 未配置 / 上游失败则跳过下一类型  
5. 成功则返回实际命中的 `provider`；全部失败 → `409 NO_AVAILABLE_MAILBOX` 等

> 注意：`all` **不是**「管理台已配置的 Provider 均匀轮询」，而是「已授权类型随机尝试 + 首个成功」。  
> 若 Key 只有 `mailboxes:acquire`，`all` 等价于仅 microsoft。  
> 若同时授权了多种类型且 microsoft 库存充足，失败的 on-demand 类型会被跳过，可能连续落到 hotmail——需要纯临时邮箱时请 `exclude_providers: ["microsoft"]` 或写死类型列表。

#### 响应字段（摘要）

| 字段 | 说明 |
| --- | --- |
| `lease_id` | 后续 verification-code / release 使用 |
| `allocated_email` | **业务注册地址**（主邮箱或 plus 别名） |
| `primary_email` | 主邮箱（plus 场景下与 allocated 不同） |
| `provider` | **实际命中的** `provider_type`（始终返回） |
| `address_kind` | `primary` / `plus_alias` |
| `usage_site` / `expires_at` / `created_at` | 站点与租约时间 |

#### 请求示例

```bash
# 1) 只要 Microsoft 主邮箱（写死，避免误随机构）
curl -X POST http://localhost:8000/api/v1/mailboxes/acquire \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <CLIENT_API_KEY>' \
  -d '{
    "provider": "microsoft",
    "usage_site": "openai",
    "lease_ttl_seconds": 600
  }'

# 2) 已授权类型中随机（含 microsoft，若已授权）
curl -X POST http://localhost:8000/api/v1/mailboxes/acquire \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <CLIENT_API_KEY>' \
  -d '{
    "provider": "all",
    "usage_site": "openai",
    "lease_ttl_seconds": 600
  }'

# 3) 排除 microsoft，仅在已授权的临时邮箱等类型中随机
curl -X POST http://localhost:8000/api/v1/mailboxes/acquire \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <CLIENT_API_KEY>' \
  -d '{
    "provider": "all",
    "exclude_providers": ["microsoft"],
    "lease_ttl_seconds": 600,
    "use_plus_alias": true
  }'
# use_plus_alias 对非 microsoft 忽略；不会因此 409 LEASE_MODE_MISMATCH

# 4) Microsoft plus 别名
curl -X POST http://localhost:8000/api/v1/mailboxes/acquire \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <CLIENT_API_KEY>' \
  -d '{
    "provider": "microsoft",
    "use_plus_alias": true,
    "lease_ttl_seconds": 600
  }'
```

### Provider 矩阵

| provider_type | 供给方式 | 支持模式 | 领取条件 |
| --- | --- | --- | --- |
| `microsoft` | inventory（四段导入） | AT / RT / mail_read | 仅需 `mailboxes:acquire`（AT/RT 另需 token scopes） |
| `smsbower_gmail` | inventory（Admin 补货） | mail_read | `providers:smsbower_gmail:acquire`；详见 [docs/smsbower-gmail-phase1a.md](docs/smsbower-gmail-phase1a.md) |
| `cloudflare_temp_email` | on_demand | mail_read | 对应 `providers:*:acquire` + 管理台启用并配置 |
| `ddg_mail` | on_demand | mail_read | 同上 |
| `cloudmail_gen` | on_demand | mail_read | 同上 |
| `tempmail_lol` | on_demand | mail_read | 同上 |
| `duckmail` | on_demand | mail_read | 同上 |
| `gptmail` | on_demand | mail_read | 同上 |
| `moemail` | on_demand | mail_read | 同上 |
| `inbucket` | on_demand | mail_read | 同上 |
| `yyds_mail` | on_demand | mail_read | 同上 |

on-demand：管理台启用并填写必填字段/密钥后，带 allowlist 的 Client Key 可领取并读验证码。未启用或未配置完整时，显式指定返回 `PROVIDER_NOT_CONFIGURED`；在 `all` 随机中可能被跳过并尝试下一类型。

### 按历史地址重新领取（reacquire）

业务侧应持久化首次 `acquire` 返回的 `allocated_email`（主邮箱或 plus 别名均可）。租约过期或释放后，如需再次取验证码：

1. `POST /api/v1/mailboxes/reacquire`，body：`{"email": "<allocated_email>", "lease_ttl_seconds": 300}`
2. 服务端自动判定主邮箱 / plus 别名；仅当**同一 Client Key 曾对该完整地址持有过 mail_read 租约**时允许
3. 使用返回的 `lease_id` 调用 `verification-code`，用毕后 `release`

请求示例：

```bash
curl -X POST http://localhost:8000/api/v1/mailboxes/reacquire \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <CLIENT_API_KEY>' \
  -d '{
    "email": "owner+reg01@outlook.com",
    "lease_ttl_seconds": 300,
    "purpose": "resend_verification"
  }'
```

错误码摘要：

- `404 EMAIL_NOT_FOUND`：地址无法解析、无历史归属、或不属于当前 Client Key（统一文案）
- `409 MAILBOX_BUSY`：目标主邮箱已被其他租约占用
- `409 NO_AVAILABLE_MAILBOX`：邮箱不可用或无读信通道
- `403 CLIENT_SCOPE_REQUIRED`：缺少 `mailboxes:reacquire`

## 管理 API

所有 `/api/v1/admin/*` 端点需要请求头 `X-Admin-Token`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/egress-proxies` | 读取脱敏代理列表 |
| `POST` | `/api/v1/admin/egress-proxies` | 添加代理，凭证仅可写入 |
| `PATCH` | `/api/v1/admin/egress-proxies/{id}` | 更新代理元数据或认证凭证 |
| `POST` | `/api/v1/admin/egress-proxies/{id}/enable` | 启用代理 |
| `POST` | `/api/v1/admin/egress-proxies/{id}/disable` | 停用代理 |
| `POST` | `/api/v1/admin/egress-proxies/{id}/test` | 受限 Microsoft 连通性测试 |
| `POST` | `/api/v1/admin/egress-proxies/{id}/recover` | 手动解除冷却 |
| `GET` | `/api/v1/admin/egress-proxies/{id}/mailboxes` | 查看代理绑定的邮箱 |
| `GET/PATCH` | `/api/v1/admin/egress-proxy-policy` | 读取或修改全局代理策略 |
| `PUT` | `/api/v1/admin/mailboxes/{id}/egress-proxy` | 手动重绑定或解除邮箱代理 |
| `POST` | `/api/v1/admin/client-keys` | 创建 Client Key，明文只返回一次 |
| `GET` | `/api/v1/admin/client-keys` | 查询不含密钥和摘要的 Client Key 元数据 |
| `PATCH` | `/api/v1/admin/client-keys/{id}` | 修改名称与权限 scopes（不轮换密钥明文） |
| `POST` | `/api/v1/admin/client-keys/{id}/disable` | 停用 Client Key |
| `GET` | `/api/v1/admin/usage-sites` | 查询注册站点白名单（含已禁用） |
| `POST` | `/api/v1/admin/usage-sites` | 创建注册站点（code 不可改） |
| `PATCH` | `/api/v1/admin/usage-sites/{code}` | 更新展示名或启用状态 |
| `DELETE` | `/api/v1/admin/usage-sites/{code}` | 删除站点（仅无未撤销占用时） |
| `GET` | `/api/v1/admin/email-site-usages` | 分页查询邮箱站点占用 |
| `POST` | `/api/v1/admin/email-site-usages/{id}/revoke` | 软撤销邮箱站点占用（幂等） |

管理台：

- **Client Key**：创建（明文仅一次）/ **编辑名称与 scopes** / 停用；编辑与创建弹窗可滚动、底部操作栏固定
- **邮箱 Provider**：catalog 状态、实例启停与密钥配置；SMSBower 补货入口
- **注册站点**：新增 / 启停 / 删除（无占用时）白名单
- **站点占用**：按业务邮箱、站点筛选占用，并可一键撤销
- **邮箱管理**：行内「站点占用」跳转并按主邮箱筛选占用
- **出口代理**：添加、启停、测试、恢复、删除与全局策略

## Refresh Token 保活

Microsoft identity platform 对非 SPA 场景的 refresh token **默认寿命约 90 天**（不是 30 天）。  
SPA / 某些 OTP 流程可能是 24 小时；个人 Outlook / Hotmail 常见为 90 天滑动/可轮换，且服务端可随时撤销。

本服务提供进程内定时保活（与代理健康探测同类，单实例 APScheduler）：

- 默认开启：`REFRESH_TOKEN_KEEPALIVE_ENABLED=true`
- 默认每天扫描一次：`REFRESH_TOKEN_KEEPALIVE_INTERVAL_SECONDS=86400`
- 默认按 90 天寿命、提前 7 天刷新：`REFRESH_TOKEN_LIFETIME_DAYS=90`、`REFRESH_TOKEN_KEEPALIVE_LEAD_DAYS=7`
- 每批最多处理：`REFRESH_TOKEN_KEEPALIVE_BATCH_SIZE=20`

规则摘要：

1. 只处理 `status=active` 且具备 `client_id` / RT 的邮箱  
2. 以 `refresh_token_expires_at` 判断是否即将/已经过期（提前 `KEEPALIVE_LEAD_DAYS`）；缺失时回退到 `access_token_refreshed_at` / `created_at` + 寿命估算  
3. 跳过仍有未过期租约的邮箱，避免 RT mode 持有方拿到旧 RT  
4. 调用 Microsoft token 端点强制刷新；成功后刷新 `refresh_token_updated_at` / `refresh_token_expires_at`（滑动窗口）；若返回新 RT 则加密落库并 `token_version + 1`  
5. `invalid_grant` 会标记邮箱 `invalid`

也可在管理台对选中/全部邮箱执行 `POST /api/v1/admin/mailboxes/access-tokens/refresh` 做手动批量刷新。

## Docker 镜像构建与部署

镜像为多阶段构建：Node 编译管理台 + **Python 3.14** 运行 FastAPI。  
默认目标平台为 `linux/arm64`（可用参数覆盖为 `linux/amd64`）。  
基座镜像为 `python:3.14-slim-bookworm`。

**分层缓存（减小 push / pull）：** 依赖与代码严格分 stage / layer：

| 层 | 何时失效 | 典型体积 |
| --- | --- | --- |
| OS + `appuser` | 基座镜像 / apt 变更 | 中 |
| Python `.venv`（`python-deps`） | 仅 `pyproject.toml` / `uv.lock` 变更 | 大（约数十 MB） |
| `mailbox_service/` | 后端代码变更 | 小 |
| `migrations/` | 迁移脚本变更 | 很小 |
| `frontend_dist` | 前端构建产物变更 | 中小 |
| 前端 `npm ci`（`frontend-deps`） | 仅 `package-lock.json` 变更 | 构建期大，不进最终镜像依赖重装 |

仅改后端代码时，`docker push` / `docker pull` 通常只需传输代码层。

相关文件：

| 路径 | 作用 |
| --- | --- |
| `Dockerfile` | 多阶段 / 分层构建定义 |
| `scripts/build-image.sh` | buildx 构建；可 load / push / 导出 tar |
| `docker-compose.yml` | 应用部署示例（外连已有 MySQL 网络） |
| `.dockerignore` | 减小构建上下文 |

### 前置条件

- 已安装 Docker，并支持 `docker buildx`
- 目标环境可访问你自己的镜像仓库（若需要 `push` / `pull`）
- 交叉构建其他架构时，需配置 QEMU / buildx 多架构支持
- 已准备 MySQL 8 实例，并创建业务库

### 1. 构建镜像

```bash
chmod +x scripts/build-image.sh

# 仅载入本机 Docker（默认，不推送）
./scripts/build-image.sh --output load

# 构建并推送到你的镜像仓库
REGISTRY=registry.example.com ./scripts/build-image.sh --output push

# 导出 tar（离线场景）
./scripts/build-image.sh --output tar
```

常用参数 / 环境变量：

```text
--platform   默认 linux/arm64；也可 linux/amd64
--tag        镜像标签，默认 latest
--name       镜像名，默认 mailbox-service
--registry   镜像仓库主机；push 时必填（也可用环境变量 REGISTRY）
--output     load | push | tar（默认 load）
```

完整镜像引用示例：`registry.example.com/mailbox-service:latest`

### 2. 服务器拉取镜像

```bash
docker pull registry.example.com/mailbox-service:latest
docker images | grep mailbox-service
```

离线 tar 场景：

```bash
# 构建机
./scripts/build-image.sh --output tar
scp dist/mailbox-service-*-linux-arm64.tar user@server:/opt/mailbox-service/

# 服务器
docker load -i mailbox-service-*-linux-arm64.tar
```

### 3. 准备配置与数据库

在部署目录准备 `.env`（**不要提交真实 `.env`**）：

```bash
cp .env.example .env
# 至少填写：
#   ADMIN_API_TOKEN
#   CREDENTIAL_ENCRYPTION_KEY   # 32 字节 URL-safe Base64
#   DATABASE_URL
#   APP_ENV=production
#   CORS_ALLOW_ORIGINS          # 同源管理台可设 *
#   PROXY_REQUIRED=true/false   # 按出口策略
```

生成加密密钥示例：

```bash
python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

**数据库迁移：**

- **推荐**：保持 `AUTO_MIGRATE_ON_STARTUP=true`（默认）。服务启动时会自动检测版本并执行 `migrations/` 中尚未记录的脚本，结果写入 `schema_migrations`。
- 使用 Compose 外连共享 MySQL 时，请先创建 `mailbox_service` 库；表结构由应用启动迁移负责。
- 关闭自动迁移时设 `AUTO_MIGRATE_ON_STARTUP=false`，再按序号手动执行：

```bash
for migration_file in migrations/*.sql; do
  mysql -u <user> -p mailbox_service < "$migration_file"
done
```

- 新增迁移请继续使用 `00N_描述.sql` 命名；**不要修改已上线版本的 SQL 内容**（版本号一旦记录即视为已应用）。

### 4a. 用 Compose 部署（外连已有 MySQL）

`docker-compose.yml` 默认镜像为 `mailbox-service:latest`，可通过环境变量覆盖：

```bash
export MAILBOX_IMAGE=registry.example.com/mailbox-service:latest
export INFRA_NETWORK_NAME=your_external_docker_network
# 在 .env 中配置 DATABASE_URL 等密钥
docker compose pull   # 若使用远程镜像
docker compose up -d
```

Compose **不自带 MySQL**，需接入外部 Docker 网络中的 MySQL（或改 `docker-compose.yml` 以适配你的拓扑）。

应用侧 `.env` 示例（主机名以容器网络可达为准）：

```env
DATABASE_URL=mysql+pymysql://<user>:<password>@<mysql-host>:3306/mailbox_service
APP_ENV=production
CORS_ALLOW_ORIGINS=*
```

首次使用需保证库已创建，例如：

```bash
mysql -u <user> -p -e "CREATE DATABASE IF NOT EXISTS mailbox_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

启动与检查：

```bash
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8000/health
```

访问：

- 管理台：`http://<host>:8000/`
- 公开 API 文档：`http://<host>:8000/docs`
- 健康检查：`http://<host>:8000/health`

### 4b. 仅运行应用容器（外部已有 MySQL）

```bash
docker run -d \
  --name mailbox-service \
  --restart unless-stopped \
  -p 8000:8000 \
  --env-file .env \
  -e APP_ENV=production \
  -e CORS_ALLOW_ORIGINS='*' \
  --network <your_external_network> \
  registry.example.com/mailbox-service:latest
```

确保 `.env` 中 `DATABASE_URL` 在容器网络内可达。

### 5. 升级镜像

```bash
# 构建机：构建并推送到你的仓库
REGISTRY=registry.example.com ./scripts/build-image.sh --output push

# 服务器：拉取最新标签并滚动
docker compose pull
docker compose up -d
# 默认会在启动时自动执行尚未记录的 migrations（见 AUTO_MIGRATE_ON_STARTUP）
```

### 6. 常见问题

| 现象 | 处理 |
| --- | --- |
| `exec format error` | 镜像架构与服务器不一致；确认构建平台并用 `docker image inspect` 查看 `Architecture` |
| buildx 交叉构建失败 | 升级 Docker / 安装 QEMU；或直接在目标架构机器上 `--output load` |
| 管理台打不开 / 接口跨域 | 同源部署将 `CORS_ALLOW_ORIGINS=*`；分离前端时填实际管理台 Origin |
| 容器起不来 / DB 连接失败 | 检查 `DATABASE_URL`、MySQL 是否 healthy、网络/防火墙、是否加入正确的 Docker 网络 |
| 拉取/推送镜像失败 | 确认仓库地址、鉴权与网络可达；HTTP 私有仓库需在 daemon 配置 `insecure-registries` |
| 迁移未生效 | 查看启动日志中的迁移输出与 `schema_migrations` 表 |
| Compose 仍用旧镜像 | 标签可能被本地缓存；执行 `docker compose pull` 后再 `up -d` |

## 安全限制

- 不要将 `.env`、代理密码、`refresh_token`、`access_token` 或 Admin Token 提交到版本控制。
- 代理密码、OAuth 凭证和 API Key 不能写入日志、审计、错误响应或管理台读取接口。
- 生产环境建议启用 `PROXY_REQUIRED=true`，并仅允许内网访问管理 API。
- 未实现 Microsoft 交互式 OAuth 首次授权；需导入已经获取的 refresh token。
- 生产环境务必使用强随机的 `ADMIN_API_TOKEN` 与 `CREDENTIAL_ENCRYPTION_KEY`，数据库账号使用最小权限。


## 安全加固与测试

本仓库已落地 Token claim/CAS、Lease claim、验证码授权复核、生产密钥校验、前端纯内存 Admin Token 等加固。

生产环境因历史部署**允许** `DATABASE_URL` 使用 root、`CORS_ALLOW_ORIGINS=*`、`TLS_MODE=disabled`；仍要求 `ADMIN_API_TOKEN` 长度大于 10 位（并拒绝常见占位值）、合法 `CREDENTIAL_ENCRYPTION_KEY`，并拒绝 `FORWARDED_ALLOW_IPS=*`。

### 自动化测试

```bash
./scripts/smoke-local.sh
# 等价于：
uv lock --check
uv run --frozen pytest -q
```

设置 `TEST_DATABASE_URL` 为 MySQL 8 后，`smoke-local.sh` 会额外执行 `pytest -m mysql`。

### 需要你环境配合的项

见 `scripts/smoke-operator-checklist.md`（MySQL 并发、TLS、浏览器 Token、压测、镜像）。

### 关键行为提示

- **导入 `replace_token`**：若邮箱存在 active lease claim，默认该行失败；传 `force_release_active_leases=true` 可先释放再替换。
- **删除邮箱**：默认同样拒绝 active claim；可 force。
- **验证码长轮询**：async endpoint；轮询等待使用 `asyncio.sleep`；Key/Lease 每轮 revalidate；超并发返回 **429**。
- **Admin Token**：仅内存保存，不写 `sessionStorage`。
- **迁移 CLI**：`uv run python scripts/migrate.py --database-url 'mysql+pymysql://...'`

## 免责声明

1. **按现状提供（AS IS）**  
   本软件及文档按「现状」提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性、不侵权、可用性、安全性或持续维护等。作者与贡献者不对因使用、无法使用、配置错误、依赖升级或第三方服务变更导致的任何直接、间接、附带、特殊、后果性或惩罚性损害承担责任（包括但不限于数据丢失、业务中断、账号封禁、凭证泄露、经济损失等），即使已被告知可能发生此类损害。

2. **合规与合法使用由使用者自行负责**  
   本项目用于自托管场景下集中管理邮箱凭证、租约与验证码读取等能力。使用者须自行确保其行为符合所在司法辖区的法律法规，以及 Microsoft、Google 及其他邮箱 / 临时邮箱 / 代理 / 上游 API 提供商的服务条款、可接受使用政策与授权范围。  
   **禁止**将本软件用于未经授权访问他人邮箱、批量滥用注册、绕过平台风控、垃圾信息、欺诈、侵犯隐私或其他违法违规用途。作者与贡献者不认可、不协助此类用途，亦不对使用者的违规后果负责。

3. **密钥与运维风险**  
   生产环境中的管理员 Token、加密密钥、数据库凭证、OAuth Refresh Token、代理密码与 Client API Key 等均由部署方自行保管。因密钥泄露、错误暴露管理接口、未启用必要访问控制或错误配置导致的损失，由部署方自行承担。

4. **第三方依赖与上游服务**  
   对第三方库、容器镜像、外部 Provider API 与网络出口的可用性、计费、接口变更或中断，本项目不作保证。对接与排障成本由使用者自行评估。

5. **非官方产品**  
   本项目为独立开源软件，与 Microsoft、Google 或任何已接入 Provider 的官方产品无关联、无背书、无合作关系。文档中的品牌与产品名仅用于描述兼容性与对接方式。

若你不同意上述条款，请勿下载、使用或分发本软件。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。

你在遵守 MIT 许可证的前提下，可以自由地使用、复制、修改、合并、发布、分发、再许可和/或销售本软件的副本；但须在所有副本或重要部分中保留版权声明与许可证全文。

**简要说明（非正式文本，以 [LICENSE](LICENSE) 为准）：**

- 允许商用、修改与闭源衍生（仍须保留 MIT 声明）
- 软件「按现状」提供，作者不承担质量与损害赔偿责任
- 完整法律文本见仓库根目录 [LICENSE](LICENSE)
