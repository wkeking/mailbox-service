# Mailbox Service

用于集中维护 Outlook / Hotmail OAuth 凭证的单实例服务。本仓库当前实现了全局出口代理池的基础设施：OAuth Token 刷新和 XOAUTH2 IMAP 连接按邮箱粘性地复用同一健康代理，并在代理链路失败后切换至备用代理。

## 已实现的出口代理能力

- HTTP CONNECT 与 SOCKS5 全局代理池，代理认证凭证使用 AES-GCM 加密保存。
- 邮箱级粘性绑定，使用 MySQL 行锁与 `FOR UPDATE SKIP LOCKED` 防止并发绑定冲突。
- 按优先级和当前绑定数选择候选代理；代理被禁用、失败冷却或不可用时自动重选。
- 强制代理模式：没有健康代理时返回 `NO_HEALTHY_EGRESS_PROXY`，不会静默直连。
- OAuth Token 与 XOAUTH2 IMAP 共用同一个解析器和代理传输层；代理链路错误最多重试一次。
- 代理健康探测、冷却、恢复、审计、Dashboard 指标与管理 API。
- React 管理页提供代理添加、启停、测试、恢复、删除和全局策略配置。

## 本地启动

1. 创建 MySQL 数据库并执行迁移：

   ```bash
   mysql -u root -p -e "CREATE DATABASE mailbox_service CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
   mysql -u root -p mailbox_service < migrations/001_create_proxy_routing.sql
   mysql -u root -p mailbox_service < migrations/002_add_mailbox_credential_columns.sql
   mysql -u root -p mailbox_service < migrations/003_add_mailbox_access_token_cache.sql
   mysql -u root -p mailbox_service < migrations/004_create_client_keys.sql
   ```

2. 复制并填写环境配置。生产环境必须使用随机的管理员 Token 和 32 字节 AES-GCM 密钥：

   ```bash
   cp .env.example .env
   python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
   ```

3. 使用虚拟环境安装并运行后端：

   ```bash
   python -m venv .venv
   .venv/bin/python -m pip install -e ".[dev]"
   .venv/bin/python -m uvicorn mailbox_service.main:app --reload
   ```

4. 启动管理台：

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

打开 `http://localhost:5173` 后，输入 `.env` 中的 `ADMIN_API_TOKEN`。Token 仅保存在浏览器当前页面内存。

## 网页版 API 文档

公开文档只展示面向外部调用方的服务接口，不包含任何 `/api/v1/admin/*` 管理路径：

- Swagger UI：`http://localhost:8000/docs`，偏向开发与在线调试，可直接填写参数并发送请求。
- ReDoc：`http://localhost:8000/redoc`，偏向阅读，适合连续浏览接口、数据模型和说明。
- OpenAPI JSON 查看器：`http://localhost:8000/openapi-viewer`，使用固定深色背景和浅色文字，适合人工查看原始定义。
- OpenAPI JSON：`http://localhost:8000/openapi.json`，是给代码生成器和其他工具读取的标准机器格式，不建议作为人工阅读页面。

在公开 Swagger UI 中点击右上角 **Authorize**，输入管理员创建后仅显示一次的 Client API Key。Swagger 会自动通过 `X-API-Key` 请求头调用外部接口。管理台左侧导航的“API 文档”也打开这份公开文档。

管理接口不会生成可访问的 Swagger、ReDoc 或 OpenAPI JSON 页面。内部控制台仍通过 `X-Admin-Token` 调用 `/api/v1/admin/*`；Client API Key 不能调用管理接口。

项目提供的文档标题、接口分组、接口摘要、接口说明和主要数据模型说明均使用中文。Swagger UI 与 ReDoc 自身的通用按钮文字由对应第三方界面提供，可能仍显示英文。

## 创建外部 Client Key

使用管理员 Token 创建 Client Key。`api_key` 明文只在创建响应中返回一次，数据库仅保存 SHA-256 摘要：

```bash
curl -X POST http://localhost:8000/api/v1/admin/client-keys \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Token: <ADMIN_API_TOKEN>' \
  -d '{
    "name": "registration-worker",
    "scopes": [
      "leases:acquire",
      "leases:release",
      "tokens:access:read",
      "tokens:refresh:read",
      "tokens:refresh:write",
      "mailboxes:acquire",
      "mail:verification-code:read"
    ]
  }'
```

可用 scope：

- `leases:acquire`：领取租约
- `leases:release`：释放租约
- `tokens:access:read`：领取或读取 AT mode 租约
- `tokens:refresh:read`：领取 RT mode 租约并读取当前 RT
- `tokens:refresh:write`：在 RT mode 租约内 CAS 回写新 RT
- `mailboxes:acquire`：领取可用邮箱账号（mail_read 租约，不返回 Token）
- `mail:verification-code:read`：在 mail_read 租约下读取收件箱验证码

## 外部服务 API

所有外部服务接口使用请求头 `X-API-Key`，路径不带 `/admin`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/api/v1/leases/acquire` | 领取 AT 或 RT mode 邮箱租约 |
| `POST` | `/api/v1/leases/{lease_id}/release` | 幂等释放租约 |
| `POST` | `/api/v1/leases/{lease_id}/access-token` | 获取未过期缓存 AT，过期时自动刷新 |
| `POST` | `/api/v1/leases/{lease_id}/refresh-token` | 按 `expected_token_version` CAS 回写 RT |
| `POST` | `/api/v1/mailboxes/acquire` | 领取可用邮箱账号（mail_read，只返回邮箱与租约） |
| `POST` | `/api/v1/leases/{lease_id}/verification-code` | 在 mail_read 租约下提取收件箱验证码 |

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
| `POST` | `/api/v1/admin/client-keys/{id}/disable` | 停用 Client Key |

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
2. 以 `access_token_refreshed_at`（无则 `created_at`）判断是否 overdue  
3. 跳过仍有未过期租约的邮箱，避免 RT mode 持有方拿到旧 RT  
4. 调用 Microsoft token 端点强制刷新；若返回新 RT 则加密落库并 `token_version + 1`  
5. `invalid_grant` 会标记邮箱 `invalid`

也可在管理台对选中/全部邮箱执行 `POST /api/v1/admin/mailboxes/access-tokens/refresh` 做手动批量刷新。

## 安全限制

- 不要将 `.env`、代理密码、`refresh_token`、`access_token` 或 Admin Token 提交到版本控制。
- 代理密码、OAuth 凭证和 API Key 不能写入日志、审计、错误响应或管理台读取接口。
- 生产环境建议启用 `PROXY_REQUIRED=true`，并仅允许内网访问管理 API。
- 未实现 Microsoft 交互式 OAuth 首次授权；需导入已经获取的 refresh token。
