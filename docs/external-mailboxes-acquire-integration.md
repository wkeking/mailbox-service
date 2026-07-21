# 外部调用方对接文档：邮箱领取（mail_read）与多类型分配

面向：**注册机 / 业务 Worker / 第三方调用方开发**  
接口范围：外部服务 API（`X-API-Key`），不含管理台  
更新日期：2026-07-22

---

## 1. 你需要对接什么

标准流程（读信 / 验证码场景）：

```text
1. POST /api/v1/mailboxes/acquire     → 领邮箱 + 得到 lease_id、allocated_email
2. （业务侧用 allocated_email 去注册）
3. POST /api/v1/leases/{lease_id}/verification-code  → 取验证码
4. POST /api/v1/leases/{lease_id}/release            → 释放租约（务必做）
```

可选：

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/usage-sites` | 查询可用注册站点 code（`usage_site`） |
| `POST /api/v1/mailboxes/reacquire` | 按历史 `allocated_email` 重新领租约 |

> **不在本文范围**：`POST /api/v1/leases/acquire`（AT/RT Token 租约，仅 Microsoft）。读码场景请统一走 `mailboxes/acquire`。

---

## 2. 基础约定

### 2.1 Base URL

由部署环境提供，例如：

```text
https://<your-host>
```

公开文档（调试）：

- Swagger：`/docs`
- ReDoc：`/redoc`
- OpenAPI：`/openapi.json`

### 2.2 鉴权

所有外部接口请求头：

```http
X-API-Key: <Client API Key 明文>
Content-Type: application/json
```

- Key 由管理员创建，**明文只返回一次**，请安全保存。
- 管理接口用的 `X-Admin-Token` **不能**调用外部接口。

### 2.3 统一错误体

HTTP 非 2xx 时，body 一般为：

```json
{
  "detail": {
    "code": "NO_AVAILABLE_MAILBOX",
    "message": "没有可用邮箱"
  }
}
```

请按 `detail.code` 分支处理，不要只依赖 HTTP 状态码文案。

---

## 3. 邮箱类型（provider_type）

| provider_type | 供给方式 | 说明 | 领取所需额外 scope |
| --- | --- | --- | --- |
| `microsoft` | 库存导入 | Outlook/Hotmail；主邮箱 / plus 别名 | **无**（仅需 `mailboxes:acquire`） |
| `smsbower_gmail` | 库存补货 | Gmail 租号 | `providers:smsbower_gmail:acquire` |
| `cloudflare_temp_email` | 即时开箱 | Temp 邮箱 | `providers:cloudflare_temp_email:acquire` |
| `ddg_mail` | 即时开箱 | Duck 别名 + 读信 | `providers:ddg_mail:acquire` |
| `cloudmail_gen` | 即时开箱 | | `providers:cloudmail_gen:acquire` |
| `tempmail_lol` | 即时开箱 | | `providers:tempmail_lol:acquire` |
| `duckmail` | 即时开箱 | | `providers:duckmail:acquire` |
| `gptmail` | 即时开箱 | | `providers:gptmail:acquire` |
| `moemail` | 即时开箱 | | `providers:moemail:acquire` |
| `inbucket` | 即时开箱 | 自建 Inbucket | `providers:inbucket:acquire` |
| `yyds_mail` | 即时开箱 | | `providers:yyds_mail:acquire` |

说明：

1. 非 `microsoft` 类型必须在 Client Key 上授予对应 `providers:{type}:acquire`，否则不会进入候选池；**显式指定未授权类型会 403**。
2. 即时开箱类型还须在服务端管理台启用并配置密钥/域名；未配置时可能返回 `PROVIDER_NOT_CONFIGURED` 或在多类型随机中跳过该类型。
3. 类型字符串大小写不敏感，服务端会规范化为小写。

---

## 4. Client Key 权限（scopes）

### 4.1 读码最小集合

```json
[
  "mailboxes:acquire",
  "mailboxes:reacquire",
  "mail:verification-code:read",
  "leases:release"
]
```

### 4.2 需要多类型 / 非 Microsoft 时

额外按类型授权，例如：

```json
[
  "mailboxes:acquire",
  "mailboxes:reacquire",
  "mail:verification-code:read",
  "leases:release",
  "providers:smsbower_gmail:acquire",
  "providers:inbucket:acquire"
]
```

| scope | 作用 |
| --- | --- |
| `mailboxes:acquire` | 领取 mail_read 租约（必选） |
| `mailboxes:reacquire` | 按历史地址重新领取 |
| `mail:verification-code:read` | 读验证码 |
| `leases:release` | 释放租约 |
| `providers:{type}:acquire` | 允许该邮箱类型进入候选池 / 显式领取 |

**安全默认**：已有 Key **不会**自动获得全部 `providers:*:acquire`。没有额外 scope 时，省略/`all` 只会落到 `microsoft`。

---

## 5. 领取接口（核心变更）

### 5.1 接口

```http
POST /api/v1/mailboxes/acquire
```

### 5.2 请求字段

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `provider` | `string` \| `string[]` \| 省略 | 否 | 邮箱类型选择。见下文 |
| `exclude_providers` | `string` \| `string[]` \| 省略 | 否 | 排除类型；**优先级最高** |
| `lease_ttl_seconds` | int | 否 | 租约秒数，默认 `600`，范围 `60–86400` |
| `usage_site` | string | 条件 | 注册站点 code。**microsoft 主邮箱路径必填**；plus 别名可选；多数非 microsoft 可不传 |
| `preferred_email` | string | 否 | 优先指定主邮箱（库存类） |
| `use_plus_alias` | bool | 否 | 默认 `false`。仅当**实际命中 microsoft** 时分配 `user+xxxx@domain`；命中非 microsoft 时**忽略**，不会强制改走 microsoft |
| `alias_suffix` | string | 否 | 指定 plus 后缀（小写字母数字）；仅对 microsoft 生效 |
| `client_tag` | string | 否 | 调用方标签，便于排查 |
| `purpose` | string | 否 | 用途说明 |

#### `provider` 取值

| 传参 | 语义 |
| --- | --- |
| 省略 / `null` / `""` | 等价 **all**：在「已授权」类型中随机 |
| `"all"` | 同上 |
| `"microsoft"` | 仅 Microsoft |
| `["microsoft", "smsbower_gmail"]` | 仅在列表内随机 |
| 含 `"all"` 的数组 | 整段按 all 处理 |

> 推荐 JSON 使用数组；单字符串也支持。不要用逗号拼在一个字符串里（`"a,b"` 会被当成非法类型名）。

#### `exclude_providers` 取值

| 传参 | 语义 |
| --- | --- |
| 省略 | 不排除 |
| `"microsoft"` | 排除 Microsoft |
| `["microsoft", "inbucket"]` | 排除多个 |

**规则：先 apply 排除，再随机。**  
即使 `provider` 写了某类型，只要出现在 `exclude_providers` 中，也不会被选中。

### 5.3 类型选择算法（调用方必须理解）

```text
1. 构造候选池
   - provider 省略 / all  → 全部已知 provider_type
   - provider 为列表/单值 → 仅这些类型
2. 减去 exclude_providers（最高优先级）
3. 减去当前 Client Key 未授权的类型
   - 省略/all 时：静默跳过未授权类型
   - 显式写了未授权类型：403 CLIENT_SCOPE_REQUIRED
4. 候选为空 → 400 PROVIDER_UNSUPPORTED
5. 对候选随机打乱，依次尝试领取
   - 库存为空 / 未配置 / 暂不可用 → 跳过下一个
   - 全部失败 → 409 NO_AVAILABLE_MAILBOX（或 microsoft 相关校验错误）
6. 成功则返回实际命中的 provider
```

特殊：

- `use_plus_alias=true` / `alias_suffix`：**仅当实际命中 microsoft 时**分配 plus；命中非 microsoft 时忽略，**不会**强制改走 microsoft。
- `usage_site`：microsoft **主邮箱**必填；可先 `GET /api/v1/usage-sites` 取可用 code。

### 5.4 成功响应 `201`

```json
{
  "lease_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "mailbox_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
  "primary_email": "owner@outlook.com",
  "allocated_email": "owner@outlook.com",
  "address_kind": "primary",
  "usage_site": "openai",
  "provider": "microsoft",
  "mode": "mail_read",
  "expires_at": "2026-07-21T12:10:00",
  "created_at": "2026-07-21T12:00:00"
}
```

| 字段 | 含义 | 调用方应如何用 |
| --- | --- | --- |
| `lease_id` | 租约 ID | 读码、释放的路径参数；**必存** |
| `mailbox_id` | 邮箱 ID | 排查用 |
| `primary_email` | 主邮箱 | OAuth/IMAP 身份（业务注册一般用 allocated） |
| `allocated_email` | **业务收件地址** | **注册填这个**；reacquire 也用这个 |
| `address_kind` | `primary` / `plus_alias` | 展示/统计 |
| `usage_site` | 本次声明的站点 | 可为空 |
| `provider` | **实际命中类型** | 多类型随机时务必读此字段；建议落库 |
| `expires_at` | 租约到期 | 到期后需 reacquire 或重新 acquire |

> 响应中的 `provider` 现在会返回实际类型（含随机命中结果）。请不要假设省略 provider 就一定是 microsoft——还取决于 Key 的 scopes 与库存。

### 5.5 与旧版差异（适配必看）

| 点 | 旧行为 | 新行为 |
| --- | --- | --- |
| 省略 `provider` | **仅** Microsoft | 在**已授权**类型中随机；无额外 scope 时仍只有 microsoft |
| 响应 `provider` | 仅显式指定时返回 | **始终返回**实际类型 |
| 多类型 | 需多次改参数 | 一次请求传数组 / all + exclude |
| 排除 | 无 | `exclude_providers` 最高优先 |

**兼容建议：**

1. 若业务**只想要 Microsoft**：请求写死  
   `"provider": "microsoft"`  
   或  
   `"exclude_providers": ["smsbower_gmail", ...]`（列出不想要的），更稳妥是 **显式 `provider: "microsoft"`**。
2. 若业务**要随机多种临时邮箱**：给 Key 开齐对应 scopes，请求 `"provider": "all"` 或省略，并用 `exclude_providers` 去掉不想要的。
3. 持久化字段至少：`lease_id`、`allocated_email`、`provider`、`expires_at`。

---

## 6. 请求示例

### 6.1 只领 Microsoft（推荐写死，避免误随机构）

```bash
curl -sS -X POST "$BASE/api/v1/mailboxes/acquire" \
  -H "X-API-Key: $CLIENT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "microsoft",
    "usage_site": "openai",
    "lease_ttl_seconds": 600,
    "purpose": "register"
  }'
```

### 6.2 已授权类型中随机（省略 / all）

```bash
curl -sS -X POST "$BASE/api/v1/mailboxes/acquire" \
  -H "X-API-Key: $CLIENT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "all",
    "usage_site": "openai",
    "lease_ttl_seconds": 600
  }'
```

> 若 Key 只有 `mailboxes:acquire`，结果仍只会是 `microsoft`，且主邮箱路径必须带 `usage_site`。  
> 若 Key 还开了 `providers:smsbower_gmail:acquire` 等，可能随机到非 Microsoft；此时 `usage_site` 对非 microsoft 一般不强制。

### 6.3 多类型白名单随机

```bash
curl -sS -X POST "$BASE/api/v1/mailboxes/acquire" \
  -H "X-API-Key: $CLIENT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": ["microsoft", "smsbower_gmail", "inbucket"],
    "usage_site": "openai",
    "lease_ttl_seconds": 600
  }'
```

### 6.4 排除优先（例如 all 但不要 Microsoft）

```bash
curl -sS -X POST "$BASE/api/v1/mailboxes/acquire" \
  -H "X-API-Key: $CLIENT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "all",
    "exclude_providers": ["microsoft"],
    "lease_ttl_seconds": 600
  }'
```

### 6.5 列表内再排除

```json
{
  "provider": ["microsoft", "smsbower_gmail", "inbucket"],
  "exclude_providers": ["microsoft"],
  "usage_site": "openai"
}
```

结果候选：`smsbower_gmail`、`inbucket`（仍受 scope / 配置 / 库存约束）。

### 6.6 Microsoft plus 别名

```json
{
  "provider": "microsoft",
  "use_plus_alias": true,
  "lease_ttl_seconds": 600,
  "purpose": "register_with_alias"
}
```

- `allocated_email` 形如 `owner+ab12cd34@outlook.com`
- 注册与 reacquire 请使用 **完整** `allocated_email`
- 与 `all` + `exclude_providers: ["microsoft"]` 同传 `use_plus_alias=true` 合法：plus 被忽略，仍在非 microsoft 池中领取

---

## 7. 后续接口（完整闭环）

### 7.1 查询注册站点

```http
GET /api/v1/usage-sites
```

需要 scope：`mailboxes:acquire`  
用于填充 `usage_site`（如 `openai`、`grok`）。

### 7.2 读取验证码

```http
POST /api/v1/leases/{lease_id}/verification-code
```

需要 scope：`mail:verification-code:read`

请求体可按产品约定传过滤条件（部分 provider 不支持自定义 from/subject 等过滤器，会返回 `PROVIDER_FILTER_UNSUPPORTED`）。

成功时拿到验证码后，业务侧完成注册即可。

### 7.3 释放租约

```http
POST /api/v1/leases/{lease_id}/release
```

需要 scope：`leases:release`  
**幂等**：重复释放安全。  
用毕务必释放，避免占用库存。

### 7.4 按历史地址重新领取

```http
POST /api/v1/mailboxes/reacquire
```

```json
{
  "email": "<上次返回的 allocated_email>",
  "lease_ttl_seconds": 300,
  "purpose": "resend_verification"
}
```

- 仅允许 **同一 Client Key** 历史上 mail_read 用过的地址
- 成功后用新的 `lease_id` 再读码

---

## 8. 错误码速查

| HTTP | code | 常见原因 | 调用方建议 |
| --- | --- | --- | --- |
| 401 | `CLIENT_API_KEY_INVALID` | Key 错误/停用 | 检查 Key |
| 403 | `CLIENT_SCOPE_REQUIRED` | 缺 scope（如未开某 `providers:*:acquire`） | 找管理员加权限；或不要显式传该类型 |
| 400 | `PROVIDER_UNSUPPORTED` | 未知类型 / 排除后候选为空 | 检查 provider 拼写与 exclude |
| 400 | `INVALID_USAGE_SITE` | `usage_site` 缺失/未知/禁用 | microsoft 主邮箱必填；先拉 usage-sites |
| 400 | `PROVIDER_FILTER_UNSUPPORTED` | 该 provider 不支持验证码过滤器 | 去掉 from/subject 等过滤参数 |
| 409 | `NO_AVAILABLE_MAILBOX` | 库存空 / 全类型不可用 | 退避重试；或扩大 provider 列表 / 减 exclude |
| 409 | `EMAIL_SITE_IN_USE` | 该主邮箱已在该站点登记 | 换站或用 plus / 其他类型 |
| 409 | `MAILBOX_BUSY` | reacquire 时邮箱被占用 | 稍后重试 |
| 404 | `LEASE_NOT_FOUND` | 租约不存在或不属于你 | 检查 lease_id / Key |
| 404 | `EMAIL_NOT_FOUND` | reacquire 地址无归属 | 用首次 acquire 的 allocated_email |
| 503 | `PROVIDER_NOT_CONFIGURED` | 类型未启用/缺密钥 | 联系运维配置；或 exclude 该类型 |
| 422 | `INVALID_REQUEST` | 参数校验失败 | 按 message 修正 |

多类型随机时：某一类型暂不可用会**内部跳过**，只有全部失败才返回 409。

---

## 9. 调用方适配清单（Checklist）

- [ ] 使用 `X-API-Key`，不要混用 Admin Token  
- [ ] 读码链路使用 `mailboxes/acquire`，不要用 AT/RT 的 `leases/acquire`  
- [ ] 明确策略：
  - 只要 Microsoft → **写死** `"provider": "microsoft"` + `usage_site`
  - 要多类型随机 → 开 scopes + `"provider": "all"` 或类型数组 + 按需 `exclude_providers`
- [ ] 解析并持久化：`lease_id`、`allocated_email`、`provider`、`expires_at`  
- [ ] 注册填 **`allocated_email`**，不是盲目用 `primary_email`（plus 场景二者不同）  
- [ ] 用毕 `release`；过期后用 `reacquire(email=allocated_email)` 或重新 `acquire`  
- [ ] 对 `403 CLIENT_SCOPE_REQUIRED` / `409 NO_AVAILABLE_MAILBOX` / `503 PROVIDER_NOT_CONFIGURED` 做可观测日志（带上请求的 provider / exclude）  
- [ ] 与管理员确认 Client Key 的 scopes 列表与环境 Base URL  

---

## 10. 推荐伪代码

```python
def acquire_mailbox(client, *, strategy: str):
    if strategy == "microsoft_only":
        body = {
            "provider": "microsoft",
            "usage_site": "openai",
            "lease_ttl_seconds": 600,
        }
    elif strategy == "random_temp_only":
        body = {
            "provider": "all",
            "exclude_providers": ["microsoft"],
            "lease_ttl_seconds": 600,
        }
    elif strategy == "whitelist":
        body = {
            "provider": ["microsoft", "smsbower_gmail", "inbucket"],
            "exclude_providers": [],  # 可选
            "usage_site": "openai",
            "lease_ttl_seconds": 600,
        }
    else:
        raise ValueError(strategy)

    resp = client.post("/api/v1/mailboxes/acquire", json=body)
    resp.raise_for_status()
    data = resp.json()
    # 必须读实际类型
    return data["lease_id"], data["allocated_email"], data["provider"]


def finish(client, lease_id: str):
    client.post(f"/api/v1/leases/{lease_id}/release")
```

---

## 11. 联调前找管理员确认的事项

1. 外部 Base URL、是否 HTTPS  
2. Client Key 明文与 **scopes 列表**  
3. 已启用、已配置的 provider 类型（尤其即时开箱类）  
4. 可用 `usage_site` code 列表（或你们自己调 `GET /usage-sites`）  
5. 租约建议 TTL、峰值时是否需扩大 provider 白名单  

---

## 12. 相关文档

| 文档 | 内容 |
| --- | --- |
| 服务根 README | 总览、scope 列表、部署 |
| `docs/smsbower-gmail-phase1a.md` | SMSBower 补货与 release 细节 |
| 在线 `/docs` | 最新 OpenAPI 字段说明 |

如字段与在线 OpenAPI 冲突，以部署环境 `/openapi.json` 为准。

---

## 附录 A：字段一页纸

```text
POST /api/v1/mailboxes/acquire
Header: X-API-Key

provider:            省略|all|单类型|类型数组  → 候选池
exclude_providers:   单类型|类型数组           → 先剔除（最高优先）
scopes:              过滤未授权类型
结果:                随机尝试 → 返回 provider / lease_id / allocated_email

后续:
  verification-code(lease_id)
  release(lease_id)
  reacquire(email=allocated_email)   # 可选
```

## 附录 B：常见策略对照

| 业务诉求 | 请求建议 | Key scopes |
| --- | --- | --- |
| 稳定 Outlook 主邮箱 | `provider=microsoft` + `usage_site` | `mailboxes:acquire` + release/read |
| Outlook plus 防占用 | `provider=microsoft` + `use_plus_alias=true` | 同上 |
| 多种临时邮箱随机 | `provider=all` + `exclude_providers=["microsoft"]` | 对应各 `providers:*:acquire` |
| 仅库存 Gmail | `provider=smsbower_gmail` | + `providers:smsbower_gmail:acquire` |
| Microsoft 优先但可兜底临时邮 | `provider=["microsoft","inbucket",...]` | 对应 scopes；依赖随机与库存跳过 |
