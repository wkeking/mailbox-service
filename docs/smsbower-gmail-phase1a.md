# SMSBower Gmail Phase 1A（库存补货 + mail_read）

状态：实现完成（2026-07-20）。单元测试：`tests/test_smsbower_*.py` 全绿；全量 `tests/`（排除 integration）154 passed。

## 范围

- 新 Provider：`smsbower_gmail`（inventory）
- 能力：Admin 补货 `getActivation`、外部 `mail_read` 领取、`getCode` 验证码、释放后 durable `setStatus`
- 非目标：fission 热切换、`setStatus=5`、plus alias、AT/RT 租约、后台自动补货调度

## 配置位置（推荐：管理台页面）

管理台侧栏 **「邮箱 Provider」**：

- 查看 Microsoft / SMSBower 目录与启用状态
- 启用 SMSBower、填写 API Base / Service / Domain / 最高价格 / 超时
- **API Key 在页面保存**（AES-GCM 加密入库，列表只显示是否已配置，不回显明文）
- **立即补货 1 个**

对应 API：

| 方法 | 路径 |
|------|------|
| `GET` | `/api/v1/admin/providers` |
| `GET` / `PATCH` | `/api/v1/admin/providers/smsbower_gmail/settings` |
| `POST` | `/api/v1/admin/providers/smsbower_gmail/replenish` |

生效规则：**数据库行优先于环境变量**。未在页面保存过时，仍回退到 env。

## 配置（env 兜底，可选）

见 `.env.example`：

| 变量 | 说明 |
|------|------|
| `SMSBOWER_ENABLED` | 默认 `false`（无 DB 行时生效） |
| `SMSBOWER_API_BASE` | 默认 `https://smsbower.page/api/mail` |
| `SMSBOWER_API_KEY` / `SMSBOWER_API_KEY_FILE` | 可选兜底密钥；页面保存后优先用 DB |
| `SMSBOWER_SERVICE` | 默认 `openai` → 上游 `service=dr` |
| `SMSBOWER_DOMAIN` | 默认 `gmail.com` |
| `SMSBOWER_MAX_PRICE` | 可选 |
| `SMSBOWER_INSTANCE_ID` | 默认 `default` |
| `SMSBOWER_REQUEST_TIMEOUT_SECONDS` | 默认 30 |

迁移：`migrations/017_create_provider_instance_settings.sql`（`provider_instance_settings` 表）

## API

### Admin 补货

`POST /api/v1/admin/providers/smsbower_gmail/replenish`  
Header: `X-Admin-Token`  
返回：`operation_id`, `status`, `mailbox_id`, `primary_email`, `external_resource_id`, `error_class`（无 secret）

### 外部领取

`POST /api/v1/mailboxes/acquire`

- **省略 `provider`**：仅 Microsoft（legacy 兼容）
- **`provider=smsbower_gmail`**：需要 Client Key 同时具备  
  `mailboxes:acquire` + `providers:smsbower_gmail:acquire`
- SMSBower **不支持** plus alias；`usage_site` 本轮不强制

### 验证码

`POST /api/v1/leases/{lease_id}/verification-code`  
SMSBower：直接 `getCode`，不走 TokenService / IMAP / Graph。  
带 `from_address` / `subject_contains` / `body_contains` / `recipient` 过滤器 → `400 PROVIDER_FILTER_UNSUPPORTED`。

### 释放

`POST /api/v1/leases/{lease_id}/release`  
本地先 `released_at` + 删除 claim；SMSBower 额外 durable `release` 操作 + `setStatus=3`；超时/网络未知 → `release_unknown`，**禁止二次购买**。

## Client Key scope

新增可选 scope：`providers:smsbower_gmail:acquire`  
**已有 Key 默认不带此权限**，不会隐式领到 SMSBower 库存。

## 安全边界

- Microsoft 四段导入 / Token 刷新 / keepalive / unprobed 探测：仅 `provider_type=microsoft`
- import 冲突：非 Microsoft 邮箱拒绝四段覆盖
- `resource_generation` CAS 防止 release 回写到新代资源

## 上游契约冻结

- 源：`chatgpt2api` `services/register/smsbower_mail.py` @ `f26f636…`
- 实现模块：`mailbox_service/providers/smsbower_contracts.py`
