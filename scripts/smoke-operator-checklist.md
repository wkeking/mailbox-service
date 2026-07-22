# 需要操作员环境配合的验收清单

以下项无法在无 MySQL/TLS/压测环境时自动证明，请按需执行。

## 1. MySQL 8 并发（必须）

```bash
export TEST_DATABASE_URL='mysql+pymysql://USER:PASS@HOST:3306/mailbox_service_test'
uv run --frozen pytest -m mysql -vv
```

期望：全部 passed；含 token single-flight 与 32 线程 lease claim。

## 2. 生产配置（历史部署兼容）

以下**允许**用于 production（历史原因）：

- `DATABASE_URL` 使用 `root`（及同类账户）
- `CORS_ALLOW_ORIGINS=*`
- `TLS_MODE=disabled`（TLS 由外部终止时）

仍会拒绝：

- 过短 / 占位 `ADMIN_API_TOKEN`
- 缺失或示例 `CREDENTIAL_ENCRYPTION_KEY`
- `FORWARDED_ALLOW_IPS=*`

```bash
# 期望：可成功构造 Settings（给定足够长 Admin Token 与合法加密密钥）
APP_ENV=production \
DATABASE_URL='mysql+pymysql://root:root@127.0.0.1:3306/mailbox_service' \
CORS_ALLOW_ORIGINS='*' \
TLS_MODE=disabled \
ADMIN_API_TOKEN='long-enough-admin-token-value' \
CREDENTIAL_ENCRYPTION_KEY="$(python -c 'from base64 import urlsafe_b64encode; print(urlsafe_b64encode(b"k"*32).decode())')" \
uv run python -c 'from mailbox_service.config import Settings; print(Settings().app_env)'
```

## 3. TLS / 反向代理

- 若使用外部反向代理终止 TLS：配置 `TLS_MODE=terminated_at_proxy` 与可信 `FORWARDED_ALLOW_IPS`
- 应用 8000 不对公网直连（默认绑定 `127.0.0.1`）
- `/live` `/ready` 正常

## 4. 前端 Admin Token（浏览器）

1. 登录后 DevTools → Application：`sessionStorage` **无** Admin Token
2. 刷新页面 → 需重新输入 Token
3. 故意错误 Token / 后端 401 → 回到登录态

## 5. 压力（可选）

- 60s 验证码轮询容量：超额返回 429 + `Retry-After`
- 32 线程同邮箱 lease acquire：仅 1 成功

## 6. 容器 frozen 构建

```bash
./scripts/verify-build.sh
docker build --pull -t mailbox-service:smoke .
```
