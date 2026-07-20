# Mailbox Service

用于集中维护邮箱凭证与 `mail_read` 租约的单实例服务。当前已接入 Provider：

| Provider | 供给 | 能力 | 说明 |
| --- | --- | --- | --- |
| `microsoft` | inventory 导入 | AT / RT / mail_read | Outlook/Hotmail OAuth；四段文本导入；默认路径（省略 `provider` 仅此） |
| `smsbower_gmail` | inventory 补货 | mail_read | 显式 `provider` + `providers:smsbower_gmail:acquire`；管理台可配置与补货 |
| `cloudflare_temp_email` | on_demand | mail_read | 管理台配置；领取时即时开箱 |
| `ddg_mail` | on_demand | mail_read | DDG 别名 + CF 兼容收件箱 |
| `cloudmail_gen` | on_demand | mail_read | 管理台配置 |
| `tempmail_lol` | on_demand | mail_read | 管理台配置 |
| `duckmail` | on_demand | mail_read | 管理台配置 |
| `gptmail` | on_demand | mail_read | 管理台配置 |
| `moemail` | on_demand | mail_read | 管理台配置 |
| `inbucket` | on_demand | mail_read | 自建 Inbucket |
| `yyds_mail` | on_demand | mail_read | 管理台配置 |

管理台 **邮箱 Provider** 页可维护各类型启停、API Base、域名与密钥（密钥加密保存、不回显明文）。  
非 Microsoft 领取须 Client Key 具备 `providers:{type}:acquire`，且请求显式传 `provider`。

同时实现了全局出口代理池：OAuth Token 刷新和 XOAUTH2 IMAP 连接按邮箱粘性地复用同一健康代理，并在代理链路失败后切换至备用代理。

## 已实现的出口代理能力

- HTTP CONNECT 与 SOCKS5 全局代理池，代理认证凭证使用 AES-GCM 加密保存。
- 邮箱级粘性绑定，使用 MySQL 行锁与 `FOR UPDATE SKIP LOCKED` 防止并发绑定冲突。
- 按优先级和当前绑定数选择候选代理；代理被禁用、失败冷却或不可用时自动重选。
- 强制代理模式：没有健康代理时返回 `NO_HEALTHY_EGRESS_PROXY`，不会静默直连。
- OAuth Token 与 XOAUTH2 IMAP 共用同一个解析器和代理传输层；代理链路错误最多重试一次。
- 代理健康探测、冷却、恢复、审计、Dashboard 指标与管理 API。
- React 管理页提供代理添加、启停、测试、恢复、删除和全局策略配置。

## 本地启动

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
      "mailboxes:reacquire",
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
- `mailboxes:reacquire`：按历史主邮箱或 plus 别名重新领取 mail_read 租约
- `mail:verification-code:read`：在 mail_read 租约下读取收件箱验证码
- `providers:smsbower_gmail:acquire`：显式领取 SMSBower Gmail 库存（须与 `mailboxes:acquire` 同时授予；默认 Key **不含**此权限）

## 外部服务 API

所有外部服务接口使用请求头 `X-API-Key`，路径不带 `/admin`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/api/v1/leases/acquire` | 领取 AT 或 RT mode 邮箱租约（Microsoft only） |
| `POST` | `/api/v1/leases/{lease_id}/release` | 幂等释放租约 |
| `POST` | `/api/v1/leases/{lease_id}/access-token` | 获取未过期缓存 AT，过期时自动刷新 |
| `POST` | `/api/v1/leases/{lease_id}/refresh-token` | 按 `expected_token_version` CAS 回写 RT |
| `POST` | `/api/v1/mailboxes/acquire` | 领取可用邮箱账号（mail_read；省略 `provider` 仅 Microsoft；主邮箱须传 `usage_site`） |
| `GET` | `/api/v1/usage-sites` | 查询启用中的注册站点白名单（需 `mailboxes:acquire`） |
| `POST` | `/api/v1/mailboxes/reacquire` | 按历史业务地址（主邮箱或 plus 别名）重新领取 mail_read 租约 |
| `POST` | `/api/v1/leases/{lease_id}/verification-code` | 在 mail_read 租约下提取收件箱验证码 |

### Provider 矩阵（本轮已验证）

| provider_type | 供给方式 | 支持模式 | 备注 |
| --- | --- | --- | --- |
| `microsoft` | inventory（四段导入） | AT / RT / mail_read | 默认路径；省略 `provider` 仅此 |
| `smsbower_gmail` | inventory（Admin 补货） | mail_read only | 须显式 `provider` + scope；详见 [docs/smsbower-gmail-phase1a.md](docs/smsbower-gmail-phase1a.md) |

TempMail / DDG / 通用 HTTP profile **未**作为 enabled Provider 暴露。

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
| `POST` | `/api/v1/admin/client-keys/{id}/disable` | 停用 Client Key |
| `GET` | `/api/v1/admin/usage-sites` | 查询注册站点白名单（含已禁用） |
| `POST` | `/api/v1/admin/usage-sites` | 创建注册站点（code 不可改） |
| `PATCH` | `/api/v1/admin/usage-sites/{code}` | 更新展示名或启用状态 |
| `DELETE` | `/api/v1/admin/usage-sites/{code}` | 删除站点（仅无未撤销占用时） |
| `GET` | `/api/v1/admin/email-site-usages` | 分页查询邮箱站点占用 |
| `POST` | `/api/v1/admin/email-site-usages/{id}/revoke` | 软撤销邮箱站点占用（幂等） |

管理台：

- **注册站点**：新增 / 启停 / 删除（无占用时）白名单
- **站点占用**：按业务邮箱、站点筛选占用，并可一键撤销
- **邮箱管理**：行内「站点占用」跳转并按主邮箱筛选占用

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

## Docker 镜像打包与 ARM 服务器部署

镜像为多阶段构建：Node 编译管理台 + **Python 3.14** 运行 FastAPI，**默认目标平台 `linux/arm64`**。  
基座镜像为 `python:3.14-slim-bookworm`，与本地开发版本对齐。  
默认镜像名：**`registry.example.com/mailbox-service:latest`**；`./scripts/build-image.sh` **默认构建后自动推送**到该私有仓库。`docker-compose.yml` 默认 `image` 与此一致。

**分层缓存（减小 push / pull）：** 依赖与代码严格分 stage / layer：

| 层 | 何时失效 | 典型体积 |
| --- | --- | --- |
| OS + `appuser` | 基座镜像 / apt 变更 | 中 |
| Python `.venv`（`python-deps`） | 仅 `pyproject.toml` / `uv.lock` 变更 | 大（约数十 MB） |
| `mailbox_service/` | 后端代码变更 | 小 |
| `migrations/` | 迁移脚本变更 | 很小 |
| `frontend_dist` | 前端构建产物变更 | 中小 |
| 前端 `npm ci`（`frontend-deps`） | 仅 `package-lock.json` 变更 | 构建期大，不进最终镜像依赖重装 |

仅改后端代码时，`docker push` / `docker pull` 会跳过仓库里已有的依赖层，服务器通常只需拉取代码层。  
推送方式：构建完成后执行 `docker push registry.example.com/mailbox-service:<tag>`（仅正式镜像标签）。**不**推送 BuildKit 的 `:buildcache`；跨机器构建加速靠 Dockerfile 分层 + 本机 BuildKit 缓存即可。

相关文件：

| 路径 | 作用 |
| --- | --- |
| `Dockerfile` | 多阶段 / 分层构建定义 |
| `scripts/build-image.sh` | buildx `--load` 后 `docker push` 正式镜像 |
| `docker-compose.yml` | 应用部署；默认拉取 `registry.example.com/mailbox-service:latest`，外连共享 infra MySQL |
| `.dockerignore` | 减小构建上下文 |

### 前置条件

- 本机已安装 Docker，并支持 `docker buildx`
- 本机与目标服务器均可访问私有仓库 `registry.example.com`（**无需** `docker login`，直接 pull/push）
- 在 **x86 开发机交叉构建 arm64** 时，Docker Desktop 需开启 containerd / QEMU
- 目标服务器已安装 Docker（可选 Docker Compose v2）

### 1. 打包并推送镜像（推荐）

```bash
# 赋予执行权限（首次）
chmod +x scripts/build-image.sh

# 默认：构建 linux/arm64 并推送 registry.example.com/mailbox-service:latest
./scripts/build-image.sh

# 仅本机载入、不推仓库（调试）
./scripts/build-image.sh --output load

# 导出 tar（离线场景，不推仓库）
./scripts/build-image.sh --output tar
```

常用参数：

```text
--platform   默认 linux/arm64；也可 linux/amd64
--tag        镜像标签，默认 latest
--name       仓库名，默认 mailbox-service
--registry   私有仓库主机，默认 registry.example.com
--output     默认 push；可选 load | tar
```

完整镜像引用：`registry.example.com/mailbox-service:latest`

### 2. 服务器拉取镜像

```bash
# 服务器直接拉取（无需 login）
docker pull registry.example.com/mailbox-service:latest
docker images | grep mailbox-service
```

离线 tar 场景（非默认）：

```bash
# 开发机
./scripts/build-image.sh --output tar
scp dist/mailbox-service-*-linux-arm64.tar user@arm-server:/opt/mailbox-service/

# 服务器
docker load -i mailbox-service-*-linux-arm64.tar
```

### 3. 准备配置与数据库

在服务器项目目录（或部署目录）准备 `.env`：

```bash
cp .env.example .env
# 编辑至少以下项：
#   ADMIN_API_TOKEN
#   CREDENTIAL_ENCRYPTION_KEY   # 32 字节 URL-safe Base64
#   DATABASE_URL
#   APP_ENV=production
#   CORS_ALLOW_ORIGINS=*        # 同源管理台可设 *
#   PROXY_REQUIRED=true/false   # 按出口策略
```

生成加密密钥示例：

```bash
python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

**数据库迁移：**

- **推荐**：保持 `AUTO_MIGRATE_ON_STARTUP=true`（默认）。服务启动时会自动检测版本并执行 `migrations/` 中尚未记录的脚本，结果写入 `schema_migrations`。
- Compose 使用共享基础设施 `mysql-host`（网络 `external_network`）时，请先创建 `mailbox_service` 库；表结构由应用启动迁移负责。
- 关闭自动迁移时设 `AUTO_MIGRATE_ON_STARTUP=false`，再按序号手动执行：

```bash
for migration_file in migrations/*.sql; do
  mysql -u root -p mailbox_service < "$migration_file"
done
```

- 新增迁移请继续使用 `00N_描述.sql` 命名；**不要修改已上线版本的 SQL 内容**（版本号一旦记录即视为已应用）。

### 4a. 用 Compose 部署（应用 + 外连共享 infra MySQL）

`docker-compose.yml` 默认镜像为 `registry.example.com/mailbox-service:latest`，与打包脚本一致。可覆盖：

```bash
export MAILBOX_IMAGE=registry.example.com/mailbox-service:latest
# 或 docker compose pull && docker compose up -d
```

Compose 默认**不自带 MySQL**，接入本机已运行的共享基础设施（见 `Docker/infra/docker-compose.yml`）：

| 资源 | 值 |
| --- | --- |
| 网络 | `external_network`（compose 项目 `infra` 的 `infra` 网络） |
| MySQL 容器 | `mysql-host` |
| 默认账号 | `root` / `change-me`（仅本地开发） |

先启动基础设施：

```bash
cd /path/to/infra
docker compose up -d
```

应用侧 `.env` 中容器内主机名须为 `mysql-host`，勿写 `127.0.0.1`：

```env
DATABASE_URL=mysql+pymysql://root:change-me@mysql-host:3306/mailbox_service
APP_ENV=production
CORS_ALLOW_ORIGINS=*
```

本机直接跑 uvicorn 时把主机改成 `127.0.0.1` 即可。

首次使用需保证库已创建：

```bash
docker exec -i mysql-host mysql -uroot -pchange-me \
  -e "CREATE DATABASE IF NOT EXISTS mailbox_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

启动：

```bash
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8000/health
```

访问：

- 管理台：`http://<服务器IP>:8000/`
- 公开 API 文档：`http://<服务器IP>:8000/docs`
- 健康检查：`http://<服务器IP>:8000/health`

### 4b. 仅运行应用容器（外部已有 MySQL）

```bash
docker run -d \
  --name mailbox-service \
  --restart unless-stopped \
  -p 8000:8000 \
  --env-file .env \
  -e APP_ENV=production \
  -e CORS_ALLOW_ORIGINS='*' \
  --network infra_default \
  registry.example.com/mailbox-service:latest
```

确保 `.env` 中 `DATABASE_URL` 在容器内可达（Compose 场景用 `mysql-host` 主机名，并加入 `infra_default` 网络）。

### 5. 升级镜像

```bash
# 开发机：构建并自动推送到私有仓库
./scripts/build-image.sh

# 服务器：拉取最新 latest 并滚动
docker compose pull
docker compose up -d
# 默认会在启动时自动执行尚未记录的 migrations（见 AUTO_MIGRATE_ON_STARTUP）
```

### 6. 常见问题

| 现象 | 处理 |
| --- | --- |
| `exec format error` | 镜像架构与服务器不一致；确认用 `linux/arm64` 构建并 `docker image inspect` 查看 `Architecture` |
| buildx 交叉构建失败 | 升级 Docker Desktop / 安装 qemu；或直接在 ARM 机器上 `--output load` |
| 管理台打不开 / 接口跨域 | 同源部署将 `CORS_ALLOW_ORIGINS=*`；分离前端时填实际管理台 Origin |
| 容器起不来 / DB 连接失败 | 检查 `DATABASE_URL`、MySQL 是否 healthy、安全组/防火墙、是否加入 `infra_default` |
| 拉取/推送镜像失败 | 确认网络可达 `registry.example.com`；HTTP 仓库时 Docker Desktop/daemon 需配置 `insecure-registries` |
| 脚本 push 报 `https://101.200...` EOF | 旧版用 `buildx --push` 会强制 HTTPS；已改为 `buildx --load` + `docker push`（与手动 push 一致），请更新脚本后重试 |
| 迁移未生效 | 查看启动日志中的迁移输出与 `schema_migrations` 表；应用启动迁移会补齐未记录版本 |
| Compose 仍用旧镜像 | `latest` 可能被本地缓存；执行 `docker compose pull` 后再 `up -d` |

## 安全限制

- 不要将 `.env`、代理密码、`refresh_token`、`access_token` 或 Admin Token 提交到版本控制。
- 代理密码、OAuth 凭证和 API Key 不能写入日志、审计、错误响应或管理台读取接口。
- 生产环境建议启用 `PROXY_REQUIRED=true`，并仅允许内网访问管理 API。
- 未实现 Microsoft 交互式 OAuth 首次授权；需导入已经获取的 refresh token。
- 生产镜像中务必更换默认 MySQL 密码、`ADMIN_API_TOKEN` 与 `CREDENTIAL_ENCRYPTION_KEY`。


## 安全加固与测试

本仓库按 `REQ-20260719-001` / `PLN-20260719-001` 落地了 Token claim/CAS、Lease claim、验证码授权复核、生产密钥校验、前端纯内存 Admin Token 等加固。

生产环境因历史部署**允许** `DATABASE_URL` 使用 root、`CORS_ALLOW_ORIGINS=*`、`TLS_MODE=disabled`；仍要求 `ADMIN_API_TOKEN` 长度大于 10 位（并拒绝常见占位值）、合法 `CREDENTIAL_ENCRYPTION_KEY`，并拒绝 `FORWARDED_ALLOW_IPS=*`。

### 本地可自动跑

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

