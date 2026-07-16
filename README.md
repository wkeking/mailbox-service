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
   for migration_file in migrations/*.sql; do
     mysql -u root -p mailbox_service < "$migration_file"
   done
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

## Docker 镜像打包与 ARM 服务器部署

镜像为多阶段构建：Node 编译管理台 + Python 运行 FastAPI，**默认目标平台 `linux/arm64`**，适合 ARM 服务器。管理台静态资源打进镜像，由后端同源提供（`VITE_API_BASE_URL` 为空）。

相关文件：

| 路径 | 作用 |
| --- | --- |
| `Dockerfile` | 多阶段构建定义 |
| `scripts/build-image.sh` | 一键 buildx 打包（默认 arm64） |
| `docker-compose.yml` | 示例：应用 + MySQL 8 |
| `.dockerignore` | 减小构建上下文 |

### 前置条件

- 本机已安装 Docker，并支持 `docker buildx`
- 在 **x86 开发机交叉构建 arm64** 时，Docker Desktop 需开启 containerd / QEMU（一般安装后 `buildx` 可用即可）
- 目标 ARM 服务器已安装 Docker（可选 Docker Compose v2）

### 1. 打包镜像（推荐在开发机执行）

```bash
# 赋予执行权限（首次）
chmod +x scripts/build-image.sh

# 方式 A：构建 linux/arm64 并导出 tar（适合 scp 到 ARM 服务器）
./scripts/build-image.sh --platform linux/arm64 --output tar

# 方式 B：本机就是 arm64（如 Apple Silicon / ARM 云主机），直接载入 Docker
./scripts/build-image.sh --platform linux/arm64 --output load

# 方式 C：推送到私有仓库
./scripts/build-image.sh --platform linux/arm64 --output push \
  --registry registry.example.com/your-namespace
```

常用参数：

```text
--platform   默认 linux/arm64；也可 linux/amd64
--tag        镜像标签，默认 YYYYMMDD-<git短哈希>
--name       镜像名，默认 mailbox-service
--output     load | tar | push
--registry   push 时的仓库前缀
```

`tar` 模式产物示例：

```text
dist/mailbox-service-20260716-abc1234-linux-arm64.tar
```

### 2. 传到 ARM 服务器并加载

```bash
# 开发机
scp dist/mailbox-service-*-linux-arm64.tar user@arm-server:/opt/mailbox-service/

# ARM 服务器
cd /opt/mailbox-service
docker load -i mailbox-service-*-linux-arm64.tar
docker images | grep mailbox-service
```

若使用仓库推送，在服务器上：

```bash
docker pull registry.example.com/your-namespace/mailbox-service:<tag>
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

- 使用下方 `docker compose` 且 MySQL 为**全新数据卷**时：`migrations/*.sql` 会挂到 `docker-entrypoint-initdb.d`，**仅首次初始化**自动执行。
- 使用已有 MySQL / 升级已有库时，请按序号手动执行尚未应用的迁移（当前含 `001`–`008`）：

```bash
for migration_file in migrations/*.sql; do
  mysql -u root -p mailbox_service < "$migration_file"
done
```

### 4a. 用 Compose 部署（应用 + MySQL）

确认 `docker-compose.yml` 中镜像名与本地 tag 一致，例如：

```bash
export MAILBOX_IMAGE=mailbox-service:20260716-abc1234
# 或改 docker-compose.yml 的 image 字段 / 打 latest 标签：
docker tag mailbox-service:20260716-abc1234 mailbox-service:latest
```

Compose 内网访问 MySQL 时，`.env` 建议：

```env
DATABASE_URL=mysql+pymysql://mailbox_service:<密码>@mysql:3306/mailbox_service
MYSQL_PASSWORD=<密码>
MYSQL_ROOT_PASSWORD=<root密码>
APP_ENV=production
CORS_ALLOW_ORIGINS=*
```

启动：

```bash
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
  mailbox-service:20260716-abc1234
```

确保 `.env` 中 `DATABASE_URL` 指向服务器可达的 MySQL 地址（不要用仅容器内网的主机名，除非加了同一 Docker 网络）。

### 5. 升级镜像

```bash
# 开发机重新打包并 scp
./scripts/build-image.sh --platform linux/arm64 --output tar
scp dist/mailbox-service-*-linux-arm64.tar user@arm-server:/opt/mailbox-service/

# 服务器
docker load -i mailbox-service-<新tag>-linux-arm64.tar
# 若有新增 migrations/*.sql，先对已有库执行迁移
docker compose up -d
# 或 docker stop/rm 后按 4b 重新 run
```

### 6. 常见问题

| 现象 | 处理 |
| --- | --- |
| `exec format error` | 镜像架构与服务器不一致；确认用 `linux/arm64` 构建并 `docker image inspect` 查看 `Architecture` |
| buildx 交叉构建失败 | 升级 Docker Desktop / 安装 qemu；或直接在 ARM 机器上 `--output load` |
| 管理台打不开 / 接口跨域 | 同源部署将 `CORS_ALLOW_ORIGINS=*`；分离前端时填实际管理台 Origin |
| 容器起不来 / DB 连接失败 | 检查 `DATABASE_URL`、MySQL 是否 healthy、安全组/防火墙 |
| 迁移未生效 | 旧数据卷不会重跑 `initdb.d`；对已有库手动执行新 SQL |

## 安全限制

- 不要将 `.env`、代理密码、`refresh_token`、`access_token` 或 Admin Token 提交到版本控制。
- 代理密码、OAuth 凭证和 API Key 不能写入日志、审计、错误响应或管理台读取接口。
- 生产环境建议启用 `PROXY_REQUIRED=true`，并仅允许内网访问管理 API。
- 未实现 Microsoft 交互式 OAuth 首次授权；需导入已经获取的 refresh token。
- 生产镜像中务必更换默认 MySQL 密码、`ADMIN_API_TOKEN` 与 `CREDENTIAL_ENCRYPTION_KEY`。
