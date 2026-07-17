#!/usr/bin/env bash
# 构建 mailbox-service 镜像并默认推送到私有仓库 registry.example.com。
#
# 默认 push 流程：buildx --load 装入本机 Docker，再 docker push。
# 不要用 buildx --push 直推：container 驱动会走 HTTPS 访问仓库，
# 而 registry.example.com 多为 HTTP insecure registry，会报 Head "https://...": EOF。
# 本机 docker push 会走 Docker daemon 的 insecure-registries 配置，与手动推送一致。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# 默认：registry.example.com/mailbox-service:latest，每次构建后自动 push。
REGISTRY="${REGISTRY:-registry.example.com}"
IMAGE_NAME="${IMAGE_NAME:-mailbox-service}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PLATFORM="${PLATFORM:-linux/arm64}"
# push=构建后推送私有仓库（默认）；load=仅载入本机；tar=导出归档
OUTPUT="${OUTPUT:-push}"
BUILDER_NAME="${BUILDER_NAME:-mailbox-service-builder}"

usage() {
  cat <<'EOF'
用法:
  ./scripts/build-image.sh [选项]

默认行为:
  构建 linux/arm64 镜像 registry.example.com/mailbox-service:latest：
  1) buildx --load 载入本机 Docker
  2) docker push 推送到私有仓库
  仓库无需 docker login；网络可达 registry.example.com 即可。
  （Docker Desktop / daemon 需已把该地址加入 insecure-registries，与手动 push 相同。）

选项:
  --platform <平台>     目标平台，默认 linux/arm64
                        示例: linux/arm64 | linux/amd64
  --tag <标签>          镜像标签，默认 latest
  --name <名称>         镜像仓库名，默认 mailbox-service
  --registry <主机>     私有仓库主机，默认 registry.example.com
  --output <方式>       push | load | tar（默认 push）
                        push : 载入本机后 docker push
                        load : 仅载入本机 Docker（不推送）
                        tar  : 导出 docker-archive 到 dist/（不推送）
  --builder <名称>      buildx builder 名称，默认 mailbox-service-builder
  -h, --help            显示帮助

环境变量（与选项等价，选项优先）:
  REGISTRY / IMAGE_NAME / IMAGE_TAG / PLATFORM / OUTPUT / BUILDER_NAME

示例:
  # 默认：构建并推送 registry.example.com/mailbox-service:latest
  ./scripts/build-image.sh

  # 仅本机调试，不推仓库
  ./scripts/build-image.sh --output load

  # 额外打版本标签再推送
  ./scripts/build-image.sh --tag 20260717-abc1234
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="${2:?}"
      shift 2
      ;;
    --tag)
      IMAGE_TAG="${2:?}"
      shift 2
      ;;
    --name)
      IMAGE_NAME="${2:?}"
      shift 2
      ;;
    --registry)
      REGISTRY="${2:?}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?}"
      shift 2
      ;;
    --builder)
      BUILDER_NAME="${2:?}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "错误: 未找到 docker 命令，请先安装 Docker。" >&2
  exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
  echo "错误: 当前 Docker 不支持 buildx，请升级 Docker Desktop / 安装 buildx 插件。" >&2
  exit 1
fi

if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "创建 buildx builder: ${BUILDER_NAME}"
  docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use >/dev/null
else
  docker buildx use "${BUILDER_NAME}" >/dev/null
fi
docker buildx inspect --bootstrap >/dev/null

FULL_IMAGE_REF="${REGISTRY%/}/${IMAGE_NAME}:${IMAGE_TAG}"

echo "========================================"
echo "镜像:     ${FULL_IMAGE_REF}"
echo "平台:     ${PLATFORM}"
echo "输出方式: ${OUTPUT}"
echo "上下文:   ${ROOT_DIR}"
echo "========================================"

COMMON_ARGS=(
  --platform "${PLATFORM}"
  --file "${ROOT_DIR}/Dockerfile"
  --tag "${FULL_IMAGE_REF}"
  --progress=plain
  "${ROOT_DIR}"
)

build_and_load_local() {
  if [[ "${PLATFORM}" == *","* ]]; then
    echo "错误: 当前 push/load 流程仅支持单平台（需 --load 进本机 Docker）。" >&2
    echo "请使用 --platform linux/arm64 或 linux/amd64。" >&2
    exit 1
  fi
  docker buildx build --load "${COMMON_ARGS[@]}"
  docker image inspect "${FULL_IMAGE_REF}" --format '架构={{.Architecture}} OS={{.Os}} 大小={{.Size}}'
}

case "${OUTPUT}" in
  push)
    # 与手动 docker push 同一路径：先进入本机镜像列表，再由 daemon push。
    # 避免 buildx --push 对 HTTP 私有仓强制 HTTPS 导致 EOF。
    build_and_load_local
    echo
    echo "正在推送: ${FULL_IMAGE_REF}"
    docker push "${FULL_IMAGE_REF}"
    echo
    echo "已推送: ${FULL_IMAGE_REF}"
    echo "服务器拉取 / Compose 使用:"
    echo "  docker pull ${FULL_IMAGE_REF}"
    echo "  # docker-compose.yml 默认 image 已对齐该名称"
    ;;
  load)
    build_and_load_local
    echo
    echo "已载入本机 Docker（未推送）: ${FULL_IMAGE_REF}"
    ;;
  tar)
    if [[ "${PLATFORM}" == *","* ]]; then
      echo "错误: --output tar 仅支持单平台。" >&2
      exit 1
    fi
    mkdir -p "${ROOT_DIR}/dist"
    SAFE_TAG="${IMAGE_TAG//\//-}"
    SAFE_PLATFORM="${PLATFORM//\//-}"
    SAFE_PLATFORM="${SAFE_PLATFORM//,/_}"
    TAR_PATH="${ROOT_DIR}/dist/${IMAGE_NAME}-${SAFE_TAG}-${SAFE_PLATFORM}.tar"
    docker buildx build --output "type=docker,dest=${TAR_PATH}" "${COMMON_ARGS[@]}"
    echo
    echo "已导出镜像包（未推送）: ${TAR_PATH}"
    ls -lh "${TAR_PATH}"
    echo
    echo "加载示例: docker load -i $(basename "${TAR_PATH}")"
    ;;
  *)
    echo "错误: 不支持的 --output=${OUTPUT}（可选: push | load | tar）" >&2
    exit 1
    ;;
esac

echo
echo "完成。"
