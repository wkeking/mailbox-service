#!/usr/bin/env bash
# Build (and optionally export) the mailbox-service container image for ARM servers.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

IMAGE_NAME="${IMAGE_NAME:-mailbox-service}"
IMAGE_TAG="${IMAGE_TAG:-$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
# Default target is ARM64 Linux for the production servers described in the README.
PLATFORM="${PLATFORM:-linux/arm64}"
OUTPUT="${OUTPUT:-load}"
PUSH_REGISTRY="${PUSH_REGISTRY:-}"
BUILDER_NAME="${BUILDER_NAME:-mailbox-service-builder}"

usage() {
  cat <<'EOF'
用法:
  ./scripts/build-image.sh [选项]

选项:
  --platform <平台>     目标平台，默认 linux/arm64
                        示例: linux/arm64 | linux/amd64 | linux/arm64,linux/amd64
  --tag <标签>          镜像标签，默认 YYYYMMDD-<git-short-sha>
  --name <名称>         镜像名，默认 mailbox-service
  --output <方式>       load | tar | push（默认 load）
                        load  : 载入本机 Docker（仅单平台）
                        tar   : 导出 docker-archive 到 dist/
                        push  : 推送到镜像仓库（需 --registry）
  --registry <仓库前缀> 推送时使用，例如 registry.example.com/team
  --builder <名称>      buildx builder 名称，默认 mailbox-service-builder
  -h, --help            显示帮助

环境变量（与选项等价，选项优先）:
  IMAGE_NAME / IMAGE_TAG / PLATFORM / OUTPUT / PUSH_REGISTRY / BUILDER_NAME

示例:
  # 本机（Apple Silicon / arm64）直接构建并载入 Docker
  ./scripts/build-image.sh

  # 在 x86 开发机上交叉构建 arm64，并导出 tar 拷到 ARM 服务器
  ./scripts/build-image.sh --platform linux/arm64 --output tar

  # 推送到私有仓库
  ./scripts/build-image.sh --output push --registry registry.example.com/mailbox
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
    --output)
      OUTPUT="${2:?}"
      shift 2
      ;;
    --registry)
      PUSH_REGISTRY="${2:?}"
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

# Ensure a builder that can cross-compile (especially amd64 host -> arm64 image).
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "创建 buildx builder: ${BUILDER_NAME}"
  docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use >/dev/null
else
  docker buildx use "${BUILDER_NAME}" >/dev/null
fi
docker buildx inspect --bootstrap >/dev/null

FULL_IMAGE_REF="${IMAGE_NAME}:${IMAGE_TAG}"
if [[ -n "${PUSH_REGISTRY}" ]]; then
  FULL_IMAGE_REF="${PUSH_REGISTRY%/}/${IMAGE_NAME}:${IMAGE_TAG}"
fi

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

case "${OUTPUT}" in
  load)
    if [[ "${PLATFORM}" == *","* ]]; then
      echo "错误: --output load 仅支持单平台；多平台请使用 tar 或 push。" >&2
      exit 1
    fi
    docker buildx build --load "${COMMON_ARGS[@]}"
    echo
    echo "已载入本机 Docker: ${FULL_IMAGE_REF}"
    docker image inspect "${FULL_IMAGE_REF}" --format '架构={{.Architecture}} OS={{.Os}} 大小={{.Size}}'
    ;;
  tar)
    if [[ "${PLATFORM}" == *","* ]]; then
      echo "错误: --output tar 仅支持单平台；多平台请使用 --output push。" >&2
      exit 1
    fi
    mkdir -p "${ROOT_DIR}/dist"
    SAFE_TAG="${IMAGE_TAG//\//-}"
    SAFE_PLATFORM="${PLATFORM//\//-}"
    SAFE_PLATFORM="${SAFE_PLATFORM//,/_}"
    TAR_PATH="${ROOT_DIR}/dist/${IMAGE_NAME}-${SAFE_TAG}-${SAFE_PLATFORM}.tar"
    docker buildx build --output "type=docker,dest=${TAR_PATH}" "${COMMON_ARGS[@]}"
    echo
    echo "已导出镜像包: ${TAR_PATH}"
    ls -lh "${TAR_PATH}"
    echo
    echo "在 ARM 服务器上加载:"
    echo "  docker load -i $(basename "${TAR_PATH}")"
    ;;
  push)
    if [[ -z "${PUSH_REGISTRY}" ]]; then
      echo "错误: --output push 需要同时指定 --registry <仓库前缀>" >&2
      exit 1
    fi
    docker buildx build --push "${COMMON_ARGS[@]}"
    echo
    echo "已推送: ${FULL_IMAGE_REF}"
    ;;
  *)
    echo "错误: 不支持的 --output=${OUTPUT}（可选: load | tar | push）" >&2
    exit 1
    ;;
esac

echo
echo "完成。"
