# RustBoard 运行时镜像（多 target：base / hub / panel / agent）。
#
# 构建上下文必须是仓库根目录：
#   docker buildx build --platform linux/amd64 --target hub -t rustboard-hub:dev .
#
# 镜像内不编译 Rust，只复制 packaging/build-release.sh 产出的静态二进制：
#   dist/<TARGETARCH>/bin/rustboard-{hub,panel,agent}
# 以及 web/dist 前端产物。构建前请先准备好这两个目录，详见 docker/README.md。
#
# 基础镜像固定 digest，避免 `latest` 漂移。升级 digest 时同步更新
# docs/plans/2026-10-25-m5-phase-b-delivery.md 与 docker/README.md。

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS base

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/pazzifirst/rustboard" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="RustBoard" \
      org.opencontainers.image.description="RustBoard 自建监控与轻量运维平台（hub / panel / agent）" \
      org.opencontainers.image.licenses="MIT"

# 运行期只需要证书、健康检查、信号转发与 setpriv；不安装编译工具链。
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
      util-linux \
 && rm -rf /var/lib/apt/lists/*

# 固定 UID/GID，entrypoint 用 setpriv 降权到该用户。
RUN groupadd --gid 10001 rustboard \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin rustboard

# /data 是唯一运行期可写目录：首次由 root 初始化，之后归 10001。
# 镜像内不创建 /etc/rustboard，也不写入任何配置、私钥或 token。
RUN install -d -m 0750 -o root -g root /data \
 && install -d -m 0755 /usr/share/rustboard/web

VOLUME ["/data"]

WORKDIR /
STOPSIGNAL SIGTERM

# ---------------------------------------------------------------------------
# hub：agent 接入 8443；管理口 8444 只绑容器内 127.0.0.1，不 EXPOSE、不发布。
# ---------------------------------------------------------------------------
FROM base AS hub

ARG TARGETARCH

COPY dist/${TARGETARCH}/bin/rustboard-hub /usr/local/bin/rustboard-hub
COPY docker/entrypoint-hub.sh /usr/local/bin/entrypoint-hub.sh
COPY web/dist/ /usr/share/rustboard/web/

RUN test -s /usr/share/rustboard/web/index.html \
 && chmod 0755 /usr/local/bin/rustboard-hub /usr/local/bin/entrypoint-hub.sh

EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=5 \
  CMD ["curl", "-fsS", "http://127.0.0.1:8444/healthz"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint-hub.sh"]

# ---------------------------------------------------------------------------
# panel：8080 由共享 hub network namespace 的 panel 监听，从 hub 服务发布。
# ---------------------------------------------------------------------------
FROM base AS panel

ARG TARGETARCH

COPY dist/${TARGETARCH}/bin/rustboard-panel /usr/local/bin/rustboard-panel
COPY docker/entrypoint-panel.sh /usr/local/bin/entrypoint-panel.sh
COPY web/dist/ /usr/share/rustboard/web/

RUN test -s /usr/share/rustboard/web/index.html \
 && chmod 0755 /usr/local/bin/rustboard-panel /usr/local/bin/entrypoint-panel.sh

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=5 \
  CMD ["curl", "-fsS", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint-panel.sh"]

# ---------------------------------------------------------------------------
# agent：不监听新端口；healthcheck 用 cert-info，未完成 enrollment 前会失败，
# 因此给了较长的 start-period。
# ---------------------------------------------------------------------------
FROM base AS agent

ARG TARGETARCH

COPY dist/${TARGETARCH}/bin/rustboard-agent /usr/local/bin/rustboard-agent
COPY docker/entrypoint-agent.sh /usr/local/bin/entrypoint-agent.sh

RUN chmod 0755 /usr/local/bin/rustboard-agent /usr/local/bin/entrypoint-agent.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["rustboard-agent", "cert-info", "--config", "/data/etc/rustboard/agent.toml"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint-agent.sh"]
