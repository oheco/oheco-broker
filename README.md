# oheco-broker 0.4.0

Go 管理服务与原生 C peer 引擎组成的端口映射工具。管理服务提供 SQLite 账号、审批、WS/WSS 信令及 Pion STUN/TURN；C 引擎使用 libjuice、xquic 和 BoringSSL，在两端完成密码认证与加密。Go SDK 和 CLI 通过 cgo 调用同一套 C 引擎。

## 安装与使用

HarmonyOS arm64 发行包提供 CLI 和独立服务端，以及 **C、Go、.NET 源码 SDK**。完整固定版本的 C 依赖及离线构建资源位于 `sdk/c/`；SDK 不以预编译库发行。

```sh
oo update
oo install oheco-broker
oheco-broker --version
oheco-broker --help
oheco-broker-server --help
```

安装包中的 `sdk/` 包含 C、Go、.NET 源码，可直接从安装目录使用。需要独立可编辑副本时，从 [Release](https://github.com/oheco/oheco-broker/releases/tag/v0.4.0) 下载 SDK 源码附件并解压。源码随附完整固定依赖、构建资源和许可证，由使用者在目标平台离线构建。

客户端入口 `bin/oheco-broker` 是可迁移的 shell 启动器，运行已签名的 `libexec/oheco-broker`，并为它配置随包的 `lib/runtime/libc++_shared.so`。独立 `bin/oheco-broker-server` 是已签名 ELF，只依赖系统 C 运行库。安装不会自动启动或部署服务。

连接自托管服务时，使用实际 HTTPS 地址：

```sh
export OHECO_BROKER_API=https://example.org:8443
oheco-broker tenant register --email user@example.org
oheco-broker tenant capabilities
# 管理员批准账号；force 模式还需单独启用租户 relay 权限。
oheco-broker tenant serve --name desktop --password-stdin \
  --allow tcp@127.0.0.1:8080 < /private/path/peer-password
# 另一端登录同一租户，输入相同的 peer 密码：
oheco-broker tenant connect --name desktop --password-stdin \
  --protocol tcp --target 127.0.0.1:8080 --local 9090 \
  --relay auto < /private/path/peer-password
```

短时网络中断会自动重试，连接与映射句柄保持不变。双方使用 v2 时，仍存活的 TCP 会话可在默认 120 秒宽限内恢复；重试耗尽后可调用 C/Go 重连函数，或向 CLI 发送 `SIGUSR1`。使用 `--state-events` 输出状态变化，默认的初次就绪 JSON 保持兼容。策略与集成示例见[自动与手动重连说明](docs/RECONNECT.md)。

域名和目标是示例。无参数显示帮助；原本地命令执行服务通过 `oheco-broker shell serve` 显式启动。该子命令无鉴权，仅适用于可信本机开发。

## Docker 部署

Linux 镜像 `ghcr.io/oheco/oheco-broker:0.4.0` 同时提供独立服务端和 CLI，默认启动服务端。见 [Docker 部署说明](docs/DOCKER.md)：内置 ACME 通过主机 TCP 443 自动签发／续期；外部 acme.sh／Certbot 导出只读证书时，可用 HTTPS TCP 3478，与 TURN UDP 3478 及 relay 范围同时运行。

## 源码构建与测试

完整 checkout 包含 Go `vendor/` 及 C `sdk/c/tpr/`，构建不下载依赖。HarmonyOS 构建需要原生 Go 1.25+、clang/clang++、CMake、Ninja、Python 和 `binary-sign-tool`；旧命令服务回归还需要 .NET 10。

```sh
sh scripts/build.sh
sh scripts/test-remote.sh
sh scripts/test.sh
```

构建产物在 `$XDG_CACHE_HOME/oheco-broker/`，临时工作在 `$TMPDIR`。C SDK 的独立源码入口是 `sh sdk/c/build.sh`。独立服务端只需要 Go/cgo、bundled SQLite 和系统 C 工具链，见[服务端构建](docs/SERVER-BUILD.md)。

## 文档与边界

- [构建、账号、映射与 SDK](docs/LOCAL-DEVELOPMENT.md)
- [原生依赖、来源与离线构建](docs/NATIVE-DEPENDENCIES.md)
- [C 管理 API 的安全与所有权](docs/C-API-DEPENDENCIES.md)
- [REST 管理契约](docs/CONTROL-API.md)、[peer 协议](docs/PEER-PROTOCOL.md)、[WS/WSS 信令](docs/WS-SIGNALING.md)
- [通用生产部署](docs/PRODUCTION-DEPLOYMENT.md)、[验收索引](docs/LOCAL-VALIDATION.md)
- [0.4.0 发布说明](docs/releases/v0.4.0.md)；历史说明：[0.3.0](docs/releases/v0.3.0.md)、[0.2.0](docs/releases/v0.2.0.md)、[0.1.0](docs/releases/v0.1.0.md)

peer 必须双向密码认证；能访问本地映射端口的程序可以使用其固定目标，默认监听 `127.0.0.1`。broker 目标 allowlist 默认拒绝全部。当前 TURN 为 UDP/IPv4，UDP 数据报为尽力交付；TCP 恢复需要双方 SDK 进程和原目标 socket 在宽限内继续存活，无法撤销应用自身的超时；没有 TUN 或所有 NAT 可连通的保证。原本地命令服务允许连接者以服务用户身份执行命令，不能暴露到公网。

项目采用 MIT；依赖保留各自许可证。libjuice 的 relay 策略修改及 MPL-2.0 源码义务见依赖记录。`BUILDINFO.txt` 和 `SHA256SUMS` 标识发行源码与产物，SDK 由使用者为目标平台原生构建。
