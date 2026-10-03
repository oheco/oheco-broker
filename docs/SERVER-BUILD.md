# 独立管理／STUN／TURN 服务端构建

`oheco-broker-server` 0.3.0 提供 SQLite 账号、broker、WS/WSS 信令、用量和 Pion UDP STUN/TURN。它共用 `internal/control` 与 `internal/servertls`，不链接 C peer SDK、xquic、BoringSSL 或 curl；peer 密码认证由端点完成。原生 Go/cgo SQLite 仍需要系统 C 运行库。

## 离线原生构建

完整 checkout 已包含 `vendor/` 与 SQLite C 源码。预先安装 Go 1.25+、目标平台 C 编译器和系统开发 headers；固定工具链版本用于发行记录。Linux 示例：

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=1 CC=gcc
mkdir -p build
go build -mod=vendor -trimpath -o build/oheco-broker-server ./cmd/oheco-broker-server
./build/oheco-broker-server --version
go test -mod=vendor -count=1 -timeout=180s \
  ./cmd/oheco-broker-server ./internal/servertls ./internal/control
go vet -mod=vendor ./cmd/oheco-broker-server ./internal/servertls ./internal/control
```

在 HarmonyOS 使用原生 clang，不设置 Linux GCC；测试执行通过 `-exec "sh $PWD/scripts/go-test-exec.sh"` 签名。最终 ELF 先签名再执行，构建缓存与产物置于权限正常的 `$XDG_CACHE_HOME`，临时工作置于 `$TMPDIR`。`CGO_ENABLED=0` 不受支持。此入口不需要构建 C peer 依赖，完整 CLI 的 `server serve` 则包含 CLI 本身的 native SDK 链接。

发行包中的 `bin/oheco-broker-server` 是 HarmonyOS arm64 签名 ELF；部署到 Linux 时从完整 checkout 在目标 Linux 平台构建。

## 配置与证书

数据库父目录需由服务用户持有、实际 0700；SQLite 0600。使用显式绝对 `--db` 路径，不将状态放源码目录。管理员 token 使用私有普通文件并经 `--admin-token-file` 读取，或设置 `OHECO_BROKER_ADMIN_TOKEN`；文件优先。token 长度 16–4096 字节，使用高熵随机值。

远程 API 必须使用 TLS，可选择：

- 外部签发的 `--tls-cert`／`--tls-key`：文件为非 symlink 普通文件，私钥归服务用户且 0600 或 0400。服务每 30 秒检测匹配、有效、稳定的文件快照，原子更新后续握手的证书；**静态证书更新无需重启**，已有 WSS 连接继续。可用 `--tls-reload-interval` 设置检测间隔；无效替换保留 last-good pair。
- 原生 ACME：`--acme-domain example.org --acme-cache /private/path/acme --acme-accept-tos`，使用 TCP 443 TLS-ALPN-01 获取并自动续期。静态文件和 ACME 模式互斥；部署者需准备正确 DNS、端口和私有缓存权限。

首次启动的注册策略默认 `approval`，relay 默认禁用；已有数据库保存的策略不由启动参数覆盖。批准账号与启用 relay 是两个管理员操作。通用 TLS、端口、状态备份和更新流程见[部署说明](PRODUCTION-DEPLOYMENT.md)。

## 本机 fixture

以下仅用于隔离本机开发；HTTP 与 loopback TURN 不能作为公网配置：

```sh
oheco-broker-server \
  --listen 127.0.0.1:18080 \
  --db "$XDG_CONFIG_HOME/oheco-broker-test/control.sqlite" \
  --admin-token-file /private/path/test-admin.token \
  --registration open \
  --turn-listen 127.0.0.1:3478 --turn-public-ip 127.0.0.1 \
  --turn-allow-loopback
```

启动输出 `server_ready` JSON；配置端口 0 可由系统分配。真实公网配置需显式 TLS、实际对外 IPv4 与准入策略。REST、信令和流量计数语义见[管理契约](CONTROL-API.md)，验证入口见[验收索引](LOCAL-VALIDATION.md)。
