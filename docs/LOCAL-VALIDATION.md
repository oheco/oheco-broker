# 0.3.0 验收索引

本次 0.3.0 清理后的 HarmonyOS arm64 原生离线 SDK 构建、完整 Go 测试与 vet、新控制面/C/Go/WSS/真实 direct 与 TURN TCP/UDP 验收，以及原 shell/C/.NET 生命周期与真实 .NET 构建回归均已通过。完整固定源码清单（五套 C 依赖与 Gorilla WebSocket）和归档策略检查通过。最终归档、独立解压 SDK 构建与正式索引安装结果在发布后复核记录中补充；本页同时区分历史公网验证范围。

## 本机原生验证

```sh
sh scripts/test-remote.sh
sh scripts/test.sh
sh scripts/build.sh
```

此前在 HarmonyOS arm64、原生 Go/cgo 与签名后可执行文件上完成过：

- Go/SQLite 租户、审批、分页、授权撤销、持久化和真实 Pion STUN/TURN allocation／转发计数。
- C 管理 API 的 TLS trust／hostname、超时、注入／预算、并发、注册回执丢失恢复和 SDK keylog-secret 抑制。
- PAKE／MAC／pin／TLS exporter／角色绑定、拒绝非零 NoCrypto、目标 ACL，以及真实 direct 和 FORCE TCP/UDP 映射。
- WS/WSS 帧、ACK／replay／idempotency、短租约／断线／重连／SQLite 重启；持续信令不回退 REST 轮询。
- 原 shell/C/.NET 回归、重复／并发启动、崩溃恢复、detached 生命周期和真实 .NET 离线 build／执行。
- 共享 TLS provider 的静态证书热加载与 ACME fixture，换证时已建立 WSS 连接继续工作。

普通套件与针对性 race 曾通过；不声称完整 bcrypt-inclusive `go test -race ./...` 已完成，也不把局部 instrumentation 结果扩大成全量覆盖。依赖来源见[固定输入](NATIVE-DEPENDENCIES.md)。

## 历史公网范围

此前完成过物理 HarmonyOS 设备与独立原生 Linux peer 的受信 HTTPS/WSS、direct／TURN 转发及实际 relay 计数验收；其他单次验收仅覆盖 FORCE＋TCP。这些属于不同历史快照，不能合并为同一最终产物的覆盖率或量化性能。

UDP 为尽力交付；历史并发大数据报试验出现过丢包，安静条件的通过不构成可靠交付或所有 NAT／IPv6 可连通保证。历史实例地址、凭据路径、证书信息及原始机器日志不作为发行内容。

显式授权的公网复测入口如下；全部变量由操作者指定，SSH 使用非 root 账号，远端路径必须绝对，`EVIDENCE_FILE` 为新的结果文件。此命令会连接测试实例并创建／清理测试资源，不属于本机离线回归。

```sh
python3 tests/production_acceptance.py \
  --api "$API" --turn-address "$TURN_ADDRESS" \
  --ssh-target "$SSH_TARGET" --ssh-port "$SSH_PORT" \
  --remote-root "$REMOTE_ROOT" --remote-peer "$REMOTE_PEER" \
  --ca-file "$CA_FILE" --remote-ca-file "$REMOTE_CA_FILE" \
  --binary "$BROKER_BIN" --admin-token-file "$ADMIN_TOKEN_FILE" \
  --output "$EVIDENCE_FILE"
```

## 最终发行复核

在实际提交与全新构建输入上完成签名 CLI／独立服务端、源码 SDK 离线构建、迁移路径、包内 C++ runtime 和实际归档烟测；记录工具链、source commit、产物 SHA-256 与结果。`BUILDINFO.txt` 和随发行提供的 `SHA256SUMS` 对应最终产物。此处不提前声明新归档或正式索引安装已验收。
