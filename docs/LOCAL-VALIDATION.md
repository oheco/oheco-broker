# 0.3.0 验收索引

本次 0.3.0 清理后的 HarmonyOS arm64 原生离线 SDK 构建、完整 Go 测试与 vet、新控制面/C/Go/WSS/真实 direct 与 TURN TCP/UDP 验收，以及原 shell/C/.NET 生命周期与真实 .NET 构建回归均已通过。完整固定源码清单（五套 C 依赖与 Gorilla WebSocket）和归档策略检查通过。最终归档、独立解压 SDK 构建与正式索引安装结果见下文发行复核记录；本页同时区分历史公网验证范围。

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

2026-10-04 在 HarmonyOS arm64 上完成最终验证，原生 Go 为 `go1.27.1 ohos/arm64`。发行构建使用全新私有目录和离线输入；[v0.3.0 源码](https://github.com/oheco/oheco-broker/tree/v0.3.0)及归档 `BUILDINFO.txt` 对应 `aecc2fd8247aec361e5573412b7bfd6e75a83127`。

- 签名 CLI、独立服务端与随包 C++ runtime 通过实际 ELF 依赖闭合检查。
- 从独立 SDK 源码归档解压到含空格目录，完整离线构建成功；实际 Go native 链接及回环 HTTP 调用、C/.NET 源码消费通过。
- 14829 个源码输入、固定清单、44 份许可 notice、完整 payload 摘要通过；第三方 fixture 原样保留。
- 包迁移、双命令直接/PATH/版本及相对符号链接、无参数帮助、独立 SQLite/API 启动与 TERM、旧 shell managed/detached 生命周期通过。真实 GitHub 查询经代理通过。
- [首次目录提交](https://github.com/oheco/oheco-packages/commit/c090679f4ea7e22c0761471b471cec73a2b8a148)及[Pages 工作流](https://github.com/oheco/oheco-packages/actions/runs/37156777249)成功。该提交误把 SDK 登记为 DevEco `projects`，后续已撤销这项登记；SDK 应通过安装包源码目录或 Release 源码附件获取。
- `oo 0.10.0` 在隔离目录经正式索引完成 update、install、双命令/版本入口、switch 和 remove；卸载后命令链接和安装目录清除。独立 SDK 归档的全部 payload 摘要及源码布局验证通过。首次执行的 SDK 项目导出虽然运行成功，但不符合 DevEco 项目规范，不计入 SDK 交付方式。没有连接或修改生产实例。

[Release](https://github.com/oheco/oheco-broker/releases/tag/v0.3.0)已正式发布并设为 Latest，上传附件的远端大小和服务端 SHA-256 与本地一致：

| 附件 | 字节数 | SHA-256 |
|---|---:|---|
| `oheco-broker-0.3.0-ohos-arm64.tar.gz` | 110389864 | `57b17ebf1bcb768d1c480fca0207027719b9f54ae0830fcf2a016d779d2a973a` |
| `oheco-broker-0.3.0-sdk-source.tar.gz` | 84851015 | `6d9255dc4ba8f1af90fa69f8954abfac01956046b79a625c7234b6bebd11cf27` |

复核记录和验收脚本的后续提交只补充证据／测试隔离顺序，不改变已发布源码 SDK、运行包、标签或附件字节。
