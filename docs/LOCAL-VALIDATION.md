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

SDK 分发更正由[目录提交](https://github.com/oheco/oheco-packages/commit/2e794b1581c565d9eda4f1b93db81b6d300a600d)及[Pages 工作流](https://github.com/oheco/oheco-packages/actions/runs/37171686574)部署。正式索引已撤销 SDK 的 `projects`，回到 schema v2；通过更正后的正式索引重新完成隔离安装、双命令版本、安装目录内 C/Go/.NET 源码与离线输入、卸载验证。SDK 源码通过安装目录或 Release 附件获取。

独立 SDK 附件的原始 README 中误写了 DevEco 导出用法，Release 说明及当前源码文档已明确更正。后续提交修正文档、登记和验收记录，不改变已发布源码 SDK、运行包、标签或附件字节。

## Linux Docker 0.3.0

2026-10-04 的[双架构原生工作流](https://github.com/oheco/oheco-broker/actions/runs/37175665476)全部通过：AMD64 使用 `ubuntu-24.04`，ARM64 使用 `ubuntu-24.04-arm`。应用源码为现有 `v0.3.0` 的 `aecc2fd8247aec361e5573412b7bfd6e75a83127`，Docker 构建配方为 `abae42826554fa978e9e612421975452277eef0e`；基础镜像固定 Go 1.27.1 Bookworm、Debian Bookworm slim 的双架构索引摘要。Go vendor 和 C SDK 源码依赖离线构建，系统工具和运行库由 Bookworm APT 提供。

- 两个架构分别完成完整 Go 测试、vet、原生 C/API/WS/WSS/direct/TURN 与 CLI、peer 生命周期验收，随后测试实际精简运行镜像。
- 实际容器验证两个程序版本、动态依赖、CA 信任、UID 10001、只读根、私有 SQLite 和 token 权限、管理认证、默认审批与独立 relay 授权；CLI 执行 direct 与强制 TURN 的 TCP/UDP 数据传输和实际 relay 计数。
- SQLite、CLI 配置和缓存在重建后保留，服务端作为 PID 1 接收 TERM 后在 15 秒内正常退出。静态证书 HTTPS TCP 3478 与 STUN/TURN UDP 3478 同时通过。
- 非 root、零 capabilities、no-new-privileges 的低端口负例在容器阈值 1024 时明确拒绝绑定 443；桥接网络阈值 0 的正例实际发布宿主 TCP 443 到容器 TCP 443并通过受信 HTTPS。只修改容器网络命名空间，不修改宿主 sysctl。
- ACME provider 的本地签发／续期 fixture 随 Go 测试通过。容器验收使用本地证书验证端口和持久化，不声称在用户域名或生产服务器上完成公有 CA 签发。

两个已验收的镜像由原生 runner 保存，发布阶段直接载入并推送，不重新构建。`ghcr.io/oheco/oheco-broker:0.3.0` 与 `latest` 使用同一索引 `sha256:5e3890c7d388161dd2db01d686032f2df5b19defe45d676294e8ed0884906f2e`：

| 平台 | 镜像摘要 |
|---|---|
| linux/amd64 | `sha256:6b8f46213fcde8087bafda19e51343d275980f20b5352b4a0b4e517d5ddebaf1` |
| linux/arm64 | `sha256:b51ddb0d6f2b1d5e4813a4d36f9d71553de24ae55cb8106d4e85f7937fdbbedc` |

初次推送后的 GHCR 包为私有可见性，匿名 registry token 请求实测 HTTP 401。包管理员已在网页中切换 Public，随后不使用账号凭据获取 registry token、`0.3.0`／`latest` 索引、两架构 manifest 与配置 blob，逐项核对 SHA-256、Linux 架构、应用版本、源码 revision 和 UID；`0.3.0`／`latest` 索引与上述发布摘要完全相同。

[匿名 Docker 拉取复核](https://github.com/oheco/oheco-broker/actions/runs/37177139985)在 AMD64 和 ARM64 原生 Linux runner 上分别通过：空 `DOCKER_CONFIG`、无登录凭据，实际 `docker pull` 后运行独立服务端和完整 CLI 的版本命令，核对两架构、应用源码标签和 `RepoDigests`，确认所拉取的索引仍为 `sha256:5e3890c7d388161dd2db01d686032f2df5b19defe45d676294e8ed0884906f2e`；验证步骤没有重新构建或覆盖镜像。部署方式见[Docker 部署](DOCKER.md)。

[目录提交](https://github.com/oheco/oheco-packages/commit/64ee85b69785b235757a2fedb1a15dfc53ff549d)补充 Docker 和两种 TLS 部署入口，[Pages 工作流](https://github.com/oheco/oheco-packages/actions/runs/37176912411)成功，正式网站与 v5 索引中的说明已复核。此次只更新 notes，所有原有运行包 URL、大小、摘要、命令映射、schema 和 latest 保持一致。
