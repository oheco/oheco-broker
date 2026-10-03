# 固定依赖与源码 SDK 离线构建

C SDK 以完整源码发行。原生依赖位于 `sdk/c/tpr/`，构建、配置与原生探针位于 `sdk/c/build/`；它们属于 SDK 输入，使用者在目标平台构建，不随包提供预编译 SDK 库。

## 固定源码与许可证

| 依赖 | 固定版本／提交 | 许可证 | 本地源码修改 |
|---|---|---|---|
| xquic | 1.9.7，`39437fa331cd0faabea76142a1218330fb6885fa` | Apache-2.0 | 无 |
| BoringSSL | `5e1bfb45c353b2bb36bdf26b006ea8f5566c82d5` | Apache-2.0 及原 notices | 无 |
| libjuice | 1.7.4，`b89c792e3612faf2f12cf35bcc56857313a06be3` | MPL-2.0 及原 notices | config／agent 两文件 relay 策略 |
| cJSON | 1.7.19，`c859b25da02955fef659d658b8f324b5cde87be3` | MIT | 无 |
| curl | 8.22.0 | curl/MIT-like | 无 |

来源、归档 SHA-256、完整文件摘要与修改白名单以 [native manifest](../sdk/c/tpr/native-dependencies.json) 和 [manifests](../sdk/c/tpr/manifests/) 为准。保留完整原始许可证和版权声明；重新发行 libjuice 时同时提供受 MPL-2.0 覆盖的源码与[修改](../sdk/c/tpr/patches/libjuice-relay-only.patch)。

Go 版本与校验值在 [go.mod](../go.mod)、[go.sum](../go.sum)，源码在 `vendor/`，Gorilla WebSocket 来源记录在 [vendor manifest](../vendor-manifests/gorilla-websocket.json)。依赖包括 SQLite、Pion STUN/TURN、Cobra、Gorilla 和 Go x modules，使用各自保留的许可证。SQLite amalgamation 为 public domain。

## 离线构建

预先准备原生 clang/clang++、CMake、Ninja、Python 和系统 C/C++ headers/runtime。HarmonyOS 执行的构建探针先由 `binary-sign-tool` 签名；完整 Go CLI 还需原生 Go 1.25+。

```sh
# 可从完整 checkout 或安装包构建 C SDK：
sh sdk/c/build.sh
# 完整 checkout 的 Go/cgo 集成与客户端构建：
sh scripts/build.sh
```

构建器审计固定输入，不临时下载源码；输出放 `$XDG_CACHE_HOME`，临时内容放 `$TMPDIR` 并清理。xquic 的配置头在缓存中的源码副本生成，checked-in 上游树保持原样。curl 使用与 peer 引擎相同的 BoringSSL 静态归档，协议范围为 HTTP/HTTPS/WS/WSS。原生 compile/link 检查及签名后 runtime 探针选择平台能力，不复制其他平台的配置结果。

## 链接与适配边界

xquic、curl、libjuice、cJSON、BoringSSL 静态链接到 SDK 消费者。**C++ 运行时仍是运行依赖**：HarmonyOS 使用 libc++，Linux 的原生构建使用其配置的 C++ runtime；宿主必须提供匹配的运行库。发行 CLI 启动器配置随包的签名 `lib/runtime/libc++_shared.so`，不为任意第三方宿主配置环境。

BoringSSL 固定 rolling commit，不承诺稳定 ABI。不要混合未隔离的另一套 OpenSSL/BoringSSL 实例。SPAKE2 为 upstream Edwards25519/SHA-512 draft-02，需 SDK 的角色／会话绑定与双向确认，不声称 RFC 9382 wire 兼容。

SDK 使用公开 TLS peer transport parameters，在发送认证 proof 或业务数据之前拒绝非零 NoCrypto。cJSON 的共享解析锁位于 SDK；与宿主共享同一 cJSON 实例时还需协调宿主解析，不在多线程运行中修改 allocator hooks 或 locale。curl 私有 SSL context 不追加 SDK 流量秘密，但上游初始化可能创建空 `SSLKEYLOGFILE`，不承诺完全不触碰该文件。

libjuice 唯一保留的 relay 策略修改保证 `force` 在 candidate pair、send 和 receive 路径实际使用本地 relay。仅查询 selected pair 再发送会存在 nomination 竞态，因此保留原子策略及对应回归。SDK API 与协议见[C API](C-API-DEPENDENCIES.md)和[peer 协议](PEER-PROTOCOL.md)，验收范围见[索引](LOCAL-VALIDATION.md)。
