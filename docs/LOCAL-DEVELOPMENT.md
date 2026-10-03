# 0.3.0 构建与使用

## 构建与 SDK

HarmonyOS CLI 的完整源码构建需要原生 Go 1.25+、clang/clang++、CMake、Ninja、Python 和 `binary-sign-tool`。预先准备工具链后，全部项目依赖由 Go `vendor/` 和 C `sdk/c/tpr/` 提供，构建不联网。

```sh
sh scripts/build.sh
"$XDG_CACHE_HOME/oheco-broker/bin/oheco-broker" --version
```

源码 SDK 随发行包提供，不包含预编译 SDK 库：

| SDK | 用途 | 构建方式 |
|---|---|---|
| [C 本地命令 SDK](../sdk/c/README.md) | 调用 `shell serve` 执行／独立启动本机程序 | 将 `oheco_broker.c` 编入宿主，或使用 CMake OBJECT target；无需第三方 C 库 |
| [C peer 与管理 SDK](../sdk/c/remote/ob_remote.h) | 认证 peer、TCP/UDP 映射及管理 API | `sh sdk/c/build.sh` 从完整固定依赖源码构建 |
| [Go SDK](../sdk/go/remote/client.go) | 同一 C 引擎的 cgo 包装 | 先构建 C SDK，再配置其 include/link 输入；Go 模块与 vendor 随包提供 |
| [.NET SDK](../sdk/dotnet/README.md) | 本地命令服务的 managed/detached 调用 | .NET 10 `ProjectReference` 或直接包含源码，无额外 NuGet 包 |

C peer SDK 的静态依赖共用同一套 BoringSSL；C++ 运行时仍是运行依赖。HarmonyOS 发行 CLI 的启动器加载随包 `lib/runtime/libc++_shared.so`。自行编译 SDK 的宿主需提供目标平台的 C/C++ 运行时，不能假定静态 C SDK 消除了 C++ 依赖，也不能未经验证混合另一套 OpenSSL/BoringSSL ABI。依赖清单和源码入口见[依赖说明](NATIVE-DEPENDENCIES.md)，独立服务端见[服务端构建](SERVER-BUILD.md)。

## 账号与管理服务

设置实际服务地址；远程管理与信令使用 HTTPS/WSS，客户端始终验证证书和主机名。

```sh
export OHECO_BROKER_API=https://example.org:8443
oheco-broker tenant register --email user@example.org
oheco-broker tenant account show
oheco-broker tenant capabilities
```

默认注册策略为 `approval`。管理员批准后账号才可使用；relay 权限需要另外启用。服务端首次启动参数仅初始化新数据库，后续策略存储在 SQLite 中，由管理员命令修改。

CLI 默认将账号配置保存到 `$XDG_CONFIG_HOME/oheco-broker/account.json`，实际目录权限 0700、文件 0600。HarmonyOS 不回退到 HOME/hmdfs；`--config` 可选独立私有路径。省略账号密码时生成 128 bit 随机值，编码为 32 个 hex 字符；账号密码与 peer 密码用途不同。

注册请求发出前先保存 `.pending` 凭据。回执丢失时保留该文件，不自动重发注册；用同一凭据登录确认：

```sh
oheco-broker --config "$XDG_CONFIG_HOME/oheco-broker/account.json.pending" tenant login
```

该命令保存到显式选择的配置路径，之后继续选用该路径或在私有目录迁移。注册、登录、账号修改和退出使用 profile 锁，避免并发覆盖。登录另一设备时使用同一租户的账号凭据。

## 创建映射

在 broker 端选择允许访问的目标，并从 stdin 输入独立强 peer 密码：

```sh
oheco-broker tenant serve --name desktop --password-stdin \
  --allow tcp@127.0.0.1:8080 \
  --allow udp@127.0.0.1:5353 < /private/path/peer-password
```

allowlist 默认拒绝全部，可按协议、地址／域名／CIDR和端口选择目标，也可用 `--allow-config` 读取规则。目标地址从 broker 所在设备看待。能触达映射监听端口的程序可使用固定目标；peer 间仍须双向密码认证。

连接端选择同一租户，输入相同 peer 密码：

```sh
oheco-broker tenant connect --name desktop --password-stdin \
  --protocol tcp --target 127.0.0.1:8080 --local 9090 \
  --relay auto < /private/path/peer-password
```

其他软件连接本地 `127.0.0.1:9090`。`--local 0` 分配随机端口并输出 `mapping_ready`；显式开放网卡时使用数值 `IP:port`。CLI 每次 connect 建立一个映射，C/Go SDK 可在一个 peer 上建多映射。

`auto` 允许直连或 relay，`never` 禁止 relay，`force` 必须有租户 relay 权限并实际走 TURN。当前 TURN 为 UDP/IPv4，无 TURN/TCP/TLS 回退。UDP 为尽力交付，TCP 断开后不透明续传。原服务的 TLS SNI、HTTP Host 或 SSH host-key 验证应保留，不能为映射关闭原服务身份验证。

## 管理与关闭

```sh
oheco-broker tenant broker list
oheco-broker tenant usage --broker BROKER_UUID
oheco-broker admin --token-file /private/path/admin.token tenant approve TENANT_UUID
oheco-broker admin --token-file /private/path/admin.token tenant relay enable TENANT_UUID
oheco-broker admin --token-file /private/path/admin.token registration set approval
oheco-broker admin --token-file /private/path/admin.token registration relay-default disable
```

账号改名／改密码及管理员禁用／重置会撤销旧凭据。正常停止的同名 broker 可恢复同一 UUID；在线 broker 不允许顶替。控制服务暂时失联时重试信令，达到授权租约先停止旧转发，不因网络 PING/PONG 延长授权。

C API 不持久化凭据。先关闭映射、peer/server，再销毁 API client；C client 必须比引用它的对象存活更久。SDK 注册未知结果、响应所有权和 bearer 范围见[C API](C-API-DEPENDENCIES.md)。

## 本地命令服务与验证

```sh
oheco-broker shell serve
```

该服务发布 `$HOME/.oheco/broker/endpoint`，无鉴权，连接者可以服务用户身份执行命令，只用于可信本机开发。重复启动完成握手后正常退出；升级不会替换已运行进程。managed 任务在断连／关闭时取消，detached 任务的成功回执丢失不得自动重试。详见[本地协议](../protocol/PROTOCOL.md)。

完整 checkout 的回归入口：

```sh
sh scripts/test-remote.sh
sh scripts/test.sh
```

测试使用隔离数据库、配置、监听器与 `$TMPDIR`，清理自己的资源。范围与最终发行证据见[验收索引](LOCAL-VALIDATION.md)。
