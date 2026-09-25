# oheco-broker

临时、本机开发用途的命令执行代理：由终端环境中的 Go 服务代为执行工具命令。提供无第三方依赖的 C 和纯 .NET 10 源码 SDK，没有 JSON 协议或配置文件。

**没有鉴权或加密。任何能连接端口的本机进程都能以 broker 用户的权限执行命令；共享 endpoint 也不能认证服务身份。仅在可信开发设备上主动启动，不应以 root 运行或无人值守。随机端口不是安全措施。**

## 安装与运行

```sh
oo update
oo install oheco-broker
oheco-broker --version
oheco-broker
```

[GitHub Releases](https://github.com/oheco/oheco-broker/releases) 也提供发行包及 `SHA256SUMS`。平台为 `ohos-arm64`；已签名的 `bin/oheco-broker` 运行只依赖系统 `libc.so`，不需要 Go/.NET。所执行的工具由使用者另行安装。

安装不自动启动服务，也不安装系统服务或修改自启动。`oheco-broker@0.2.0` 是指定版本入口。服务前台运行，Ctrl+C/SIGTERM 正常退出。

服务只监听系统分配的回环 TCP 端口，原子写入 `$HOME/.oheco/broker/endpoint`，文件只包含一行：

```text
127.0.0.1:35205
```

### 重复启动

`0.2.0` 检查现有 endpoint 并完成 broker 握手；确认已有可用服务时输出 `oheco-broker is already running.`，以 **0** 退出，不覆盖/删除原 endpoint，也不影响已有任务。

单实例互斥使用由规范 HOME 路径派生的固定抽象 Unix socket 名称。它**只用作内核互斥锁，不承载客户端通信**，不产生 socket 文件，不依赖 HOME 的 chmod，也不受 XDG_CACHE_HOME 不同的影响。并发启动只有一个实例获得锁；崩溃由内核释放锁。旧/失效的 endpoint 可以恢复，端口开放但握手不是 broker 不会被误认。

互斥范围是同一规范 HOME、同一网络命名空间内的 `0.2.0` 实例。兼容保留私有缓存 `service.lock`，并能发现已经运行的 `0.1.0`；但旧版程序本身不认识新锁，不能保证后来手动启动的旧版在另一缓存目录里也遵守新规则。不要混用旧版启动器。不同应用的安全域/网络命名空间仍受系统策略约束，原生终端测试不替代真实跨应用验收。

升级时若仍有 `0.1.0` 服务运行，请先正常停止旧服务，再启动新版本；重复启动不会替换运行中的旧进程。

若锁被占用但 3 秒内没有可握手的 endpoint，或遇到权限/监听等真实错误，非零退出，不强行启动第二个实例。

## 源码 SDK

默认安装路径（自定义 OHECO_ROOT 时替换 `~/.oheco`）：

```text
~/.oheco/packages/oheco-broker/0.2.0/sdk/c/
~/.oheco/packages/oheco-broker/0.2.0/sdk/dotnet/
```

- [C SDK](sdk/c/README.md)：编译 `oheco_broker.c`，包含 `oheco_broker.h`；可使用 CMake OBJECT target。不需要独立 SDK `.a`/`.so`。
- [.NET SDK](sdk/dotnet/README.md)：`ProjectReference` 引用 `Oheco.Broker.csproj`，或直接编译 `BrokerProcess.cs`。无需 P/Invoke/额外 NuGet 包。
- [协议](protocol/PROTOCOL.md)：固定帧头和长度前缀，一条连接一个执行/启动请求。

SDK 默认读取 `$HOME/.oheco/broker/endpoint`，可显式传入发现路径。应用自己的 HOME 可能不同，需要传入实际共享路径。**发现文件不存在、读取或格式错误、端口连接失败/超时统一为 UNAVAILABLE**；C 为 `OHECO_BROKER_ERR_UNAVAILABLE`，.NET 为 `BrokerErrorCode.Unavailable`。握手不兼容是 PROTOCOL，不与服务不存在混淆。SDK 不自动启动 broker，也不自动重发命令。

## 两种执行方式

### 受管理执行（原有接口，v1）

支持程序/参数数组、cwd、环境变量覆盖、stdin/stdout/stderr、退出码、等待和取消。直接执行程序，不隐式使用 shell。环境继承服务，路径必须是服务可访问的位置。

连接断开、SDK 释放/Dispose、显式取消或 broker 正常退出会取消任务：SIGTERM 后最多等待 2 秒，再强制清理进程组。外层命令退出后会清理同组辅助进程。不保证清理主动脱离进程组的后代。

输出有界，必须持续消费；等待超时只结束等待，不自动取消任务。最多 32 条同时连接。原 v1 SDK 可使用新服务，新 SDK 的受管理调用仍可使用 `0.1.0`。

### 独立后台启动（新接口，v2）

```c
uint32_t pid;
oheco_broker_options options = { .executable = "/path/to/server" };
oheco_broker_diagnostic error;
int rc = oheco_broker_spawn_detached(NULL, &options,
    "/path/to/server.out.log", "/path/to/server.err.log", &pid, &error);
```

```csharp
var info = new Oheco.Broker.BrokerProcessStartInfo { FileName = "/path/to/server" };
int pid = await Oheco.Broker.BrokerProcess.SpawnDetachedAsync(
    info, "/path/to/server.out.log", "/path/to/server.err.log");
```

- 成功启动到新的 POSIX 会话；连接关闭或 broker 正常退出不会终止它。
- stdin 是 `/dev/null`。输出文件为空时丢弃到 `/dev/null`；非空时要求普通文件，追加写入，不截断；相对路径按服务处理后的 cwd 解析，目录需预先存在。可以让 stdout/stderr 指向同一文件。
- 不使用连接对应的输出管道，不能重定向到 SDK 流；.NET 的三个 RedirectStandard* 必须为 false，C 的 stdin_enabled 必须为 0。
- 只返回诊断 PID。它不是调用方的本地子进程，不支持 `waitpid`，没有 broker 的 Wait/Cancel/重新接管接口。启动成功不等于服务已就绪，停止服务由其自身接口或用户终端负责。
- broker 存活期间异步回收直接子进程，最多跟踪 64 个存活直接子进程；这不是对子孙进程总数的隔离。
- 成功创建进程就是提交点，即使启动回执丢失也不撤销。因此发送启动请求后连接丢失/超时属于结果可能未知，**不得自动重试**。
- 对旧 `0.1.0` 服务，v2 握手明确报 PROTOCOL，不降级成会随连接取消的受管理任务。

**关闭/强停终端应用或系统回收整个应用时的生存性不保证；仅调用 broker 的正常退出不等于系统强停整个应用。** 所有模式仍受系统权限约束，阻塞的内核文件系统/exec 调用也不能由 Go context 强制中断。

## 发行包布局

从 `0.2.0` 开始只包含：已签名服务、两套源码 SDK、必要说明/协议、许可证及 BUILDINFO。**不再把 Go 服务源码、测试、示例和构建脚本装进 package。** 完整源码留在 GitHub；已发布的 `0.1.0` 保持不变。

## 源码构建、测试与发布

以下命令在完整 Git checkout 中运行，不是在精简安装包中运行。要求本机 OHOS Go 1.25+、clang/C11、.NET 10、Python 3.12+ 和 PATH 中的 `binary-sign-tool`；没有外部源码依赖需要联网下载。

```sh
sh scripts/build.sh
sh scripts/test.sh
# 提交全部源码并确保工作区干净后：
python3 scripts/package.py
python3 tests/release_smoke.py dist/oheco-broker-0.2.0-ohos-arm64.tar.gz
```

测试使用 TMPDIR 私有目录、隔离 HOME/缓存和测试服务，清理自己创建的后台程序。`tests/lifecycle.py` 验证重复/并发启动、崩溃恢复、独立程序在 broker 退出后存活；可选参数还可验收真实旧版客户端/服务。发行烟测验证精简白名单、来源和摘要、迁移路径、系统库依赖和真实 GitHub 查询（当前开发环境代理 `127.0.0.1:10808`）。

打包脚本只在私有临时目录保留完整源码快照以编译，最终归档使用显式白名单。产物不覆盖已有同名归档，包含源码提交、工具链和签名二进制摘要。通过本机验收才创建标签/Release，再更新 packages 和正式索引验收。

发布说明：[0.2.0](docs/releases/v0.2.0.md)；历史 [0.1.0](docs/releases/v0.1.0.md) 及 [实现初期验证记录](VALIDATION.md)。

## 集成边界与许可证

不自动拦截 `exec` / `System.Diagnostics.Process.Start`。不做文件同步、PTY、远程主机、后台服务数据库/重连、完整 Process 兼容或系统服务安装。本版本不修改 Godot；接入应限定编辑器及插件，游戏和导出模板不引入依赖。

MIT。发行包同时保留 Go 运行时代码的相关许可证。
