# oheco-broker

临时、本机开发用途的命令执行代理：让无法直接启动外部命令的应用，通过回环 TCP 请求终端环境中的 Go 服务执行命令。C 和 .NET 客户端均以源码提供，不要求部署 broker 客户端 `.a` / `.so`，没有第三方依赖、JSON 或配置文件。

**安全边界：没有鉴权，也没有加密。任何能连接该回环端口的本机进程，都能以 broker 用户的权限执行任意命令。共享 endpoint 也不能认证服务身份。仅在可信开发设备上主动启动，使用完关闭；不要以 root 运行，不要用于公共、多租户或无人值守环境。随机端口不是安全措施。**

## 安装

通过 [oheco 软件目录](https://oheco.org/) 安装：

```sh
oo update
oo install oheco-broker
oheco-broker --version
```

也可从 [GitHub Releases](https://github.com/oheco/oheco-broker/releases) 下载 `ohos-arm64` 发行包，并使用随附 `SHA256SUMS` 校验。包内 `bin/oheco-broker` 已签名，运行只依赖系统 `libc.so`，不需要安装 Go 或 .NET；所执行的工具由使用者另行安装。

发行包同时包含完整源码及两套 SDK。使用 `oo` 默认安装目录时，源码 SDK 位于：

```text
~/.oheco/packages/oheco-broker/0.1.0/sdk/c/
~/.oheco/packages/oheco-broker/0.1.0/sdk/dotnet/
```

自定义 `OHECO_ROOT` 时替换上述 `~/.oheco`。C 项目编译 `.c` 并包含 `.h`；C# 项目用 `ProjectReference` 引用 SDK 项目，或直接编译 `BrokerProcess.cs`。无需独立原生 SDK 库。

安装不会启动服务，不修改自启动配置；`oheco-broker@0.1.0` 可使用指定版本入口。

## 使用

在具备工具执行能力的终端中运行：

```sh
oheco-broker
```

服务前台运行，仅监听 `127.0.0.1` 的系统分配端口，并原子写入：

```text
$HOME/.oheco/broker/endpoint
```

文件仅一行，例如：

```text
127.0.0.1:35205
```

按 Ctrl+C 或发送 SIGTERM 关闭服务。正常退出会清理自己发布的 endpoint 和受管理任务。崩溃可能留下 endpoint；SDK 会根据实际连接结果判断服务不可用。`oheco-broker --version` 输出版本。

服务使用 `$XDG_CACHE_HOME/oheco-broker/service.lock` 的文件锁避免同一终端环境内重复启动；未设置 XDG_CACHE_HOME 时使用 TMPDIR。它们应指向支持 flock 的私有真实文件系统，不依赖 HOME 的权限位。锁文件会保留，文件存在不代表锁被占用。不同终端应用的私有目录不同，不提供跨终端应用的全局单例保证。

## SDK 与统一错误

- [C SDK](sdk/c/README.md)：直接把 C 源码加入宿主构建，可使用 CMake OBJECT target。
- [.NET SDK](sdk/dotnet/README.md)：纯 C#，ProjectReference 或直接包含源码；无需 P/Invoke。
- [协议规范](protocol/PROTOCOL.md)：一条 TCP 连接执行一个命令，固定帧头与长度前缀。

SDK 默认读取 `$HOME/.oheco/broker/endpoint`，也可显式传入路径。鸿蒙应用自己的 HOME 不一定是终端 HOME，集成方应传入实际共享发现路径。

**endpoint 不存在、无法读取、为空、格式无效，以及端口无法连接或连接超时，都统一为 `OHECO_BROKER_ERR_UNAVAILABLE` / `BrokerErrorCode.Unavailable`。** UI 可以直接提示“请先在终端运行 oheco-broker”。错误仍保留阶段、系统错误等诊断信息。

握手错误使用 PROTOCOL；无法启动目标程序使用 SPAWN_FAILED；已经发送启动请求后断线使用 CONNECTION_LOST（结果可能未知）。命令自身返回非零退出码不是 SDK 错误。SDK 不自动启动 broker、不重试执行请求，也不会把等待超时自动转为任务取消。

## 执行模型

- 程序与参数数组直接传给进程 API，不隐式使用 shell。
- 继承服务的环境，支持本次调用的变量覆盖；使用有效 PATH 和请求的工作目录查找程序。
- stdin/stdout/stderr 按原始字节传输；EXIT 在输出读完之后发送。
- 并发执行使用多条连接，最多接受 32 条连接；不做任务 ID、数据库、恢复或脱离运行。
- 客户端必须持续消费重定向输出。缓冲有限，超限或长时间不读会明确失败，不静默丢弃数据。
- 取消、断线或服务关闭时，向任务进程组发送 SIGTERM，最多等待 2 秒后 SIGKILL。
- 命令完成后，清理仍在同一进程组的辅助进程。不保证清理主动脱离进程组的后代；服务被 SIGKILL 后也没有绝对清理保证。
- 网络启动阶段有 3 秒超时，但 Go 无法强制中断阻塞在内核里的文件系统/exec 调用；迟到的进程会被清理，系统调用长期阻塞仍可能延迟服务退出。不要把失效网络挂载用作工具路径或工作目录。
- 关闭/Dispose 正在运行的 SDK 句柄会断开连接，因此服务会取消命令。这个极简版本不支持“释放句柄但保留后台任务”。

构建工具尽量关闭长期服务器/节点复用，例如按用途传递 `--disable-build-servers`、`-nr:false` 等；broker 不是持久构建服务器的宿主。

## 文件与集成边界

服务与客户端不共享应用身份或私有目录。项目、SDK、构建引用、日志输出路径必须是服务可访问的路径。本项目不做文件传输或路径映射。

Godot 是潜在调用方而不是服务依赖。本仓库不修改 Godot：原生编辑器需要显式接入 C SDK，GodotTools 需要显式接入 .NET SDK。SDK 不自动拦截 `exec` / `System.Diagnostics.Process.Start`。集成应限制在编辑器和编辑器插件，游戏运行时和导出模板不应引入依赖。

未来系统支持直接执行命令时，只需替换宿主的命令执行适配层，不让构建 UI 依赖 broker 专有概念。

## 构建与验证

要求：Go 1.25+（目标平台可用的移植版）、C11 clang/兼容编译器、.NET 10 SDK；鸿蒙二进制签名使用 PATH 中的 `binary-sign-tool`。没有外部 Go module 或 NuGet 包，无需联网构建。

```sh
sh scripts/build.sh
sh scripts/test.sh
```

`build.sh` 生成 `build/oheco-broker`，只构建服务，不产生独立客户端库。测试脚本使用 TMPDIR 中的隔离 HOME、缓存、编译产物和临时服务，退出时清理，不覆盖用户的发现文件，不保留运行中的测试服务。

当前鸿蒙原生验收、工具链版本、真实 `dotnet build` 结果及限制见 [VALIDATION.md](VALIDATION.md)。

仅实现 Unix/POSIX 服务端，首要验收目标为 HarmonyOS/OpenHarmony arm64。其他平台不应视为已验证。鸿蒙中的应用到回环 TCP 的访问仍依赖应用权限和系统版本；终端侧 SDK 验证不能替代真实应用的跨沙箱集成验证。

## 发行构建

在干净且已提交的鸿蒙原生 checkout 中执行：

```sh
sh scripts/test.sh
python3 scripts/package.py
python3 tests/release_smoke.py dist/oheco-broker-0.1.0-ohos-arm64.tar.gz
```

打包脚本从当前 Git 提交导出源码，在私有临时目录编译、签名并生成 `dist/` 下的压缩包、校验和及构建日志，不自动创建标签或发布。归档包含 `BUILDINFO.txt`（源码提交、工具链、二进制摘要）及 Go 运行时代码许可证。已存在的同名归档不会被覆盖。发布烟测会迁移到含空格和 Unicode 的目录，验证服务执行、SDK 文件、版本入口和真实 GitHub 上游访问；外网访问固定使用当前开发环境的 SOCKS5 代理。

完成上述验证后才能创建对应标签/Release，并更新 `oheco-packages`；正式发布的产物保持不可变。初版说明见 [v0.1.0](docs/releases/v0.1.0.md)。

## 不包含

TLS/配对授权、PTY、远程主机、文件同步、断线恢复、后台任务、完整 System.Diagnostics.Process 兼容性、系统服务安装和自动拉起。

## 许可证

MIT。版本、协议和 SDK 都在同一个仓库维护。
