# Linux 原生 C SDK 离线构建

C peer SDK 与全部固定源码、许可证、探针和构建资源随 `sdk/c/` 提供。预先准备目标 Linux 平台的 C/C++ 编译器、CMake、Ninja、Python 和系统开发 headers，再从源码离线构建：

```sh
sh sdk/c/build.sh
```

完整 checkout 另保留 `sh scripts/deploy-client-build.sh` 作为本地离线 Linux 构建入口；它不上传源码、不连接远端、不启动生产服务。具体前缀／编译器／C++ runtime 参数以构建入口及 C SDK README 为准。

xquic、BoringSSL、cJSON、curl 保持固定上游源码；libjuice 仅保留已记录的 relay 策略修改。curl 使用与 xquic 相同的 BoringSSL，协议范围 HTTP/HTTPS/WS/WSS。构建 cache 与 xquic 生成配置头的源码副本不写入原始依赖树。Linux 消费者需提供其原生 C++ runtime，不能将 HarmonyOS libc++ 产物作为 Linux 构建输入。

完整仓库中的 `tests/public_peer.c` 是独立 C SDK 验收消费者，支持 API、CA 和私有 credential 文件参数。公网验收需显式提供独立测试实例与已有授权 profile，验证 direct、FORCE、TCP/UDP 和实际 relay 计数；源码构建成功本身不代表公网验收通过。保持原服务 TLS／host identity 验证、清理自身创建的 peer／broker／临时凭据。输入来源见[依赖说明](NATIVE-DEPENDENCIES.md)，历史范围与最终发行复核见[验收索引](LOCAL-VALIDATION.md)。
