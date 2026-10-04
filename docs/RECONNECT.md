# 远程连接恢复

C SDK 的重连管理器保留逻辑 peer、映射句柄和本地监听端口，为每次网络尝试重新建立控制会话、ICE/TURN、QUIC 和认证。Go SDK 调用同一个 C 引擎；CLI 不另建重连状态机。

## 默认策略与状态

零初始化重连策略使用以下默认值：

| 项目 | 默认值 |
| --- | --- |
| 自动恢复尝试 | 最多 8 次 |
| 指数退避 | 首次恢复立即尝试，随后从 1 秒递增，上限 15 秒，另附加 0–25% 抖动 |
| 一轮自动恢复预算 | 60 秒，耗尽后暂停 |
| TCP 恢复保留期限 | 120 秒 |
| 稳定连接后重置失败预算 | 30 秒 |
| v2 QUIC 空闲检测 | 15 秒，并启用传输保活 |

状态为 `connecting`、`connected`、`reconnecting`、`retry_wait`、`paused`、`failed`、`closed`。`paused` 保留句柄和监听端口，可手动唤醒；保留期限仍继续计时。`Status` 用于检查终止错误，详细恢复状态通过状态快照获取。`connected` 表示新的认证传输已建立，旧 TCP 流随后完成各自的恢复握手。

`Reconnect` 成功只表示请求已接受，完成情况需继续观察状态。重复请求会合并；健康连接上的请求不会重建连接。手动请求可以开始新一轮尝试，但不能延长尚未恢复 TCP 流的原有保留期限。关闭 peer、server 或映射是最终关闭，相应句柄不能复活。

## C SDK

使用 `ob_remote_connect_async` 可在首次网络尝试完成前取得句柄，因此首次网络故障也可在同一个句柄上手动恢复。既有 `ob_remote_connect` 继续同步等待首次连接成功。下面的片段假定已创建 `api`，并持有有效的 `broker_id` 和 `password`：

```c
ob_remote_peer *peer = NULL;
ob_remote_connect_options options = {0};
ob_remote_error error = {0};
int rc = ob_remote_connect_async(api, broker_id, password,
                                 &options, &peer, &error);
if (rc == 0) {
    ob_remote_reconnect_policy policy;
    ob_remote_reconnect_policy_init(&policy);
    policy.disabled = 1; /* 禁用自动尝试，仍允许手动 Reconnect。 */
    ob_remote_peer_set_reconnect_policy(peer, &policy, &error);

    ob_remote_connection_info info;
    ob_remote_peer_get_state(peer, &info);
    ob_remote_peer_reconnect(peer, &error); /* 非阻塞，不代表已连接。 */
    /* 应用继续持有 peer；在拥有该句柄的线程中最终关闭它。 */
}
```

对应的 server 接口是 `ob_remote_server_set_reconnect_policy`、`ob_remote_server_get_state` 和 `ob_remote_server_reconnect`。server 状态反映控制连接；各 peer 的传输与业务流有独立的恢复过程。

`ob_remote_peer_set_state_callback` 和 `ob_remote_server_set_state_callback` 的回调不持有 SDK 互斥锁，但在 SDK worker 中运行。**不要在回调内关闭或销毁该 peer、server 或客户端**；回调通知应用线程，由应用线程执行关闭。回调拿到的快照只在本次调用期间有效，需要保存时复制它。

## Go SDK

`ConnectAsync`、`Peer/Server.SetReconnectPolicy`、`Peer/Server.GetConnectionInfo` 和 `Peer/Server.Reconnect` 是 C API 的薄封装。零策略选择 C 的默认值，时间字段使用 `time.Duration`，非零值需是整毫秒。延迟和传输检测上限为 5 分钟，预算、保留期和稳定重置间隔上限为 1 小时；传输检测的非零下限为 1 秒。

```go
peer, err := client.ConnectAsync(brokerID, password, remote.ConnectOptions{})
if err != nil {
    return err
}
defer peer.Close()
if err := peer.SetReconnectPolicy(remote.ReconnectPolicy{
    Disabled: true,
    FlowGrace: 120 * time.Second,
}); err != nil {
    return err
}
mapping, err := peer.Map(remote.TCP, "127.0.0.1", 0, "127.0.0.1", 8080)
if err != nil {
    return err
}
defer mapping.Close()

info, err := peer.GetConnectionInfo()
if err == nil && info.State == remote.StatePaused {
    err = peer.Reconnect() // accepted，不是 connected。
}
```

应用可用带 context 的 ticker 轮询 `GetConnectionInfo`，观察 `State`、`Attempts`、`Generation`、`NextRetry` 和 `LastError`。Go SDK 不把 Go 回调指针传给 C worker。句柄互斥锁保护状态操作与关闭；关闭顺序仍为映射、peer/server、client，活跃 peer/server 会阻止 client 提前销毁。

## 前台 CLI 与手动唤醒

`tenant serve` 和 `tenant connect` 在重连、退避及暂停时继续运行，保留同一个 SDK 句柄。`tenant connect` 仍同步完成首次连接，然后输出原有 `mapping_ready`；`tenant serve` 保留原有 `broker_ready` 事件。首次同步启动失败仍返回错误，需要处理首次失败的嵌入式应用应使用异步 SDK 接口。

增加 `--state-events` 可在 stdout 输出 JSON 恢复事件，默认关闭，保持原有 ready JSON 消费方式：

```sh
oheco-broker tenant serve --name example --allow tcp@127.0.0.1:8080 \
  --password-stdin --state-events
oheco-broker tenant connect --name example --target 127.0.0.1:8080 \
  --local 18080 --password-stdin --state-events
```

Linux 和 HarmonyOS 上，对正在运行的 serve/connect 进程发送 `SIGUSR1` 可请求手动恢复：

```sh
kill -USR1 <serve-or-connect-pid>
```

此请求不关闭映射、不更换端口。启用状态事件后，`reconnect_requested` 的 `accepted: true` 表示请求已接受；`connection_state` 记录状态、尝试次数、代数、下次重试延迟和脱敏错误原因。事件采用轮询，可能合并短暂状态变化。事件不包含密码、账户 token、设备 token 或会话 token。`SIGINT`、`SIGTERM` 继续正常关闭程序。

## TCP 连续性的边界与兼容性

已有 TCP 连接继续使用同一个业务 socket，需要两端 SDK 进程和目标 socket 都仍存活，并在保留期限内恢复。v2 发送端保存有界重放缓存，接收端只在真实 socket 写入成功后确认累计位置；恢复时校验双方位置，重发尚未确认的数据并保留半关闭。缓存满时施加背压，不无限增长。SDK 不能撤销业务应用自己的超时，也不能恢复已经丢失的目标应用状态。

每个 peer 的映射层缓存及流上下文分配预算仍为 16 MiB，每条 TCP 流有至多 64 KiB 发送缓存和 64 KiB 接收缓存。`max_flows` 是逻辑流数量上限，实际容量还受内存预算约束。SDK 在预算内预留证明和 RESUME 解析上下文，确保满载时也能恢复已经接纳的流；新增流达到资源上限时可能被拒绝。

恢复上下文不存在、两端进程重启或保留期限已过时，旧 TCP 会关闭；SDK 不为旧流重新连接目标 socket，也不会将旧业务请求重新发送到一个新目标连接。在逻辑连接的授权仍有效时，稳定映射句柄仍可接受新的连接；若进程重启同时轮换设备凭据、账户权限失效或连接被明确撤销，则需取得新授权并创建新的 peer。显式关闭的映射不会由重连恢复。

UDP 没有可靠重放：中断时丢弃发送队列和重组状态，恢复前清理监听 socket 中的旧报文。应用仍需按自己的 UDP 协议处理丢包。

映射能力在已认证的 ICE 消息中协商：`mapping_version: 2` 支持 TCP 恢复，缺失该字段则使用 v1；ALPN、PAKE 确认和 QUIC 连接证明仍兼容 v1。旧 v1 peer 可建连并恢复映射服务，但已有 TCP 不具备 v2 的连续性保证，QUIC 保留旧的 90 秒空闲设置以兼容旧端保活周期。

持久恢复关系需要新版后端的数据库 schema v2，使用逻辑 `connection_id` 与会话代数绑定账户、broker 和设备；`/v1/status` 的 `connection_recovery_version` 标识该控制能力。TCP 上下文还由保留的恢复秘密与新认证证明绑定，不能只凭逻辑 ID 接管旧 socket。旧控制端可使用兼容会话路径，但不能承诺保留旧目标 socket 的透明恢复。

每次恢复重新检查授权。密码认证失败、设备或 broker 明确撤销以及账户权限失效属于终止错误，手动重连不能绕过。目标 ACL 拒绝会关闭相应目标流。

租户连接配额计算仍获授权的逻辑连接，正常关闭后释放租户配额。后端保留撤销记录，直到原账户或设备凭据失效，以免丢失首次请求结果的客户端重新创建已撤销的关系。全部逻辑连接及撤销记录另受 10,000 条存储上限约束；达到此上限时仍可恢复现有获授权连接，新逻辑连接需等待记录自然清理或管理员使旧凭据失效。

为重新执行认证，C SDK 在句柄存活期间保留密码的自有内存副本，最终关闭时清除；不会把 peer 密码写入配置、磁盘或管理 HTTP 请求。调用方仍需管理自己的密码副本；Go 字符串不可原地擦除，SDK 无法保证清除调用方或运行时保留的副本。
