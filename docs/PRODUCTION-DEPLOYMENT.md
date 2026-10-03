# 通用 HTTPS/WSS 与 STUN/TURN 部署

先按[服务端构建](SERVER-BUILD.md)在目标平台构建并验证 `oheco-broker-server`。以下仅是部署模板，`example.org`、`192.0.2.1` 和私有路径均为占位值；替换成自己的配置，不包含任何现有实例操作。

## 端口与准入

| 用途 | 示例入口 |
|---|---|
| REST 与 WSS | TCP 8443，`https://example.org:8443` |
| STUN／TURN | UDP 3478，实际公网 IPv4 |
| TURN allocation pool | UDP 50000–59999，包含两端 |

示例 API 使用非特权 TCP 8443，STUN/TURN 使用 UDP 3478；部署者可显式选择其他端口。安全组、主机防火墙和 NAT 必须允许相应协议、relay 范围及到合法 peer 的返回流量。`--turn-public-ip` 公告对外地址，不能填 `0.0.0.0`；云 NAT 公网地址未配置在网卡上时，绑定 `0.0.0.0` 并公告实际公网 IPv4。

relay 最小／最大端口必须同时设置且 `1 <= min <= max <= 65535`；均为 0 表示系统临时端口。allocator 按需创建 socket，跳过占用端口，耗尽后失败，不回退到范围外。范围约束不等于并发会话数；全局 allocation 默认上限为 512。TURN 当前仅 UDP/IPv4，不支持 TCP/TLS 回退。

公网采用 `registration=approval`、`registration-relay=false`，并配置准入／限速。批准账号不自动授予 relay；现存数据库策略通过管理员 API 修改，启动参数只初始化新数据库。不要启用 `--turn-allow-loopback`。

## 静态证书模板

以专用服务用户运行，准备其拥有的 0700 状态目录和 0600 token／私钥普通文件。证书必须匹配客户端使用的 DNS 名或 IP SAN；客户端保留证书链及主机名验证。

```sh
: "${BROKER_BIN:?set the verified platform-native executable}"
: "${BROKER_STATE_DIR:?set a private persistent directory}"
: "${BROKER_ADMIN_TOKEN_FILE:?set a private admin token file}"
: "${BROKER_TLS_CERT:?set the full certificate chain}"
: "${BROKER_TLS_KEY:?set the matching private key}"
: "${BROKER_PUBLIC_IP:?set the real externally reachable IPv4}"

"$BROKER_BIN" \
  --listen 0.0.0.0:8443 \
  --db "$BROKER_STATE_DIR/control.sqlite" \
  --admin-token-file "$BROKER_ADMIN_TOKEN_FILE" \
  --registration approval --registration-relay=false \
  --tls-cert "$BROKER_TLS_CERT" --tls-key "$BROKER_TLS_KEY" \
  --tls-reload-interval 30s \
  --turn-listen 0.0.0.0:3478 --turn-public-ip "$BROKER_PUBLIC_IP" \
  --turn-relay-min-port 50000 --turn-relay-max-port 59999
```

外部 issuer 负责签发／续期。broker 每 30 秒验证稳定快照、匹配密钥、有效期和权限，原子换证，**无需重启**；已有 WSS 连接继续。缺失／部分替换／格式错误／密钥不匹配／不安全权限／symlink／并发变化保留最后有效 pair。首次无有效证书时拒绝启动。

观察 `certificate_loaded`、`certificate_reloaded`、`certificate_reload_error`、`certificate_reload_recovered`。外部 issuer 续期失败仍需在最后有效证书到期前处理。原生 ACME 模式改用 `--acme-domain example.org --acme-cache "$BROKER_STATE_DIR/acme" --acme-accept-tos`，绑定 TCP 443；不能同时配置静态证书参数。

## 管理与更新

```sh
oheco-broker --api https://example.org:8443 \
  admin --token-file /private/path/admin.token registration show
oheco-broker --api https://example.org:8443 \
  admin --token-file /private/path/admin.token tenant approve TENANT_UUID
oheco-broker --api https://example.org:8443 \
  admin --token-file /private/path/admin.token tenant relay enable TENANT_UUID
```

私有 CA 用 `--ca-file` 显式指定，不关闭验证。持久化数据库、管理员 token、证书来源及服务用户独立于源码／构建缓存；HarmonyOS 使用权限正常的 `$XDG_CONFIG_HOME`，不依赖 HOME/hmdfs chmod。

Linux 提供[systemd unit](../deploy/systemd/oheco-broker.service)及[环境模板](../deploy/systemd/oheco-broker.env.example)，以专用 `oheco-broker` 用户运行。配置显式 listener、管理员 token、TLS 文件、对外 IPv4 和 relay 范围；默认 API TCP 8443、TURN UDP 3478。文件所有权需匹配该服务用户。更新前通过 SQLite backup API 保存一致数据库备份，单独保护管理员 token 与 issuer 管理的证书。先离线构建／测试新产物，再安装不可变版本、切换程序入口并重启；保留旧程序与备份用于回滚，保留现存数据库与 token。首次安装不依赖任何旧测试目录或缓存。

## 验证

验证真实受信 HTTPS/WSS、UDP STUN、审批与独立 relay 权限；用独立原生 peer 检查 direct 和 `force` 的 TCP/UDP 数据、实际 relay 计数和清理。启动就绪日志不能证明防火墙或公网转发。UDP 丢包如实记录，某条设备到云主机路径通过不代表所有 NAT。当前源码及发行验收入口见[索引](LOCAL-VALIDATION.md)。
