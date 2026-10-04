# Linux Docker 部署

单一镜像 `ghcr.io/oheco/oheco-broker:0.4.0` 包含 `oheco-broker-server` 和完整 `oheco-broker` CLI，默认入口为独立服务端。使用 Linux Docker Engine 与 Compose v2；镜像发布提供 Linux amd64／arm64，HarmonyOS 发行包与 Linux 容器使用不同产物。本文命令从完整 checkout 的根目录执行，域名、IPv4 和私有路径由部署者填写。

## 两种 TLS 模式

| 模式 | Compose／环境模板 | HTTPS/WSS | 签发与续期 |
|---|---|---|---|
| 内置 ACME | [compose.acme.yaml](../deploy/docker/compose.acme.yaml)／[.env.acme.example](../deploy/docker/.env.acme.example) | bridge 网络，主机 TCP 443 发布到容器 TCP 443 | 服务端通过 TLS-ALPN-01 自动获取、续期；持久化 ACME 缓存 |
| 外部证书 | [compose.static.yaml](../deploy/docker/compose.static.yaml)／[.env.static.example](../deploy/docker/.env.static.example) | host 网络，主机 TCP 3478，可改为其他非特权端口 | acme.sh、Certbot 或其他 issuer 签发；服务只读导出目录，每 30 秒加载有效更新 |

**内置 ACME 使用 Linux bridge 网络**，由 Docker 将主机 TCP 443、UDP 3478 和 UDP 50000–50100 发布到容器内相同端口。**外部证书使用 `network_mode: host`**，直接使用主机网卡及端口，不填写 Compose `ports:`。两者的服务 listener 都绑定其网络命名空间内的 `0.0.0.0`。

主机 UDP 3478 用于 STUN/TURN，UDP 50000–50100 为显式设置的 relay 范围，包含两端。TCP 3478 和 UDP 3478 是独立 socket，外部证书模式可以同时运行 HTTPS 和 TURN。当前 TURN 只支持 UDP/IPv4。准备 DNS A 记录、实际可达公网 IPv4，以及以下安全组／主机防火墙／NAT 规则：

| 流量 | 内置 ACME | 外部证书默认值 |
|---|---|---|
| API、WSS、TLS 握手 | TCP 443 | TCP 3478 |
| STUN/TURN | UDP 3478 | UDP 3478 |
| TURN relay | UDP 50000–50100 | UDP 50000–50100 |

还需允许服务到合法 peer 的 UDP 流量及返回流量；内置 ACME 需出站 HTTPS 访问 CA。`BROKER_PUBLIC_IPV4` 必须是实际对外 IPv4，不能填 `0.0.0.0` 或容器的 bridge 私网地址。bridge 模式的 Docker NAT 将每个 relay UDP 端口发布到相同主机端口，与 TURN 公告的公网 IPv4／端口一致；不要只发布 UDP 3478 或改变 relay 的内外端口对应关系。主机防火墙必须允许 Docker 发布端口的转发路径及返回流量。

云 NAT 地址不在网卡上时，监听仍用 `0.0.0.0`，公告公网地址，并由部署者配置相同端口的转发。更改 relay 上下界时，ACME Compose 自动用同一环境变量更新 published range，还需同时更新防火墙和外层 NAT。端口池不是并发会话数，耗尽后 allocation 失败，不回退到范围外。

内置 ACME 要求域名 TCP 443 **经端口发布直接到达此服务的 TLS listener**，支持 `acme-tls/1` ALPN。Docker 转发保持 TLS 流量交给容器内服务端处理；TLS 终止代理、CDN、错误 DNS 或其他进程占用主机 443 会阻止签发／续期。若发布 AAAA，也必须保证其验证流量可达；服务 listener 使用 IPv4。部署者先检查现有 443 listener，并自行安排端口归属，模板不停止其他服务。此模式不需要 TCP 80，不支持将 HTTPS 改到 3478 后继续使用内置 TLS-ALPN-01。

外部证书可用 DNS-01，也可在其他主机签发后安全导出；broker 本身不需要开放 TCP 443 或 TCP 80。证书必须覆盖客户端使用的域名，并包含完整中间证书链。公有 CA 使用镜像内的系统 CA；私有 CA 客户端通过 `--ca-file` 指定信任文件。

## 持久化目录与权限

准备 Linux 上真正支持 Unix 所有权、chmod 和原子 rename 的持久化文件系统。容器始终以 **UID/GID 10001:10001** 运行，根文件系统只读，`/tmp` 为 16 MiB 临时 tmpfs。数据库、ACME 缓存及 CLI 配置写入唯一的状态 bind mount。首次创建宿主目录需要 root 权限；运行服务不使用 root，也不在启动时修复任意宿主目录。

在操作员 shell 中设置一个绝对、非 symlink 的状态根目录，例如 `/srv/oheco-broker`；以下命令只针对新部署目录。不要在已有实例上重新生成管理员 token。

```sh
: "${BROKER_BASE:?set a new absolute persistent directory, for example /srv/oheco-broker}"
export BROKER_DATA_DIR="$BROKER_BASE/data"
export BROKER_SECRETS_DIR="$BROKER_BASE/secrets"
export BROKER_CERT_DIR="$BROKER_BASE/tls"

sudo install -d -o root -g root -m 0755 "$BROKER_BASE"
sudo install -d -o 10001 -g 10001 -m 0700 \
  "$BROKER_DATA_DIR" "$BROKER_DATA_DIR/db" "$BROKER_DATA_DIR/acme" \
  "$BROKER_DATA_DIR/config" "$BROKER_DATA_DIR/config/oheco-broker" \
  "$BROKER_SECRETS_DIR" "$BROKER_CERT_DIR"

# 在 root shell 的私有 umask 下生成；不把 token 打印到终端或放入 .env。
sudo sh -eu -c '
  token_file="$1/admin.token"
  test ! -e "$token_file" && test ! -L "$token_file"
  umask 077
  openssl rand -hex 32 > "$token_file"
  chown 10001:10001 "$token_file"
  chmod 0600 "$token_file"
' sh "$BROKER_SECRETS_DIR"

sudo stat -c '%u:%g %a %n' \
  "$BROKER_DATA_DIR/db" "$BROKER_DATA_DIR/acme" \
  "$BROKER_DATA_DIR/config/oheco-broker" "$BROKER_SECRETS_DIR/admin.token"
```

目录应显示 `10001:10001 700`，token 显示 `10001:10001 600`。数据库路径固定为 `/var/lib/oheco-broker/db/control.sqlite`；ACME 缓存为 `/var/lib/oheco-broker/acme`；`XDG_CONFIG_HOME=/var/lib/oheco-broker/config`，CLI 账号文件默认位于其下的 `oheco-broker/account.json`。服务端用显式 `--db`，不从 CLI 账号配置读取服务参数。

Compose 的 bind mount 会遮住镜像中预建的目录，必须在宿主准备上述子目录。例子设置 `create_host_path: false`，缺失目录直接报错。不要替换成未经初始化的 named volume 根目录：Docker 默认 root 所有、0755 的目录不满足这里的写入／隐私要求。若自行采用 named volume，先初始化其内由 UID 10001 持有的 0700 子目录，再让数据库和缓存使用这些子目录；单纯挂载新 volume 并不能完成初始化。rootless Docker／user namespace remapping 需要部署者把容器 UID 10001 映射到实际宿主 UID，再按映射准备文件。

管理员 token 和 TLS 私钥必须为 **普通文件、无 symlink、由有效服务 UID 10001 持有、实际模式 0600 或 0400**；私钥还不能有额外硬链接。证书也必须是普通文件，示例统一使用 UID/GID 10001、0600。Compose 的默认 secret 文件模式 0444 不符合服务的私密文件检查，本文使用只读目录 bind。不要直接挂载 Let's Encrypt 的 `live/` 文件：它们通常是指向 `archive/` 的 symlink。不要单独 bind 两个 PEM 文件：宿主原子替换后，文件 bind 可能仍指向旧 inode。

## 启动内置 ACME

```sh
cp deploy/docker/.env.acme.example deploy/docker/.env.acme
```

编辑 `.env.acme`，填写 `BROKER_DOMAIN`、`BROKER_PUBLIC_IPV4`、`BROKER_DATA_DIR`、`BROKER_SECRETS_DIR`；路径与上一步一致，使用绝对路径。可设置联系邮箱。`BROKER_ACME_DIRECTORY` 留空使用 Let's Encrypt production。阅读所选 CA 的服务条款后显式填写 `BROKER_ACME_ACCEPT_TOS=true`；模板默认空值，不替部署者接受条款。必填空值触发 `${VAR:?…}`，Compose 在启动前拒绝不完整配置。

```sh
docker compose --env-file deploy/docker/.env.acme \
  -f deploy/docker/compose.acme.yaml config --quiet
docker compose --env-file deploy/docker/.env.acme \
  -f deploy/docker/compose.acme.yaml pull
docker compose --env-file deploy/docker/.env.acme \
  -f deploy/docker/compose.acme.yaml up -d
docker compose --env-file deploy/docker/.env.acme \
  -f deploy/docker/compose.acme.yaml logs --tail=100 broker
```

ACME Compose 在独立容器网络命名空间中设置 `net.ipv4.ip_unprivileged_port_start=0`，允许 UID 10001 绑定容器 TCP 443；保留 `cap_drop: ALL` 和 `no-new-privileges`，不需要网络 capability。此 sysctl 只影响该容器的网络命名空间，不修改宿主 sysctl。普通 rootful Docker Engine 负责发布主机 TCP 443。使用 rootless Docker 时，其主机低端口发布限制仍然适用，部署者需先配置可用的 443 发布／转发方式，容器 sysctl 不能解决该宿主限制。

首次启动会签发证书，后续启动复用持久化账号和证书，运行中自动续期。保留缓存，不要把日常重启变成重复注册和签发。检查 `acme_ready`、`certificate_served`、`server_ready`；CA、DNS 或端口错误时先处理原因再重试。需要 staging 测试时选用独立状态目录并设置 staging directory URL；staging 证书不受公有信任，不与 production 缓存混用。

## 外部签发与续期导出

先按上面的权限步骤准备 `BROKER_CERT_DIR`。issuer 在宿主或独立管理环境中运行，证书和 DNS-provider 凭据不写进容器镜像或 `.env`。broker 只读取该目录；续期任务需要有权写目录并执行 `chown 10001:10001`。以下示例由 root 调度 issuer；acme.sh 的 cron 或 Certbot timer 必须使用同一配置，并且每次成功续期都运行导出 hook。

以下宿主 hook 同时支持 acme.sh 安装后的权限检查与 Certbot 导出。它读取 root 管理的目标目录配置，不依赖续期任务继承当前 shell 的变量。Certbot 导出先准备 UID 10001、0600 的新普通文件，再逐个 rename；短暂的不匹配由服务保留最后有效证书。

```sh
sudo install -d -o root -g root -m 0755 /etc/oheco-broker
printf '%s\n' "$BROKER_CERT_DIR" | sudo tee /etc/oheco-broker/tls-export-dir >/dev/null
sudo chown root:root /etc/oheco-broker/tls-export-dir
sudo chmod 0600 /etc/oheco-broker/tls-export-dir
sudo tee /usr/local/sbin/oheco-broker-cert-export >/dev/null <<'SH'
#!/bin/sh
set -eu
IFS= read -r export_dir < /etc/oheco-broker/tls-export-dir
case "$export_dir" in /*) ;; *) exit 1 ;; esac
test -d "$export_dir" && test ! -L "$export_dir"
if [ "${1:-}" = --permissions-only ]; then
  for name in fullchain.pem privkey.pem; do
    test -f "$export_dir/$name" && test ! -L "$export_dir/$name"
    chown 10001:10001 "$export_dir/$name"
    chmod 0600 "$export_dir/$name"
  done
  exit 0
fi
: "${RENEWED_LINEAGE:?Certbot must supply its renewed certificate directory}"
stage=$(mktemp -d "$export_dir/.renew.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -o 10001 -g 10001 -m 0600 "$RENEWED_LINEAGE/fullchain.pem" "$stage/fullchain.pem"
install -o 10001 -g 10001 -m 0600 "$RENEWED_LINEAGE/privkey.pem" "$stage/privkey.pem"
mv -f "$stage/fullchain.pem" "$export_dir/fullchain.pem"
mv -f "$stage/privkey.pem" "$export_dir/privkey.pem"
SH
sudo chown root:root /usr/local/sbin/oheco-broker-cert-export
sudo chmod 0755 /usr/local/sbin/oheco-broker-cert-export
```

**acme.sh：**使用已经配置好的 DNS provider 插件签发，例如将 `dns_PROVIDER` 替换成所用插件名；其凭据由 issuer 自己管理。`--install-cert` 才是部署接口，不读取 acme.sh 内部工作目录。这里的 root acme.sh 安装路径是示例，按实际安装调整。RSA 证书省略 `--ecc`；示例签发 EC 证书。

```sh
: "${BROKER_DOMAIN:?set the certificate DNS name}"
sudo /root/.acme.sh/acme.sh --issue --server letsencrypt \
  --dns dns_PROVIDER -d "$BROKER_DOMAIN" --keylength ec-256
sudo /root/.acme.sh/acme.sh --install-cert -d "$BROKER_DOMAIN" --ecc \
  --key-file "$BROKER_CERT_DIR/privkey.pem" \
  --fullchain-file "$BROKER_CERT_DIR/fullchain.pem" \
  --reloadcmd '/usr/local/sbin/oheco-broker-cert-export --permissions-only'
```

acme.sh 记录安装路径及 `reloadcmd`，后续成功续期继续安装普通文件并恢复 UID 10001／0600。不要用 `--reloadcmd` 重启 broker。若签发在其他主机，必须让目标主机的导出步骤执行相同权限检查，并把两个普通文件复制／rename 到已挂载目录；移动整个宿主导出目录会使现有 directory bind 仍指向旧目录。

**Certbot：**下面使用真实的 Cloudflare DNS 插件选项，需预先安装插件并准备 root 私有 credentials 文件；使用其他 DNS provider 时按插件说明替换对应选项。`certonly` 保存 issuer 管理的 `live/` symlink，deploy hook 把它们的内容复制为 broker 导出目录里的普通文件。

```sh
: "${BROKER_DOMAIN:?set the certificate DNS name}"
: "${BROKER_ACME_EMAIL:?set the issuer contact email}"
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /private/path/cloudflare.ini \
  --non-interactive --agree-tos --email "$BROKER_ACME_EMAIL" \
  -d "$BROKER_DOMAIN" --cert-name "$BROKER_DOMAIN" \
  --deploy-hook /usr/local/sbin/oheco-broker-cert-export

# 已有证书首次导出时可显式调用；RENEWED_LINEAGE 是 issuer 的来源目录。
sudo env RENEWED_LINEAGE="/etc/letsencrypt/live/$BROKER_DOMAIN" \
  /usr/local/sbin/oheco-broker-cert-export
sudo certbot renew --dry-run
```

确认 Certbot 该证书的 renewal 配置记录此 deploy hook，root timer／cron 执行 `certbot renew`；检查续期任务日志。`--dry-run` 检查签发路径，默认不运行 deploy hook；首次实际导出及以下 `stat` 才检查导出文件。服务端不能代替外部 issuer 续期，监控证书到期时间和 hook 失败。

```sh
sudo stat -c '%F %u:%g %a %n' \
  "$BROKER_CERT_DIR/fullchain.pem" "$BROKER_CERT_DIR/privkey.pem"
```

两者应为普通文件、`10001:10001 600`。证书可以读取 issuer 来源的 symlink 内容，但导出目标自身不能是 symlink。

## 启动外部证书模式

```sh
cp deploy/docker/.env.static.example deploy/docker/.env.static
```

编辑 `.env.static`，填写公网 IPv4 和准备好的状态／secret／证书导出目录。`BROKER_HTTPS_PORT=3478` 表示 **HTTPS TCP 3478**，TURN 仍用 **UDP 3478**；此 host 网络模板可选择其他大于等于 1024 的可用 TCP 端口。首次启动必须已有匹配、有效的证书与私钥。

```sh
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml config --quiet
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml pull
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml up -d
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml logs --tail=100 broker
```

外部证书同样可以使用主机 TCP 443 或其他可用 TCP 端口：改用前述 bridge 发布方式，容器通过独立网络命名空间的 sysctl 绑定 TCP 443，保留静态证书 flags 与只读证书目录。下面是替代 host Compose 部署的完整例子；发布其他 HTTPS 端口时只修改 `443:443/tcp` 中的第一个端口。普通 rootful Docker Engine 发布主机端口，rootless 限制见内置 ACME 段。

```sh
docker run -d --name oheco-broker-static --restart unless-stopped \
  --network bridge --user 10001:10001 --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --publish 443:443/tcp --publish 3478:3478/udp \
  --publish "${BROKER_RELAY_MIN_PORT:-50000}-${BROKER_RELAY_MAX_PORT:-50100}:${BROKER_RELAY_MIN_PORT:-50000}-${BROKER_RELAY_MAX_PORT:-50100}/udp" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
  -e XDG_CONFIG_HOME=/var/lib/oheco-broker/config \
  --mount "type=bind,src=$BROKER_DATA_DIR,dst=/var/lib/oheco-broker" \
  --mount "type=bind,src=$BROKER_SECRETS_DIR,dst=/run/oheco-broker/secrets,readonly" \
  --mount "type=bind,src=$BROKER_CERT_DIR,dst=/run/oheco-broker/tls,readonly" \
  ghcr.io/oheco/oheco-broker:0.4.0 \
  --listen=0.0.0.0:443 --db=/var/lib/oheco-broker/db/control.sqlite \
  --admin-token-file=/run/oheco-broker/secrets/admin.token \
  --registration=approval --registration-relay=false \
  --tls-cert=/run/oheco-broker/tls/fullchain.pem \
  --tls-key=/run/oheco-broker/tls/privkey.pem --tls-reload-interval=30s \
  --turn-listen=0.0.0.0:3478 --turn-public-ip="${BROKER_PUBLIC_IPV4:?set the public IPv4}" \
  --turn-relay-min-port="${BROKER_RELAY_MIN_PORT:-50000}" \
  --turn-relay-max-port="${BROKER_RELAY_MAX_PORT:-50100}"
```

服务每 30 秒读取稳定的证书／密钥快照，校验权限、匹配关系和有效期。成功后新 TLS 握手使用更新证书，已有 WSS 连接继续，**无需容器重启**。文件缺失、部分更新、无效格式、symlink、错误权限或不匹配时保留最后有效 pair，记录 `certificate_reload_error`；恢复后记录 `certificate_reload_recovered`／`certificate_reloaded`。最后有效证书也会到期，不能忽略持续的续期／加载失败。

## CLI 与管理员操作

同一镜像默认启动服务端，`docker exec` 可运行其中的 CLI。以下外部证书例子将 `BROKER_DOMAIN` 设为证书覆盖的真实域名；若 HTTPS 端口已改，更新 URL。内置 ACME 使用 `https://域名`。

```sh
: "${BROKER_DOMAIN:?set the DNS name covered by the certificate}"
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml exec -T broker \
  /usr/local/bin/oheco-broker --api "https://$BROKER_DOMAIN:3478" \
  admin --token-file /run/oheco-broker/secrets/admin.token registration show

docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml exec -T broker \
  /usr/local/bin/oheco-broker --api "https://$BROKER_DOMAIN:3478" \
  admin --token-file /run/oheco-broker/secrets/admin.token tenant approve TENANT_UUID

docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml exec -T broker \
  /usr/local/bin/oheco-broker --api "https://$BROKER_DOMAIN:3478" \
  admin --token-file /run/oheco-broker/secrets/admin.token tenant relay enable TENANT_UUID
```

首次数据库初始化保持 `registration=approval`、`registration-relay=false`。批准租户与启用其 relay 是两个独立操作，批准不授予 relay；已有数据库中的策略不会被启动参数覆盖，通过管理员 API／CLI 修改。

从宿主的一次性容器调用 CLI，可显式覆盖入口、保留同一非 root 用户及私有配置目录：

```sh
docker run --rm --network host --user 10001:10001 --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
  -e XDG_CONFIG_HOME=/var/lib/oheco-broker/config \
  --mount "type=bind,src=$BROKER_DATA_DIR,dst=/var/lib/oheco-broker" \
  --mount "type=bind,src=$BROKER_SECRETS_DIR,dst=/run/oheco-broker/secrets,readonly" \
  --entrypoint /usr/local/bin/oheco-broker ghcr.io/oheco/oheco-broker:0.4.0 \
  --api "https://$BROKER_DOMAIN:3478" \
  admin --token-file /run/oheco-broker/secrets/admin.token registration show
```

普通租户命令也使用 `--api`，注册／登录写入持久化 XDG 账号文件；管理员命令读取 `--token-file`。若使用私有 CA，将信任的 CA PEM 普通文件导出到 `BROKER_CERT_DIR/ca.pem`，由 UID 10001 可读，沿用外部证书目录的只读挂载：

```sh
docker compose --env-file deploy/docker/.env.static \
  -f deploy/docker/compose.static.yaml exec -T broker \
  /usr/local/bin/oheco-broker --api "https://$BROKER_DOMAIN:3478" \
  --ca-file /run/oheco-broker/tls/ca.pem \
  admin --token-file /run/oheco-broker/secrets/admin.token registration show
```

一次性 CLI 容器需同时添加证书目录的只读 `--mount`。所有例子保留证书链和主机名验证。

## 镜像、资源与更新

环境模板默认固定 `0.4.0` 标签，可用 `BROKER_IMAGE` 指定已验证的 digest 或本地镜像。服务配置由 Compose `command` 中的独立服务端 flags 提供；`OHECO_BROKER_ADMIN_TOKEN` 是 token 的环境备选来源，但例子使用私有文件，避免 token 出现在环境、命令行或渲染配置里。完整 flags 可直接查看：

```sh
docker run --rm ghcr.io/oheco/oheco-broker:0.4.0 --help
docker run --rm ghcr.io/oheco/oheco-broker:0.4.0 --version
docker run --rm --entrypoint /usr/local/bin/oheco-broker \
  ghcr.io/oheco/oheco-broker:0.4.0 --help

# 从完整 checkout 构建当前主机架构的镜像。
docker build -t oheco-broker:0.4.0 \
  --build-arg APP_VERSION=0.4.0 \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" .
```

镜像构建使用仓库中固定的 Go vendor 和 C SDK 依赖；首次拉取基础镜像、构建工具及系统包需要网络。应用 MIT，镜像的项目与依赖许可证位于 `/usr/share/licenses/oheco-broker/`，系统包版权记录位于 `/usr/share/doc/`。libjuice 及其他依赖保留各自许可证和源码义务，见[依赖记录](NATIVE-DEPENDENCIES.md)与[根许可证](../LICENSE)。完整 CLI 包含 C peer 引擎；默认独立服务端不链接该引擎。

Compose 示例给出 1 CPU、512 MiB 内存、128 个进程上限和每个服务最多 3×10 MiB 的 JSON 日志。按实际并发与 relay 流量调整这些限制及端口范围；观察 CPU、内存、磁盘和带宽。外部证书例子的 host 网络直接占用主机端口，ACME 例子的 published ports 也占用对应主机端口；两种模板是替代部署方案，相同主机端口同时只能由一个实例持有。

更新前保存一致的 SQLite 备份，并单独保护管理员 token、ACME 缓存或外部 issuer 的账号／证书、CLI 账号配置。可停止服务后备份整个状态目录，或由受控备份工具使用 SQLite backup API；不要在服务写入时只复制数据库主文件。拉取已验证的新镜像后用同一 Compose／环境文件 `up -d` 替换容器，保留 bind 目录；数据库有迁移时回滚同时需要兼容旧程序的一致备份。`docker compose down` 不删除宿主 bind 数据。

部署后验证受信 HTTPS/WSS、UDP STUN、审批及独立 relay 权限，再从真实客户端检查 direct 与 `force` 的 TCP／UDP 数据、relay 用量和清理。`server_ready` 或容器运行状态不能证明公网防火墙、端口转发和 peer 路径通过。更多边界与验收见[通用部署](PRODUCTION-DEPLOYMENT.md)和[验收索引](LOCAL-VALIDATION.md)。

## 维护者构建与发布

[Docker 工作流](../.github/workflows/docker.yml)在两种原生 Linux runner 上分别构建和验收，随后加载原样保存的已验收镜像发布 GHCR，多架构索引不重新构建应用。PR 执行构建验收；新 `v*` 标签自动发布；手动触发的 `version` 通常选择既有应用标签 `vVERSION`；发布前可指定完整 40 位 `source_revision` 并保持 `publish=false`、`verify_only=false`，验证该提交而不创建标签或发布镜像。构建配方取所触发的工作流提交，并分别记录 revision。

可选 `image_tag` 留空时使用应用版本，只允许显式指定同一应用版本或 `VERSION-docker.N`（`N` 为正整数）。例如维护容器配方时选择 `0.4.0-docker.1`，源码仍取不可变的 `v0.4.0`，两种程序的版本及 OCI 应用版本标签仍为 `0.4.0`。镜像已有版本／修订标签拒绝覆盖；不移动应用 Git 标签，也不替换已发布的 `0.3.0` 镜像。匿名验证同样接受 `image_tag`，拉取所选镜像标签并核对原应用版本／源码 revision。

```sh
# 发布前验证当前提交，不创建标签或上传镜像。
gh workflow run docker.yml --repo oheco/oheco-broker --ref main \
  -f version=0.4.0 -f source_revision="$(git rev-parse HEAD)" -F publish=false

# 未来配方修订示例；默认 publish=false，两种架构必须全部通过才发布。
gh workflow run docker.yml --repo oheco/oheco-broker --ref main \
  -f version=0.4.0 -f image_tag=0.4.0-docker.1 -F publish=true

# 验证现有镜像的匿名拉取和两架构实际执行，不重建或覆盖镜像。
gh workflow run docker.yml --repo oheco/oheco-broker --ref main \
  -f version=0.4.0 -F verify_only=true
```

GitHub 首次创建 GHCR 包默认私有，仓库本身公开不会自动改变包可见性。包管理员需在[包设置](https://github.com/orgs/oheco/packages/container/oheco-broker/settings)的 **Change visibility → Public** 完成一次公开设置，然后运行上面的匿名验证。发布凭据使用 Actions `GITHUB_TOKEN` 的 `packages: write`，不需要 Docker Hub 密码；匿名验证使用空 Docker 凭据目录。GitHub 目前[通过包设置网页管理可见性](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#configuring-visibility-of-packages-for-an-organization)，REST API 不提供此修改接口。
