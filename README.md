# lyco-control

给一台机器上的几个自托管面板加一道共用的密码门：登录一次，然后从卡片进各个面板。

纯 Python 标准库 + 一个反向代理，没有数据库、不需要 Node、也不装任何监控组件。

## 能做什么

- **一个密码管所有入口**：登录后签发一个签名 cookie，子域共享，各面板子域由反代做 `auth_request` 校验。
- **卡片式首页**：每张卡片显示名称、说明、图标，以及服务端探活结果（HTTP 毫秒数或 systemd 状态）。
- **资源概览**：CPU / 内存 / 磁盘 / 负载，外加可配置窗口的 CPU、内存、网络曲线，以及按服务或容器拆分的占用表。
- **浏览器里改**：标题、卡片增删、密码，都在 `/admin` 里改，不用碰文件。
- **详情页**：按卡片看 systemd 单元状态、内存占用和日志尾部。

## 不做什么

- **不代替面板自己的登录**：过了这道门，目标面板仍可能要求它自己的账号密码。
- **没有多用户**：只有一套密码，没有角色、没有权限分级。
- **不做代登录**：不会替你把密码填进目标面板。
- **不长期存指标**：历史默认写在 `/run`，服务重启可恢复，机器重启清空。

## 页面与接口

| 路径 | 作用 |
|---|---|
| `/` | 首页：卡片、资源条、图表、服务占用表 |
| `/login`、`/logout` | 登录、退出 |
| `/setup` | 首次设置密码，必须带 `?t=<token>` |
| `/admin` | 改标题、卡片、密码 |
| `/detail?id=<id>` | 单个卡片的 systemd 状态与日志尾 |
| `/api/status` | 卡片探活结果（JSON，需登录） |
| `/api/metrics` | 资源采样 + 服务占用（JSON，需登录） |
| `/auth` | 供反代 `auth_request` 调用的内部端点 |

## 它是怎么串起来的

```
                 ┌──────────────── 127.0.0.1:7900  门户（登录 / 卡片 / 编辑 / 指标）
                 │
浏览器 ── TLS ── 反代 ── panel.example.com  → 门户
                 │
                 └─ app1.example.com ─ auth_request ─→ 门户 /auth
                                     └─ 通过后 ──→ 127.0.0.1:8080  面板本身
```

入口默认只监听 `127.0.0.1`，对外由反代提供 TLS 和子域入口。只信任本机反代覆盖写入的 `X-Client-IP` 和 `X-Forwarded-Proto`。远程反代需要本机转发接入，并单独配置网络访问控制。

## 快速开始

要求：Linux、Python 3.9+、反代（示例用 nginx）、certbot。以 Debian/Ubuntu 为例：

```bash
sudo apt-get install -y python3 nginx certbot python3-certbot-nginx
sudo useradd --system --home /srv/lyco-control --shell /usr/sbin/nologin portal
sudo mkdir -p /srv/lyco-control
sudo cp -r app.py metrics.py service_status.py templates static /srv/lyco-control/
sudo chown -R portal:portal /srv/lyco-control
sudo cp deploy/lyco-control.service /etc/systemd/system/lyco-control.service
sudoedit /etc/systemd/system/lyco-control.service     # 改域名、路径、端口
sudo systemctl daemon-reload && sudo systemctl enable --now lyco-control
```

服务文件里要改的三处：`PORTAL_COOKIE_DOMAIN`（填 `.example.com`）、`PORTAL_SECURE`（上 HTTPS 后改 1）、`WorkingDirectory` 与 `ExecStart` 的路径。

### 反向代理

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/lyco-control
sudoedit /etc/nginx/sites-available/lyco-control   # 改 server_name 和 map 里的端口
sudo ln -s /etc/nginx/sites-available/lyco-control /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

要点：

- 门户自己的 `server` 块整块 `proxy_pass` 到 `http://127.0.0.1:7900`。
- 每个面板子域用 `auth_request /_auth`，内部 `location = /_auth` 转发到门户的 `/auth`：有会话返回 200，否则 401，前端跳去登录页。
- 登录页和首次设置页不要加 `auth_request`，否则永远打不开。
- 转发时必须覆盖写：`proxy_set_header X-Client-IP $remote_addr;`
- 保留浏览器访问的主机及端口：`proxy_set_header Host $http_host;`，并覆盖写 `X-Forwarded-Proto $scheme`。
- 所有 POST 必须携带与入口匹配的 `Origin` 或 `Referer`；脚本调用可显式设置 `Origin: https://panel.example.com`。

### 证书

```bash
sudo certbot --nginx -d panel.example.com -d app1.example.com -d app2.example.com
```

签完把服务文件里的 `PORTAL_SECURE` 改成 `1` 并重启，cookie 才会带 `Secure`。

## 首次设置密码

密码至少 10 位。启动时会生成一次性 token 并写进日志：

```bash
sudo journalctl -u lyco-control --no-pager -n 30
# 首次使用：打开 /setup?t=<token> 设置密码（设完这条链接即失效）
```

打开 `https://panel.example.com/setup?t=<token>` 设置。设完 token 立即作废，之后访问 `/setup` 会重定向到登录页。忘了密码的话，停服务、清掉 `portal.json` 里的 `password_hash` 与 `session_epoch`、再启动，就会重新生成 token。

## 配置

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORTAL_CONFIG` | `./portal.json` | 配置文件；含密码哈希和会话密钥，权限 600 |
| `PORTAL_BIND` | `127.0.0.1` | 监听地址，默认只给本机反代用 |
| `PORTAL_PORT` | `7900` | 监听端口 |
| `PORTAL_TITLE` | `服务入口` | 初始标题；在 `/admin` 改过之后以配置为准 |
| `PORTAL_COOKIE_DOMAIN` | 空 | 填 `.example.com` 让子域共用一次登录 |
| `PORTAL_SECURE` | `0` | HTTPS 就绪后设 1，cookie 加 `Secure` |
| `PORTAL_SESSION_HOURS` | `8` | 登录有效期（小时），限制在 1–168 小时 |
| `PORTAL_LOGIN_LOG` | 空 | 登录审计日志路径；记录成功/失败、IP、时间，超 1 MB 自动轮转 |
| `PORTAL_METRICS_HOURS` | `24` | 资源曲线窗口长度（小时），仅默认模式生效 |
| `PORTAL_METRICS_FILE` | `/run/lyco-portal/metrics-history.json` | 历史存放位置，想落磁盘才自己指到别处 |

### `portal.json` 里的卡片

卡片在 `services[]` 里。只改这个数组，不要整份覆盖——同一个文件还存着密码哈希、会话密钥和设置 token。

```json
{"services": [{
  "id": "app1",
  "name": "应用面板",
  "desc": "查看和管理应用",
  "url": "https://app1.example.com",
  "check": "http://127.0.0.1:8080/",
  "unit": "app1.service",
  "log": "/srv/app1/logs/app1.log",
  "icon": "A",
  "enabled": true
}]}
```

| 字段 | 说明 |
|---|---|
| `id` | 稳定标识，供 `/detail?id=` 使用，与显示名称无关 |
| `name` | 卡片标题 |
| `desc` | 一行说明 |
| `url` | 点击地址，也可写站内路径，如 `/detail?id=app1` |
| `check` | 探活用的 HTTP 地址；有值就发请求，能显示毫秒 |
| `unit` | systemd 单元名；`check` 为空时按它判断在线，但不显示毫秒 |
| `log` | 日志文件路径，详情页显示尾部 |
| `icon` | 可选，一个字符或 emoji；不填则用名称首字生成字标 |
| `enabled` | 是否显示 |

探活优先级：有 `check` 走 HTTP → 没有 `check` 但有 `unit` 走 systemd → 两者都空则状态未知。

最多 128 张卡片，标识不可重复。HTTP 探活不跟随重定向、不使用环境代理；状态码小于 500 表示入口可响应（包括需要登录的 401/403），不代表业务健康。详情页不展示响应正文，避免回显内部凭据。单次请求只等待有限时间，繁忙时显示未探活。

## 资源指标

`metrics.py` 只读 `/proc`、`statvfs` 和 cgroup v2，不装 agent。后端每 3 秒采一次，按分钟聚合成一个点；默认最多存 1440 个点（24 小时），页面每 3 秒读一次 `/api/metrics` 拿快照。横轴只画已有的数据：从第一个点画到最后一个点，不预留后面的空白。

历史固定放在 `/run`（tmpfs，内存盘）：服务重启后接着画，机器重启清空，全程不写硬盘。

**窗口有两种模式**，在 `/admin` →「资源历史」里切：

| 模式 | 采样 | 点数 | 能看多久 |
|---|---|---|---|
| 默认 | 每分钟一个点 | 1440 | 24 小时（时长可改，1–168 小时） |
| 原来那套 | 每 3 秒一个点 | 120 | 6 分钟，曲线更细 |

随附 systemd 单元会创建权限为 0700 的 `/run/lyco-portal`，服务重启时保留。自行部署而不使用该单元时，可加 tmpfiles 规则：

```bash
echo 'd /run/lyco-portal 0700 <运行用户> <运行用户> -' | sudo tee /etc/tmpfiles.d/lyco-portal.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/lyco-portal.conf
```

两个值存在 `portal.json` 的 `metrics` 段里；环境变量 `PORTAL_METRICS_HOURS` 只作为首次运行的默认值，之后以页面里的为准。切换模式时不会混用旧档：存档里记着采样间隔，跟当前模式对不上就直接弃用。

开启时，重启那几十秒的空白补不上——只会在上次的点之后接着画。窗口长度也在页面里改，调大只会让内存占用按比例变大（每小时 60 个点）。

返回内容：CPU 与内存百分比、磁盘用量、load、uptime、上下行速率，以及 `services[]`（按 cgroup 统计每个服务或容器的内存与 CPU，按内存降序）。

指标口径：CPU 为整机总算力占比（包含 steal，不重复计算 guest）；服务 CPU 同样按整机总算力归一化。内存优先使用 `MemAvailable`；磁盘用量不包含文件系统保留块，使用率按「已用 /（已用 + 普通用户可用）」计算。网络速率单位为 KiB/s，排除回环及常见容器网桥接口；复杂 bond、隧道或自定义网桥拓扑仍可能重复统计。负载是 Linux 原始 1/5/15 分钟 load，未除以核心数。

指标读取失败时保留最近一次成功快照并标记延迟；首次采样尚未成功时 `/api/metrics` 返回 503。历史保存失败也会标记降级。页面会显示更新失败并自动重试。

**容器名字（可选）**：cgroup 目录名是容器 ID，为了让表格显示 `astrbot` 这种名字，需要一个 root 定时器把 ID→名字写成一个文件给门户读——门户本身不拿 docker 权限：

```bash
sudo cp deploy/lyco-container-names /usr/local/bin/ && sudo chmod +x /usr/local/bin/lyco-container-names
sudo mkdir -p /var/lib/lyco-portal-ceil
sudo cp deploy/lyco-container-names.service deploy/lyco-container-names.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now lyco-container-names.timer
```

没有这个定时器也没关系：卡片和系统服务照常统计，只是 docker 容器会显示成一段 ID。

## 安全上做了哪些事

- 密码存 PBKDF2-HMAC-SHA256、200,000 轮、独立 salt，不存明文。
- 会话是 HMAC 签名的时间戳 cookie，`HttpOnly` + `SameSite=Lax`，HTTPS 下加 `Secure`；签名绑定 `session_epoch`，改密码即让所有旧 cookie 失效。
- 单 IP 连错 5 次开始指数退避（1 分钟起、封顶 1 小时，带 `Retry-After`）；IPv6 按 /64 归并。
- 10 分钟内全局失败 30 次进入 2 秒慢速模式；登录校验最多并发 2 个。
- 客户端 IP 仅接受本机反代覆盖写入的 `X-Client-IP`，其他连接使用对端地址；不读取 `X-Forwarded-For`。
- POST 严格校验来源防 CSRF，缺少来源头也拒绝；请求体上限 256 KB，拒绝重复长度头和 Transfer-Encoding。
- 卡片字段做 HTML 转义；登录后的 `next` 只接受站内路径，`//evil.example` 这类会被丢弃。
- 配置写入串行化，临时文件 + fsync + rename 原子替换，权限 600。
- HTTP 活动连接最多 128 个（accept 队列同为 128），探活工作线程全局最多 8 个；认证读快照不等待配置写盘。
  一个页面的并发 subrequest 有几十个、每个都要过 `/auth`，上限过低会把连接掐掉，边缘上表现为 502。
- 动态 HTML 转义，静态路径验证真实目录边界；响应禁止缓存、嵌入框架和泄漏 Referer。

本地自检（仅标准库）：

```bash
python -m py_compile app.py metrics.py service_status.py
python -m unittest -v test_portal
```

## 目录结构

```
app.py                HTTP 服务：路由、认证、渲染
metrics.py            /proc、statvfs、cgroup 采样
service_status.py     systemd 状态与日志尾（只读）
templates/            index、login、setup、admin、detail
static/               style.css 与站点图标
deploy/               systemd 单元、nginx 示例、容器名定时器
```

## 已知限制

- 目标面板仍可能要自己的账号密码；这里只统一了「进得去」这一层。
- 单用户、单机；配置是一个 JSON 文件，不支持集群或多副本。
- 探活只有 HTTP 和 systemd 两种；systemd 模式给不出响应时间。
- 指标历史默认在 `/run`，机器重启清空；不做告警，也没有长期存储。
- TLS 和子域入口依赖外部反代，服务本身只说 HTTP。
- 所有共享会话 cookie 的子域都必须可信；任何一个面板的服务端被攻破，都可能泄漏共用 cookie。
- 退出登录只清除当前浏览器 cookie；无状态会话被复制后仍可用至过期，改密码会撤销全部旧会话。
- 探活地址和日志路径由单一管理员配置，允许访问本机服务及运行用户可读的文件；没有为多用户提供 SSRF 或文件访问隔离。
