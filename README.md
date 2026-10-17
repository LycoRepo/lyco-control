# panel-gate

给一台个人服务器做的**单一入口**：一个登录页，若干张卡片，每张卡片通到一个本地面板（机器人框架、监控、自己的服务都行）。

后端纯标准库，没有依赖；前端是服务端渲染的 HTML + 一份 CSS。

```
panel.example.com   → 入口（登录 / 卡片 / 编辑 / 详情）
app1.example.com    → 127.0.0.1:8080   你的某个面板
app2.example.com    → 127.0.0.1:9090   另一个
```

## 它解决什么

- **面板不再各自暴露端口**：所有后端服务只监听 `127.0.0.1`，对外只有 nginx 的 80/443。
- **只输一次密码**：会话 cookie 设在 `.example.com`，所有子域共用。
- **页面里能改**：卡片（名称/链接/探活地址/开关）和门户密码都在 `/admin` 改，写进 `portal.json`，不用重启。
- **状态是真的**：卡片上的在线/离线由**服务端**并发探活得出，不是浏览器猜的。
- **没有 Web 面板的服务**也能进：给它配 `unit` + `log`，站内 `/detail` 页显示 systemd 状态、内存、探活响应、日志尾。

## 为什么用子域名而不是 `/app1/` 这种路径

多数面板（Vite/React 构建的）把资源写成绝对路径 `/assets/...`，挂在子路径下会白屏。子域名让每个面板仍然待在根路径，代码零改动。代价是要几条 DNS 记录——但平时只记入口那一个地址。

## 快速开始

```bash
sudo useradd --system --home /srv/panel-gate --shell /usr/sbin/nologin portal
sudo mkdir -p /srv/panel-gate
sudo cp -r app.py service_status.py templates static /srv/panel-gate/
sudo chown -R portal:portal /srv/panel-gate

sudo cp deploy/panel-gate.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now panel-gate
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7900/setup     # 200

sudo cp deploy/nginx.conf /etc/nginx/sites-available/panel-gate
sudo ln -s /etc/nginx/sites-available/panel-gate /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# DNS 生效后签证书
sudo certbot --nginx -d panel.example.com -d app1.example.com -d app2.example.com
sudo sed -i 's/PORTAL_SECURE=0/PORTAL_SECURE=1/' /etc/systemd/system/panel-gate.service
sudo systemctl daemon-reload && sudo systemctl restart panel-gate
```

### 第一次设密码

启动日志里会打印一条带一次性 token 的链接（防止别人抢先给你的面板设密码）：

```bash
sudo journalctl -u panel-gate -n 20 | grep setup
# 首次使用：打开 /setup?t=3f9c… 设置密码（设完这条链接即失效）
```

把它拼到你的域名后面打开即可，**设完 token 立刻失效**，之后再访问 `/setup` 会 403。

## 配置

运行时配置在 `portal.json`（首次启动自动生成，权限 600），也可以直接在 `/admin` 里改：

| 字段 | 说明 |
|---|---|
| `title` | 页面标题/品牌名（也可用环境变量 `PORTAL_TITLE`） |
| `password_hash` | pbkdf2-sha256（20 万轮）+ 随机盐 |
| `secret` | 会话签名密钥，自动生成 |
| `services[].name` | 卡片名称，也是 `/detail?id=` 的键 |
| `services[].url` | 点进去的地址；站内页可写 `/detail?id=xxx` |
| `services[].check` | 服务端探活地址（建议 `http://127.0.0.1:port/`） |
| `services[].unit` | 可选，systemd 单元名 |
| `services[].log` | 可选，日志文件路径 |
| `services[].enabled` | 是否显示 |

环境变量：`PORTAL_PORT`（默认 7900）、`PORTAL_BIND`、`PORTAL_COOKIE_DOMAIN`、`PORTAL_SECURE`、`PORTAL_TITLE`、`PORTAL_CONFIG`。

## 结构

```
app.py              后端：登录/会话/卡片/探活/编辑/改密/详情/auth
service_status.py   只读 systemd 与 /proc，读日志尾、探活
templates/          index login setup admin detail
static/style.css    样式（系统字体，无外链）
deploy/             systemd 单元 + nginx 站点
```

## 安全说明

- 密码只存 pbkdf2 哈希；**最短 10 位**；登录失败会延迟 400ms。
- **首次设置要一次性 token**（日志里打印），避免"谁先打开谁设密码"。
- **改密码会轮换会话代次**：其它设备上的旧 cookie 立即失效，当前浏览器自动换新。
- 登录后的 `next` 只接受站内路径，`//evil.example` 这类开放重定向会被丢弃。
- POST 体积上限 256 KB，超了直接 413；读超时 15 秒，慢连接不会长期占线程。

### 防爆破（三层）

| 层 | 做什么 | 为什么 |
|---|---|---|
| 应用 · 单 IP | 5 次失败开始封，1 分钟起**指数退避**（1/2/4/8… 最长 1 小时），带 `Retry-After` | 让暴力尝试的成本随时间指数上升 |
| 应用 · 全局 | 10 分钟内失败 30 次 → 进入**慢速模式**（每次校验强制等 2 秒），**不整体封禁** | 全禁会变成"攻击者花 30 个请求把站长锁在门外" |
| nginx | `limit_req` 只统计 **POST /login**（GET 不计），超了退回登录页提示 | 第二道闸；只算 GET 会把正常刷新也挡掉 |

配套细节：
- IP 取 `X-Client-IP`（nginx 用 `$remote_addr` **覆盖写**，客户端伪造无效）；**完全不信任 `X-Forwarded-For`**。
- **IPv6 按 /64 归并**——否则换一个地址就是一个新身份，计数永远不触发。
- 同时最多 2 个登录校验在跑，避免用并发把线程和 CPU 打满。
- `PORTAL_LOGIN_LOG=/var/log/panel-gate-login.log` 可开审计日志（成/败、IP、时间），超过 1 MB 自动轮转。
- 会话 cookie 是 HMAC 签名的时间戳，`HttpOnly` + `SameSite=Lax`；上 HTTPS 后必须开 `PORTAL_SECURE=1`。
- **推荐 HTTPS**：公网明文 HTTP 登录等于把面板钥匙挂在路上。
- 这个项目**不代替**各面板自己的鉴权：它只加一层门。要让面板彻底无感登录，需要在门户里做代登录（各面板登录接口不同，本项目不含）。

## License

MIT
