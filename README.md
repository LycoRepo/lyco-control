# panel-gate

给一台服务器上的几个自托管面板加一个密码门：登录后从卡片进入各面板，由 Python 标准库 HTTP 服务配合 nginx 提供入口。

## 它做什么，不做什么

- 提供单密码登录、卡片入口、服务状态和浏览器内编辑页。

- 配置共享 cookie 域，并让各子域通过 nginx 校验会话后，入口密码只需登录一次。

- 不代替面板自身的登录：通过入口后，目标面板仍可能要求账号密码。

- 适合单人、单服务器使用，不提供多用户或角色权限。

## 界面有什么

- `/`：卡片网格，显示名称、说明、图标及服务端探活状态。

- `/detail?id=<卡片id>`：查看 systemd 状态、内存占用和日志尾。

- `/admin`：编辑品牌名、卡片表及密码；三个表单分别 POST 到 `/admin/title`、`/admin/services`、`/admin/password`。

- `/login`、`/logout`：登录和退出；`/api/status`：需登录的 JSON 状态接口。

- `/static/*`：CSS 与图标。仓库自带 `icon-32.png`、`icon-192.png`、`icon-512.png`、`icon.ico`、`apple-touch-icon.png`。

- 未放置图标时，回退到按标题首字生成的 SVG 字标；`/favicon.svg` 随标题实时生成。

## 快速开始

需要 Python 3.9+、nginx 和 certbot；Python 服务不需要第三方包。以下安装命令适用于使用 apt 的系统，部署命令从仓库根目录执行。先核对 `deploy/panel-gate.service` 中的运行用户和程序路径，确保与示例的 `portal`、`/srv/panel-gate` 一致。

```bash

sudo apt-get update

sudo apt-get install -y python3 nginx certbot python3-certbot-nginx

python3 --version

sudo useradd --system --home /srv/panel-gate --shell /usr/sbin/nologin portal

sudo mkdir -p /srv/panel-gate

sudo cp -r app.py service_status.py templates static /srv/panel-gate/

sudo chown -R portal:portal /srv/panel-gate

sudo cp deploy/panel-gate.service /etc/systemd/system/panel-gate.service

sudo systemctl daemon-reload

sudo systemctl edit panel-gate

```

在覆盖配置中加入以下内容。示例启用首次设置 token，避免开放公网后被他人抢先设置密码。

```text

[Service]

WorkingDirectory=/srv/panel-gate

Environment="PORTAL_CONFIG=/srv/panel-gate/portal.json"

Environment="PORTAL_BIND=127.0.0.1"

Environment="PORTAL_PORT=7900"

Environment="PORTAL_COOKIE_DOMAIN=.example.com"

Environment="PORTAL_SECURE=0"

Environment="PORTAL_SETUP_TOKEN=1"

```

```bash

sudo systemctl daemon-reload && sudo systemctl enable --now panel-gate

sudo systemctl status panel-gate --no-pager

```

### nginx 与证书

将 `panel.example.com` 和各面板子域的 DNS 指向服务器，再安装并编辑示例配置。以下使用 nginx 的 `sites-available` / `sites-enabled` 目录布局。

```bash

sudo cp deploy/nginx.conf /etc/nginx/sites-available/panel-gate

sudoedit /etc/nginx/sites-available/panel-gate

sudo ln -s /etc/nginx/sites-available/panel-gate /etc/nginx/sites-enabled/panel-gate

sudo nginx -t && sudo systemctl reload nginx

```

编辑时，每个子域使用独立的 `server` 块：门户请求通过 `proxy_pass` 转到 `http://127.0.0.1:7900`，面板请求转到各自的本机端口。

受保护的面板位置使用 `auth_request /_auth`，由内部 `location = /_auth` 把认证子请求转发到门户的 `/auth`；有会话返回 200，否则返回 401，并跳转到门户登录页。

不要让登录和首次设置页面也要求已有会话。转发给门户时，用 `proxy_set_header X-Client-IP $remote_addr;` 覆盖客户端传入的同名头。

DNS 生效后申请证书；按实际入口增减子域。密码设置和登录应在 HTTPS 就绪后进行。

```bash

sudo certbot --nginx -d panel.example.com -d app1.example.com -d app2.example.com

sudo systemctl edit panel-gate

```

将上面的覆盖项 `PORTAL_SECURE=0` 改为 `PORTAL_SECURE=1`，然后重启，使 cookie 带上 `Secure`。

```bash

sudo systemctl daemon-reload && sudo systemctl restart panel-gate

```

## 首次设置密码

密码最短 10 位。首次设置有两种模式：

- 默认 `PORTAL_SETUP_TOKEN=0`：`/setup` 直接可用，谁先访问谁设置。未设置密码前，不要把这个入口交给不可信访问者。

- 设置 `PORTAL_SETUP_TOKEN=1`：必须打开 `/setup?t=<token>` 才能设置；一次性 token 只出现在服务日志中，适合先暴露公网、稍后才设置密码的情况。

上面的部署示例使用第二种模式。读取日志，将其中的 token 用于 `https://panel.example.com/setup?t=<token>`：

```bash

sudo journalctl -u panel-gate --no-pager -n 50

```

设置完成后，一次性 token 失效；此后访问 `/setup` 会重定向到 `/login`。

## 配置项

### 环境变量

| 变量 | 默认值 | 说明 |

|---|---|---|

| `PORTAL_CONFIG` | `./portal.json` | 配置路径；含密码哈希和会话密钥，文件权限为 600 |

| `PORTAL_PORT` | `7900` | 监听端口 |

| `PORTAL_BIND` | `127.0.0.1` | 监听地址；默认仅本机，由 nginx 对外提供访问 |

| `PORTAL_TITLE` | `Server Panel` | 初始标题；在 `/admin` 修改后以配置为准 |

| `PORTAL_COOKIE_DOMAIN` | 空 | 如 `.example.com`，用于子域共享登录 |

| `PORTAL_SECURE` | `0` | HTTPS 就绪后设为 1，为 cookie 添加 `Secure` |

| `PORTAL_SETUP_TOKEN` | `0` | 设为 1 时，首次设置必须带 `?t=<token>` |

| `PORTAL_LOGIN_LOG` | 空 | 登录审计日志路径，记录成功或失败、IP、时间；超过 1 MB 自动轮转 |

### `portal.json` 卡片字段

卡片位于 `services[]`。以下仅展示卡片配置，不要用它覆盖包含密码哈希和会话密钥的完整配置。

```json

{"services": [{

  "id": "app1", "name": "应用面板", "desc": "查看和管理应用",

  "url": "https://app1.example.com", "check": "http://127.0.0.1:8080/",

  "unit": "app1.service", "log": "/srv/panel-gate/logs/app1.log",

  "icon": "A", "enabled": true

}]}

```

| 字段 | 说明 |

|---|---|

| `id` | 稳定标识，用于 `/detail?id=`，不是卡片名称 |

| `name` | 卡片名称 |

| `desc` | 一行说明 |

| `url` | 点击地址，也可使用站内路径，如 `/detail?id=app1` |

| `check` | 服务端 HTTP 探活地址；有值时发起 HTTP 请求，可显示毫秒 |

| `unit` | systemd 单元名；`check` 为空时，按单元状态判断在线，不显示毫秒 |

| `log` | 日志文件路径，详情页显示尾部 |

| `icon` | 可选，一个字符或 emoji |

| `enabled` | 是否显示卡片 |

探活优先级：有 `check` 用 HTTP；没有 `check` 但有 `unit` 用 systemd；两者都空时状态为未知。

## 安全说明

- 密码使用 PBKDF2-HMAC-SHA256、200,000 轮及独立 salt，不存明文密码。

- 会话为 HMAC 签名的时间戳 cookie，有效期 14 天，带 `HttpOnly` 和 `SameSite=Lax`；HTTPS 下需启用 `Secure`。

- 签名绑定 `session_epoch`，修改或重设密码后，旧 cookie 立即失效。

- 单 IP 连续失败 5 次起指数退避，1 分钟起、封顶 1 小时，响应带 `Retry-After`；IPv6 按 /64 归并。

- 10 分钟内全局失败 30 次进入 2 秒慢速模式，不整体封禁；登录校验最多同时运行 2 个。

- 客户端 IP 只认 nginx 覆盖写入的 `X-Client-IP`，不信任 `X-Forwarded-For`；不要让外部请求绕过反代直连服务。

- POST 做 same-origin 校验以防 CSRF，请求体上限 256 KB，超出返回 413。

- 卡片字段做 HTML 转义；登录后的 `next` 只接受站内路径，丢弃 `//evil.example` 这类开放重定向。

- 配置写入串行化，通过临时文件、fsync 和 rename 原子替换，权限为 600；该文件含会话密钥，应限制读取权限。

- 共享 cookie 只应覆盖你信任的子域。密码门不替代 HTTPS，也不替代各面板自己的认证。

## 目录结构

```text

app.py                    单文件服务：路由、认证、探活、渲染

service_status.py         systemd 状态与日志尾：只读，调用 systemctl/journalctl

templates/                index、login、setup、admin、detail

static/                   style.css 与图标

deploy/                   panel-gate.service、nginx.conf

```

## 已知限制

- 不做卡片背后面板的代登录，目标面板仍可能要求自己的账号密码。

- 没有多用户和角色权限，只有一套密码；没有数据库，配置保存在单个 JSON 文件中。

- 探活仅支持 HTTP 和 systemd；`unit` 模式无法提供响应时间。

- 需要 nginx 或同类反代提供 HTTPS 与子域入口；服务默认只监听 `127.0.0.1`。

- 不支持集群或多副本，状态保存在内存与单个 JSON 文件中。
