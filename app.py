#!/usr/bin/env python3
"""
panel-gate — 服务器统一管理入口

职责：
  1. 一个登录页（单密码），会话 cookie 设在 PORTAL_COOKIE_DOMAIN，各子域共用
  2. 首页列出各服务的卡片 + 实时状态（服务端探活，不依赖浏览器）
  3. 编辑页：改卡片（名称/地址/探活目标/开关）、改密码 —— 不碰代码
  4. /auth 给 nginx 的 auth_request 用：校验 cookie，返回 200/401

不依赖任何第三方库（只用标准库），Python 3.9+ 可跑。
"""
from __future__ import annotations

import base64
import copy
import hashlib
import html as html_mod
import hmac
import io
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from string import Template
from urllib.parse import parse_qs, quote, urlparse

import metrics
import service_status

ROOT = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.environ.get("PORTAL_CONFIG", os.path.join(ROOT, "portal.json"))
TPL_DIR = os.path.join(ROOT, "templates")
STATIC_DIR = os.path.join(ROOT, "static")
PORT = int(os.environ.get("PORTAL_PORT", "7900"))
BIND = os.environ.get("PORTAL_BIND", "127.0.0.1")
COOKIE = "panel_gate"
COOKIE_DOMAIN = os.environ.get("PORTAL_COOKIE_DOMAIN", "")   # 例如 .example.com
SECURE_COOKIE = os.environ.get("PORTAL_SECURE", "0") == "1"
SESSION_HOURS = int(os.environ.get("PORTAL_SESSION_HOURS", "8"))   # 登录有效期（小时）
SESSION_SECONDS = SESSION_HOURS * 3600
PBKDF2_ITERS = 200_000
MIN_PASSWORD = 10              # 密码最短长度
MAX_BODY = 256 * 1024          # 表单就几百字节，给足余量但不让人塞爆内存
CFG_LOCK = threading.Lock()    # 配置读改写串行化
LOGIN_LOCK = threading.Lock()          # 登录失败计数
LOGIN_FAILS: dict[str, tuple[int, float]] = {}
MAX_FAILS = 5                          # 单个 IP 连续失败 5 次开始封
BASE_BLOCK = 60                        # 首次封 1 分钟
MAX_BLOCK = 3600                       # 最长封 1 小时
GLOBAL_MAX = 30                        # 全局：10 分钟内失败 30 次就进入「慢速模式」
GLOBAL_WINDOW = 600
GLOBAL_SLOW_FOR = 60                   # 慢速持续 60 秒，每次尝试强制等 2 秒
GLOBAL_SLOW_UNTIL = 0.0
GLOBAL_FAILS: list[float] = []         # 失败时间戳（滑动窗口）
GLOBAL_UNTIL = 0.0
LOGIN_LOG = os.environ.get("PORTAL_LOGIN_LOG", "")   # 审计日志，空则只写 stdout
LOGIN_SEM = threading.Semaphore(2)     # 同时最多处理 2 个登录请求
TITLE = os.environ.get("PORTAL_TITLE", "Server Panel")

DEFAULT_CONFIG = {
    "secret": "",
    "password_hash": "",
    "session_epoch": "",
    "setup_token": "",
    "title": TITLE,
    "services": [
        # 一个卡片 = 一个入口。url 是点进去的地址（可用 https://… 或站内 /detail?id=xxx）。
        # check 是服务端探活的地址（建议指向 127.0.0.1 上的真实端口）。
        # unit / log 可选：填了之后详情页会显示 systemd 状态和日志尾。
        {"id": "service-a", "name": "示例服务 A", "desc": "点进去是它的 Web 面板",
         "url": "https://panel-a.example.com/", "check": "http://127.0.0.1:8080/",
         "icon": "🅰", "enabled": True},
        {"id": "service-b", "name": "示例服务 B", "desc": "没有 Web 面板，看站内状态页",
         "url": "/detail?id=service-b", "check": "http://127.0.0.1:9090/health",
         "unit": "myservice-b.service", "log": "/var/log/myservice-b.log",
         "icon": "🅱", "enabled": True},
    ],
}


# ---------- 配置读写 ----------

def load_config() -> dict:
    """读配置；缺字段就补齐并落盘。第一次运行也走同一条补齐路径（否则会漏掉 setup_token）。"""
    if os.path.exists(CFG_PATH):
        with io.open(CFG_PATH, encoding="utf-8") as fh:
            cfg = json.load(fh)
    else:
        cfg = {}
    changed = False
    for key, val in DEFAULT_CONFIG.items():
        if key not in cfg:
            cfg[key] = copy.deepcopy(val)
            changed = True
    if not cfg.get("secret"):
        cfg["secret"] = secrets_token()
        changed = True
    if not cfg.get("session_epoch"):
        cfg["session_epoch"] = secrets_token()
        changed = True
    if not cfg.get("password_hash") and not cfg.get("setup_token"):
        cfg["setup_token"] = secrets_token()   # 首启时生成，设完密码即清空
        changed = True
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg: dict) -> None:
    tmp = "{}.{}.tmp".format(CFG_PATH, os.getpid())
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, CFG_PATH)
    try:
        os.chmod(CFG_PATH, 0o600)
    except OSError:
        pass


def secrets_token() -> str:
    import secrets
    return secrets.token_hex(32)


# ---------- 密码与会话 ----------

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return "pbkdf2${}${}${}".format(PBKDF2_ITERS, salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_session(secret: str, epoch: str) -> str:
    exp = int(time.time()) + SESSION_SECONDS
    return "{}.{}".format(exp, _sign(secret, "{}.{}".format(exp, epoch)))


def valid_session(secret: str, epoch: str, token: str) -> bool:
    """会话 = 过期时间 + HMAC(secret, 过期时间.epoch)。改密码时 epoch 轮换，旧 cookie 立刻失效。"""
    try:
        exp_s, sig = token.split(".", 1)
        if int(exp_s) < time.time():
            return False
        return hmac.compare_digest(sig, _sign(secret, "{}.{}".format(exp_s, epoch)))
    except Exception:
        return False


# ---------- 探活 ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None     # 不跟随：探活只看第一次响应，避免被当成盲 SSRF 的跳板


_OPENER = urllib.request.build_opener(_NoRedirect)


def probe(target: str, timeout: float = 2.5) -> dict:
    if not target:
        return {"up": None, "ms": None, "detail": "未配置"}
    scheme = urlparse(target).scheme.lower()
    if scheme not in ("http", "https"):
        return {"up": None, "ms": None, "detail": "仅支持 http/https"}
    started = time.time()
    try:
        req = urllib.request.Request(target, method="GET", headers={"User-Agent": "panel-gate"})
        with _OPENER.open(req, timeout=timeout) as resp:
            resp.read(256)
            code = resp.getcode()
        return {"up": code < 500, "ms": int((time.time() - started) * 1000), "detail": "HTTP {}".format(code)}
    except urllib.error.HTTPError as exc:
        ok = exc.code < 500
        return {"up": ok, "ms": int((time.time() - started) * 1000), "detail": "HTTP {}".format(exc.code)}
    except Exception as exc:  # 连接失败、超时、DNS
        return {"up": False, "ms": int((time.time() - started) * 1000), "detail": type(exc).__name__}


def probe_all(services: list[dict]) -> list[dict]:
    results: list[dict | None] = [None] * len(services)

    def run(idx: int, svc: dict) -> None:
        if not svc.get("check") and svc.get("unit"):
            st = service_status.unit_state(svc["unit"])
            active = st.get("active") == "active"
            results[idx] = {"up": active, "ms": None,
                            "detail": "systemd: {}".format(st.get("active") or "unknown")}
            return
        results[idx] = probe(svc.get("check", ""))

    threads = [threading.Thread(target=run, args=(i, s), daemon=True) for i, s in enumerate(services)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=4)
    out = []
    for i, svc in enumerate(services):
        r = results[i] or {"up": None, "ms": None, "detail": "超时"}
        out.append({**svc, **r})
    return out


def safe_url(u: str) -> str:
    """卡片链接只允许 http(s) 或站内绝对路径；javascript:/data: 一律丢弃。"""
    u = (u or "").strip()
    if not u:
        return ""
    if u.startswith("/") and not u.startswith("//"):
        return u
    return u if urlparse(u).scheme.lower() in ("http", "https") else ""


def safe_next(target: str) -> bool:
    """只接受站内绝对路径：排除 //host、/\\host、以及带协议的跳转，防开放重定向。"""
    if not target or not target.startswith("/"):
        return False
    if target.startswith("//") or target.startswith("/\\"):
        return False
    return "://" not in target and "\r" not in target and "\n" not in target


def stats_strip() -> str:
    """首页顶部的资源概览数字。"""
    try:
        m = metrics.last()
    except Exception:
        return ""
    cells = [
        ("CPU", "{:.0f}<span class=\"u\">%</span>".format(m["cpu"])),
        ("内存", "{:.0f}<span class=\"u\">%</span>".format(m["mem_pct"])),
        ("磁盘", "{:.0f}<span class=\"u\">%</span>".format(m["disk"]["pct"])),
        ("负载", "{:.2f}".format(m["load"][0])),
    ]
    body = "".join('<div class="stat-strip-item"><span class="k">{}</span>'
                   '<span class="v">{}</span></div>'.format(k, v) for k, v in cells)
    return '<section class="stat-strip" aria-label="资源占用">' + body + '</section>'


def brand_mark(title: str) -> str:
    """品牌标记：标题的第一个有效字符（中文取首字，英文自动大写），都是标点/空白就退回 L。"""
    core = re.sub(r"^[^\w\u4e00-\u9fff]+", "", (title or "").strip())
    return core[:1].upper() or "L"


def slug(name: str) -> str:
    """把名字变成一个 ASCII 稳定的 id（中文名会退化成短哈希），供 /detail?id= 使用。"""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if base:
        return base[:32]
    return "svc-" + hashlib.sha1(name.encode()).hexdigest()[:8]


def card_msg(text: str, cls: str) -> str:
    return '<p class="msg {}">{}</p>'.format(cls, text) if text else ""


# ---------- 渲染 ----------

def render(template: str, **ctx) -> bytes:
    ctx.setdefault("title", TITLE)
    with io.open(os.path.join(TPL_DIR, template), encoding="utf-8") as fh:
        raw = fh.read()
    return Template(raw).safe_substitute(**ctx).encode("utf-8")


def status_class(up) -> str:
    if up is True:
        return "ok"
    if up is False:
        return "down"
    return "unknown"


def status_text(up, detail: str = "", ms=None) -> str:
    if up is True:
        return "在线 · {}ms".format(ms) if ms is not None else "在线"
    if up is False:
        return "离线 · {}".format(detail) if detail else "离线"
    return "未检查"


def cards_html(services: list[dict]) -> str:
    rows = []
    for svc in services:
        if not svc.get("enabled", True):
            continue
        cls = status_class(svc.get("up"))
        txt = status_text(svc.get("up"), svc.get("detail", ""), svc.get("ms"))
        url = safe_url(svc.get("url", "")) or "#"
        rows.append(
            '<a class="card" href="{url}" target="_blank" rel="noopener">'
            '<span class="card-icon">{icon}</span>'
            '<span class="card-body"><span class="card-name">{name}</span>'
            '<span class="card-desc">{desc}</span></span>'
            '<span class="pill {cls}">{txt}</span></a>'.format(
                url=html_mod.escape(quote(url, safe=":/?#[]@!&'()*+,;=%")),
                icon=html_mod.escape(str(svc.get("icon", "•"))),
                name=html_mod.escape(str(svc.get("name", "未命名"))),
                desc=html_mod.escape(str(svc.get("desc", ""))),
                cls=cls,
                txt=html_mod.escape(txt),
            )
        )
    return "\n".join(rows) or '<p class="empty">还没有启用的卡片，去「编辑」里加一个。</p>'


def admin_rows(services: list[dict]) -> str:
    rows = []
    for i, svc in enumerate(services):
        checked = "checked" if svc.get("enabled", True) else ""
        rows.append(
            '<tr>'
            '<td><input type="hidden" name="id_{i}" value="{sid}">'
            '<input name="icon_{i}" value="{icon}" class="w-icon"></td>'
            '<td><input name="name_{i}" value="{name}" class="w-name"></td>'
            '<td><input name="desc_{i}" value="{desc}" class="w-desc"></td>'
            '<td><input name="url_{i}" value="{url}" class="w-url"></td>'
            '<td><input name="check_{i}" value="{check}" class="w-check"></td>'
            '<td><input name="unit_{i}" value="{unit}" class="w-unit" placeholder="xxx.service"></td>'
            '<td><input name="log_{i}" value="{log}" class="w-log" placeholder="/var/log/xxx.log"></td>'
            '<td class="center"><input type="checkbox" name="enabled_{i}" {checked}></td>'
            '</tr>'.format(i=i, sid=html_mod.escape(str(svc.get("id") or slug(svc.get("name", "")))),
                           icon=html_mod.escape(str(svc.get("icon", ""))),
                           name=html_mod.escape(str(svc.get("name", ""))),
                           desc=html_mod.escape(str(svc.get("desc", ""))),
                           url=html_mod.escape(str(svc.get("url", ""))),
                           check=html_mod.escape(str(svc.get("check", ""))),
                           unit=html_mod.escape(str(svc.get("unit") or "")),
                           log=html_mod.escape(str(svc.get("log") or "")), checked=checked)
        )
    return "\n".join(rows)


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "panel-gate"
    protocol_version = "HTTP/1.1"   # 支持 keep-alive（每个响应都带 Content-Length）
    timeout = 15                    # 慢连接最多占一个线程 15 秒
    cfg = DEFAULT_CONFIG  # 由 main() 覆盖

    # --- 工具 ---
    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _logged_in(self) -> bool:
        return valid_session(self.cfg.get("secret", ""), self.cfg.get("session_epoch", ""),
                             self._cookies().get(COOKIE, ""))

    def _cookie_header(self, value: str, max_age: int) -> str:
        parts = ["{}={}".format(COOKIE, value), "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age={}".format(max_age)]
        if COOKIE_DOMAIN:
            parts.append("Domain=" + COOKIE_DOMAIN)
        if SECURE_COOKIE:
            parts.append("Secure")
        return "; ".join(parts)

    def _send(self, body: bytes, code: int = 200, ctype: str = "text/html; charset=utf-8", extra: list[str] | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for h in extra or []:
            self.send_header(*h.split(": ", 1))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str, extra: list[str] | None = None):
        self.send_response(302)
        # 头必须是 ASCII：中文路径也要能跳
        self.send_header("Location", quote(location, safe=":/?#[]@!&'()*+,;=%"))
        self.send_header("Content-Length", "0")
        for h in extra or []:
            self.send_header(*h.split(": ", 1))
        self.end_headers()

    def _body(self) -> dict:
        self._too_large = False
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > MAX_BODY:
            self._too_large = True      # 负数会让 read() 一直读到 EOF，必须挡掉
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    # --- 路由 ---
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/static/"):
            return self._static(path)
        if path == "/auth":
            return self._auth()
        if path in ("/favicon.svg", "/favicon.ico"):
            return self._favicon()
        if path == "/api/status":
            return self._api_status()
        if path == "/setup":
            if self.cfg.get("password_hash"):
                return self._redirect("/login")
            if not self._setup_allowed():
                return self._send(b"<h1>403</h1><p>setup token required</p>", 403)
            return self._send(self.render("setup.html", error_block=""))
        if path == "/login":
            slow = parse_qs(urlparse(self.path).query).get("slow") == ["1"]
            note = card_msg("请求太频繁，稍等一下再试", "err") if slow else ""
            return self._send(self.render("login.html", error_block=note, next=quote(self._next())))
        if path == "/logout":
            return self._redirect("/login", extra=["Set-Cookie: " + self._cookie_header("", 0)])
        if not self._logged_in():
            return self._redirect("/login?next=" + quote(self.path))
        if path == "/":
            return self._send(self.render("index.html", cards=cards_html(probe_all(self.cfg["services"])),
                                     stats_strip=stats_strip(),
                                     when=time.strftime("%Y-%m-%d %H:%M:%S")))
        if path == "/admin":
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block="", path=CFG_PATH))
        if path == "/stats":
            return self._redirect("/")      # 资源已经并在首页，旧书签回到首页
        if path == "/api/metrics":
            metrics.ensure_sampler()
            payload = metrics.last()
            payload["services"] = metrics.services()
            return self._send(json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                              200, "application/json; charset=utf-8",
                              extra=["Cache-Control: no-store"])
        if path == "/detail":
            qs = parse_qs(urlparse(self.path).query)
            key = (qs.get("id") or [""])[0]
            svc = next((s for s in self.cfg["services"]
                        if key and key in (s.get("name"), s.get("id"))), None)
            if not svc:
                return self._send("<h1>404 — no such service</h1>".encode("utf-8"), 404)
            snap = service_status.snapshot(svc)
            st = snap["state"]
            return self._send(self.render(
                "detail.html",
                name=html_mod.escape(svc.get("name", "")),
                desc=html_mod.escape(svc.get("desc", "")),
                unit=html_mod.escape(svc.get("unit", "") or "（未配置 unit）"),
                active=st["active"] or "—",
                enabled=st["enabled"] or "—",
                rss=st["rss"] if st["rss"] is not None else "—",
                active_cls="ok" if st["active"] == "active" else "down",
                enabled_cls="ok" if st["enabled"] == "enabled" else "unknown",
                health_cls="ok" if snap["health"]["ok"] else "down",
                health_text="正常" if snap["health"]["ok"] else "失败",
                health_ok=snap["health"]["ok"],
                health_detail=html_mod.escape(snap["health"]["detail"]),
                log=html_mod.escape("\n".join(snap["log"]) or "（这个卡片没配 log）"),
            ))
        return self._send(b"<h1>404</h1>", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._body()
        if getattr(self, "_too_large", False):
            self.close_connection = True    # 残余 body 不能被当成下一个请求解析
            return self._send(b"payload too large", 413, "text/plain",
                              extra=["Connection: close"])
        if not self._same_origin():
            return self._send(b"cross-origin POST rejected", 403, "text/plain")
        if path == "/setup":
            if self.cfg.get("password_hash"):
                return self._redirect("/login")
            if not self._setup_allowed():
                return self._send(b"<h1>403</h1><p>setup token required</p>", 403)
            pw = form.get("password", "")
            if len(pw) < MIN_PASSWORD:
                return self._send(self.render("setup.html",
                                         error_block=card_msg("至少 {} 个字符".format(MIN_PASSWORD), "err")), 400)
            if pw != form.get("confirm", ""):
                return self._send(self.render("setup.html", error_block=card_msg("两次输入不一致", "err")), 400)
            with CFG_LOCK:
                self.cfg["password_hash"] = hash_password(pw)
                self.cfg["setup_token"] = ""
                self.cfg["session_epoch"] = secrets_token()
                save_config(self.cfg)
            return self._redirect("/", extra=["Set-Cookie: " + self._cookie_header(
                make_session(self.cfg["secret"], self.cfg["session_epoch"]), SESSION_SECONDS)])
        if path == "/login":
            blocked, wait = self._login_blocked()
            if blocked:
                return self._send(self.render("login.html",
                                         error_block=card_msg("尝试次数过多，{} 秒后再试".format(wait), "err"),
                                         next=quote(form.get("next", "/"))), 429,
                                  extra=["Retry-After: {}".format(max(wait, 1))])
            if self._global_slow():
                time.sleep(2)      # 全局降速：只让人变慢，绝不把所有人挡在门外
            pw = form.get("password", "")
            with LOGIN_SEM:        # 最多 2 个并发校验，避免拿线程和 CPU 打满
                ok = verify_password(pw, self.cfg.get("password_hash", ""))
            self._note_login(ok)
            if ok:
                target = form.get("next") or "/"
                if not safe_next(target):
                    target = "/"
                return self._redirect(target, extra=["Set-Cookie: " + self._cookie_header(
                    make_session(self.cfg["secret"], self.cfg["session_epoch"]), SESSION_SECONDS)])
            time.sleep(0.4)
            return self._send(self.render("login.html", error_block=card_msg("密码不对", "err"),
                                     next=quote(form.get("next", "/"))), 401)
        if not self._logged_in():
            return self._redirect("/login")
        if path == "/admin/title":
            name = (form.get("title") or "").strip()[:40]
            if name:
                with CFG_LOCK:
                    self.cfg["title"] = name
                    save_config(self.cfg)
            return self._redirect("/admin")
        if path == "/admin/services":
            return self._save_services(form)
        if path == "/admin/password":
            return self._save_password(form)
        return self._send(b"<h1>404</h1>", 404)

    # --- 具体处理 ---
    def _next(self) -> str:
        qs = parse_qs(urlparse(self.path).query)
        nxt = (qs.get("next") or ["/"])[0]
        return nxt if safe_next(nxt) else "/"

    def _client_ip(self) -> str:
        """反代后面取真实客户端 IP。

        只信 nginx 用 $remote_addr 覆盖写的 X-Client-IP（客户端改不了）。
        退而求其次取 X-Forwarded-For 的**最后**一段（那是自己这台反代追加的）；
        取第一段等于让攻击者自己填一个"新 IP"来绕过限速。
        """
        raw = (self.headers.get("X-Client-IP") or "").strip() or self.client_address[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return "unknown"        # 头里塞垃圾就当"未知"，不构成一个新身份
        if ip.version == 6:
            # 一个 /64 是同一台机器，按 /64 归并，否则换地址就能无限重置计数
            return str(ipaddress.ip_network("{}/64".format(ip), strict=False).network_address) + "/64"
        return str(ip)

    def _login_blocked(self) -> tuple[bool, int]:
        """返回 (是否封禁, 还要等几秒)。只按 IP 硬拦；全局只做降速，不把站长一起关在门外。"""
        now = time.time()
        with LOGIN_LOCK:
            fails, until = LOGIN_FAILS.get(self._client_ip(), (0, 0.0))
            if fails >= MAX_FAILS and now < until:
                return True, int(until - now)
        return False, 0

    def _global_slow(self) -> bool:
        with LOGIN_LOCK:
            return time.time() < GLOBAL_SLOW_UNTIL

    def _note_login(self, ok: bool) -> None:
        """记一次登录结果。锁里只动内存计数；审计写盘在锁外。"""
        global GLOBAL_SLOW_UNTIL
        ip = self._client_ip()
        now = time.time()
        with LOGIN_LOCK:
            if ok:
                LOGIN_FAILS.pop(ip, None)
                GLOBAL_FAILS.clear()
                GLOBAL_SLOW_UNTIL = 0.0
            else:
                fails, _ = LOGIN_FAILS.get(ip, (0, 0.0))
                fails += 1
                if fails >= MAX_FAILS:
                    wait = min(BASE_BLOCK * (2 ** (fails - MAX_FAILS)), MAX_BLOCK)
                    LOGIN_FAILS[ip] = (fails, now + wait)
                else:
                    LOGIN_FAILS[ip] = (fails, now + 60.0)   # 到期时间，供淘汰用
                # 淘汰过期条目；仍超量就丢最旧的一批（不能整表清空，否则封禁会被一起抹掉）
                for k in [k for k, (f, u) in LOGIN_FAILS.items() if u and u < now]:
                    LOGIN_FAILS.pop(k, None)
                if len(LOGIN_FAILS) > 4096:
                    for k in sorted(LOGIN_FAILS, key=lambda x: LOGIN_FAILS[x][1])[:1024]:
                        LOGIN_FAILS.pop(k, None)
                GLOBAL_FAILS.append(now)
                cutoff = now - GLOBAL_WINDOW
                while GLOBAL_FAILS and GLOBAL_FAILS[0] < cutoff:
                    GLOBAL_FAILS.pop(0)
                if len(GLOBAL_FAILS) >= GLOBAL_MAX:
                    # 只降速，不整体封禁：否则 30 个请求就能把站长锁在门外
                    GLOBAL_SLOW_UNTIL = now + GLOBAL_SLOW_FOR
                    GLOBAL_FAILS.clear()
        self._audit(ip, ok)

    def _audit(self, ip: str, ok: bool) -> None:
        """登录审计：谁、成没成。写文件失败不影响登录，但要留下痕迹。"""
        safe_ip = "".join(ch for ch in str(ip) if ch.isprintable() and ch not in "\r\n")[:64]
        line = '{} {} {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S"), "OK  " if ok else "FAIL", safe_ip)
        if LOGIN_LOG:
            try:
                if os.path.exists(LOGIN_LOG) and os.path.getsize(LOGIN_LOG) > 1024 * 1024:
                    os.replace(LOGIN_LOG, LOGIN_LOG + ".1")     # 超过 1MB 轮转一次
                with io.open(LOGIN_LOG, "a", encoding="utf-8") as fh:
                    fh.write(line)
                return
            except Exception as exc:
                print("audit write failed: {} | {}".format(type(exc).__name__, line.strip()), flush=True)
                return
        print(line.rstrip(), flush=True)

    def _same_origin(self) -> bool:
        """浏览器发起的跨站 POST 要挡掉：Origin（其次 Referer）的主机必须与 Host 一致。

        SameSite=Lax 只挡跨站，同父域下的兄弟子域仍算 same-site，所以这里再核一次主机。
        没有 Origin/Referer 的请求（curl、脚本）放行——它们本来就能直接调接口。
        """
        ref = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not ref:
            return True
        try:
            host = urlparse(ref).netloc.lower()
            return host == (self.headers.get("Host", "") or "").lower()
        except Exception:
            return False

    def render(self, template: str, **ctx) -> bytes:
        """模板渲染：标题优先用配置里改过的名字，没改过才用环境变量。"""
        title = self.cfg.get("title") or TITLE
        ctx.setdefault("title", title)
        ctx.setdefault("title_attr", html_mod.escape(title))   # 放进 value="..." 时要转义
        ctx.setdefault("brand_mark", html_mod.escape(brand_mark(title)))
        return render(template, **ctx)

    def _setup_allowed(self) -> bool:
        """首次设密码必须带 ?t=<setup_token>（token 只在服务日志里出现），防止被人抢先设密码。"""
        qs = parse_qs(urlparse(self.path).query)
        given = (qs.get("t") or [""])[0]
        want = self.cfg.get("setup_token", "")
        try:
            return bool(want) and hmac.compare_digest(given.encode("utf-8"), want.encode("utf-8"))
        except Exception:
            return False

    def _favicon(self):
        """字标 favicon：跟着标题走，改了名字图标就跟着换（浏览器支持 SVG 图标）。"""
        mark = html_mod.escape(brand_mark(self.cfg.get("title") or TITLE))
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="#b03a52"/><stop offset="1" stop-color="#e05a72"/>'
            '</linearGradient></defs>'
            '<rect width="64" height="64" rx="15" fill="url(#g)"/>'
            '<text x="32" y="45" text-anchor="middle" font-size="38" font-weight="700" '
            'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" fill="#ffffff">'
            + mark +
            '</text></svg>'
        ).encode("utf-8")
        return self._send(svg, 200, "image/svg+xml",
                          extra=["Cache-Control: public, max-age=600"])

    def _auth(self):
        if self._logged_in():
            return self._send(b"ok", 200, "text/plain")
        return self._send(b"no", 401, "text/plain")

    def _api_status(self):
        if not self._logged_in():
            return self._send(b'{"error":"unauthorized"}', 401, "application/json")
        data = [{"name": s["name"], "up": s.get("up"), "ms": s.get("ms"), "detail": s.get("detail")}
                for s in probe_all(self.cfg["services"])]
        return self._send(json.dumps(data, ensure_ascii=False).encode(), 200, "application/json")

    def _static(self, path: str):
        rel = path[len("/static/"):]
        if ".." in rel or rel.startswith("/"):
            return self._send(b"bad", 400, "text/plain")
        full = os.path.join(STATIC_DIR, rel)
        if not os.path.isfile(full):
            return self._send(b"not found", 404, "text/plain")
        ext = os.path.splitext(full)[1].lower()
        ctype = {".css": "text/css", ".js": "application/javascript", ".svg": "image/svg+xml",
                 ".png": "image/png", ".ico": "image/x-icon"}.get(ext, "application/octet-stream")
        with open(full, "rb") as fh:
            return self._send(fh.read(), 200, ctype)

    def _save_services(self, form: dict):
        idxs = sorted({int(k.split("_")[1]) for k in form if k.startswith("name_") and k.split("_")[1].isdigit()})
        services = []
        for i in idxs:
            name = form.get("name_{}".format(i), "").strip()
            if not name:
                continue
            services.append({
                "id": (form.get("id_{}".format(i)) or "").strip()
                      or slug(form.get("name_{}".format(i), "")),
                "icon": form.get("icon_{}".format(i), "").strip() or "•",
                "name": name,
                "desc": form.get("desc_{}".format(i), "").strip(),
                "url": safe_url(form.get("url_{}".format(i), "")),
                "check": form.get("check_{}".format(i), "").strip(),
                "unit": form.get("unit_{}".format(i), "").strip(),
                "log": form.get("log_{}".format(i), "").strip(),
                "enabled": form.get("enabled_{}".format(i)) == "on",
            })
        with CFG_LOCK:
            self.cfg["services"] = services
            save_config(self.cfg)
        return self._send(self.render("admin.html", rows=admin_rows(services),
                                 msg_block=card_msg("已保存", "ok"), path=CFG_PATH))

    def _save_password(self, form: dict):
        old = form.get("old", "")
        new = form.get("new", "")
        if not verify_password(old, self.cfg.get("password_hash", "")):
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("原密码不对", "err"), path=CFG_PATH), 401)
        if len(new) < MIN_PASSWORD:
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("新密码至少 {} 个字符".format(MIN_PASSWORD), "err"),
                                     path=CFG_PATH), 400)
        if new != form.get("confirm", ""):
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("两次输入不一致", "err"), path=CFG_PATH), 400)
        with CFG_LOCK:
            self.cfg["password_hash"] = hash_password(new)
            self.cfg["session_epoch"] = secrets_token()   # 其它设备上的旧 cookie 立即失效
            save_config(self.cfg)
        return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                 msg_block=card_msg("密码已更新（其它设备需要重新登录）", "ok"), path=CFG_PATH),
                          extra=["Set-Cookie: " + self._cookie_header(
                              make_session(self.cfg["secret"], self.cfg["session_epoch"]),
                              SESSION_SECONDS)])

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    cfg = load_config()
    Handler.cfg = cfg
    # 后台采样：页面不打开也在攒历史，打开时立刻就有趋势可看（读 /proc，开销可忽略）
    def _sampler() -> None:
        while True:
            try:
                metrics.sample()
            except Exception:
                pass
            time.sleep(3)

    threading.Thread(target=_sampler, daemon=True).start()

    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    metrics.ensure_sampler()      # 开机就开始按固定节奏记历史，不必等有人访问
    print("lyco-control on http://{}:{}/ (config {})".format(BIND, PORT, CFG_PATH), flush=True)
    if COOKIE_DOMAIN and not SECURE_COOKIE:
        print("警告：PORTAL_COOKIE_DOMAIN={} 但 PORTAL_SECURE=0 —— 上 HTTPS 后务必改成 1"
              .format(COOKIE_DOMAIN), flush=True)
    if not cfg.get("password_hash") and cfg.get("setup_token"):
        print("首次使用：打开 /setup?t={} 设置密码（设完这条链接即失效）".format(cfg["setup_token"]),
              flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
