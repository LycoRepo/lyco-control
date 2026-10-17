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
import stat
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from string import Template
from urllib.parse import parse_qs, quote, urlparse, unquote

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
SESSION_HOURS = max(1, min(168, int(os.environ.get("PORTAL_SESSION_HOURS", "8"))))
SESSION_SECONDS = SESSION_HOURS * 3600
PBKDF2_ITERS = 200_000
MIN_PASSWORD = 10              # 密码最短长度
MAX_BODY = 256 * 1024          # 表单就几百字节，给足余量但不让人塞爆内存
CFG_LOCK = threading.Lock()    # 仅保护配置快照发布
CFG_WRITE_LOCK = threading.Lock()  # 写盘串行化，不阻塞认证读取配置快照
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
LOGIN_SEM = threading.Semaphore(2)
AUDIT_LOCK = threading.Lock()     # 审计追加与轮转串行化
PROBE_SEM = threading.BoundedSemaphore(8)
TITLE = os.environ.get("PORTAL_TITLE", "服务入口")

DEFAULT_CONFIG = {
    "secret": "",
    "password_hash": "",
    "session_epoch": "",
    "setup_token": "",
    "title": TITLE,
    # 资源曲线：窗口长度（小时）与是否用原始 6 分钟模式。UI 里能改，这里只是默认值。
    "metrics": {"hours": metrics.HISTORY_HOURS, "short": False},
    "services": [
        # 一个卡片 = 一个入口。url 是点进去的地址（可用 https://… 或站内 /detail?id=xxx）。
        # check 是服务端探活的地址（建议指向 127.0.0.1 上的真实端口）。
        # unit / log 可选：填了之后详情页会显示 systemd 状态和日志尾。
        {"id": "service-a", "name": "面板入口", "desc": "打开服务面板",
         "url": "https://panel-a.example.com/", "check": "http://127.0.0.1:8080/",
         "icon": "•", "enabled": True},
        {"id": "service-b", "name": "服务状态", "desc": "查看服务状态和最近日志",
         "url": "/detail?id=service-b", "check": "http://127.0.0.1:9090/health",
         "unit": "myservice-b.service", "log": "/var/log/myservice-b.log",
         "icon": "•", "enabled": True},
    ],
}


# ---------- 配置读写 ----------

def load_config() -> dict:
    """读配置；缺字段就补齐并落盘。第一次运行也走同一条补齐路径（否则会漏掉 setup_token）。"""
    if os.path.exists(CFG_PATH):
        if os.path.islink(CFG_PATH):
            raise ValueError("配置文件不能是符号链接")
        os.chmod(CFG_PATH, 0o600)
        with io.open(CFG_PATH, encoding="utf-8") as fh:
            cfg = json.load(fh)
    else:
        cfg = {}
    if not isinstance(cfg, dict):
        raise ValueError("配置必须是 JSON 对象")
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
    validate_config(cfg)
    if changed:
        save_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    """拒绝损坏的配置；认证配置异常时不能自动退回首次设置。"""
    for key in ("secret", "session_epoch", "password_hash", "setup_token", "title"):
        if not isinstance(cfg.get(key), str):
            raise ValueError("配置字段类型无效：" + key)
    if not isinstance(cfg.get("metrics"), dict):
        raise ValueError("指标配置必须是对象")
    hours = cfg["metrics"].get("hours", 24)
    if type(hours) is not int or not 1 <= hours <= 168 or type(cfg["metrics"].get("short", False)) is not bool:
        raise ValueError("指标时长必须为 1–168 小时，短期模式必须为布尔值")
    services = cfg.get("services")
    if not isinstance(services, list) or len(services) > 128:
        raise ValueError("卡片数量不能超过 128")
    ids = set()
    for svc in services:
        if not isinstance(svc, dict):
            raise ValueError("卡片必须是对象")
        if type(svc.get("enabled", True)) is not bool:
            raise ValueError("卡片启用状态必须为布尔值")
        for key in ("id", "name", "desc", "url", "check", "unit", "log", "icon"):
            if not isinstance(svc.get(key, ""), str):
                raise ValueError("卡片字段类型无效：" + key)
        sid = svc.get("id") or slug(svc.get("name", ""))
        if sid in ids:
            raise ValueError("卡片标识重复：" + sid)
        ids.add(sid)
        target = svc.get("check", "")
        if target and not service_status.valid_http_url(target):
            raise ValueError("探活地址必须是有效的 HTTP 或 HTTPS 地址")
        if svc.get("unit") and not service_status.valid_unit(svc["unit"]):
            raise ValueError("服务单元名称无效")


def save_config(cfg: dict) -> None:
    # 先用 0600 建文件再写：默认 umask 下临时文件可能是 0644，里面装着会话密钥
    fd, tmp = tempfile.mkstemp(prefix=".portal-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(CFG_PATH)))
    try:
        with io.open(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, CFG_PATH)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    try:                                   # 让目录项也落盘，掉电后不会回到旧文件
        dfd = os.open(os.path.dirname(os.path.abspath(CFG_PATH)) or ".", os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except (OSError, AttributeError):
        pass
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
        if (scheme != "pbkdf2" or not 100_000 <= int(iters) <= 2_000_000
                or len(salt_hex) != 32 or not re.fullmatch(r"[0-9a-f]{64}", hash_hex)):
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
        if not secret or not epoch or len(token) > 100:
            return False
        exp_s, sig = token.split(".", 1)
        if not exp_s.isascii() or not exp_s.isdigit() or int(exp_s) <= time.time():
            return False
        return hmac.compare_digest(sig, _sign(secret, "{}.{}".format(exp_s, epoch)))
    except Exception:
        return False


# ---------- 探活 ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None     # 不跟随：探活只看第一次响应，避免被当成盲 SSRF 的跳板


def probe(target: str, timeout: float = 2.5) -> dict:
    if not target:
        return {"up": None, "ms": None, "detail": "未配置探活地址"}
    if not service_status.valid_http_url(target):
        return {"up": None, "ms": None, "detail": "仅支持 HTTP 或 HTTPS"}
    started = time.monotonic()
    try:
        req = urllib.request.Request(target, method="GET", headers={"User-Agent": "panel-gate"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
        return {"up": code < 500, "ms": int((time.monotonic() - started) * 1000), "detail": "HTTP {}".format(code)}
    except urllib.error.HTTPError as exc:
        ok = exc.code < 500
        exc.close()
        return {"up": ok, "ms": int((time.monotonic() - started) * 1000), "detail": "HTTP {}".format(exc.code)}
    except Exception as exc:  # 连接失败、超时、DNS
        return {"up": False, "ms": int((time.monotonic() - started) * 1000), "detail": type(exc).__name__}


def probe_all(services: list[dict]) -> list[dict]:
    results: list[dict | None] = [None] * len(services)

    def check(idx: int, svc: dict) -> None:
        if not svc.get("check") and svc.get("unit"):
            st = service_status.unit_state(svc["unit"])
            active = None if st.get("active") in (None, "unknown") else st["active"] == "active"
            results[idx] = {"up": active, "ms": None,
                            "detail": "服务单元状态：{}".format(st.get("active") or "未知")}
            return
        results[idx] = probe(svc.get("check", ""))

    pending = iter(enumerate(services))
    pending_lock = threading.Lock()
    deadline = time.monotonic() + 4

    def run() -> None:
        try:
            while time.monotonic() < deadline:
                with pending_lock:
                    item = next(pending, None)
                if item is None:
                    break
                idx, svc = item
                if svc.get("enabled", True):
                    check(idx, svc)
        finally:
            PROBE_SEM.release()

    threads = []
    for _ in range(min(8, len(services))):
        if not PROBE_SEM.acquire(blocking=False):
            break
        th = threading.Thread(target=run, daemon=True)
        try:
            th.start()
        except RuntimeError:
            PROBE_SEM.release()
            continue
        threads.append(th)
    for th in threads:
        th.join(timeout=max(0, deadline - time.monotonic()))
    out = []
    for i, svc in enumerate(services):
        r = results[i] or {"up": None, "ms": None, "detail": "探活繁忙或超时"}
        out.append({**svc, **r})
    return out


def safe_url(u: str) -> str:
    """卡片链接只允许 http(s) 或站内绝对路径；javascript:/data: 一律丢弃。"""
    u = (u or "").strip()
    if not u:
        return ""
    if any(ord(c) < 32 or ord(c) == 127 for c in u) or "\\" in u:
        return ""
    if safe_next(u):
        return u
    return u if service_status.valid_http_url(u) else ""


def safe_next(target: str) -> bool:
    """只接受站内绝对路径：排除 //host、/\\host、以及带协议的跳转，防开放重定向。"""
    if not target or not target.startswith("/"):
        return False
    if target.startswith("//") or "\\" in target or any(ord(c) < 32 or ord(c) == 127 for c in target):
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
    return '<section class="stat-strip" aria-label="资源概览">' + body + '</section>'


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
    return '<p class="msg {}" role="status">{}</p>'.format(cls, html_mod.escape(text)) if text else ""


# ---------- 渲染 ----------

def render(template: str, **ctx) -> bytes:
    # 标题是用户可在 /admin 改的自由文本，进模板前必须转义（safe_substitute 不做 HTML 转义）
    ctx["title"] = html_mod.escape(str(ctx.get("title", TITLE)))
    if "title_attr" in ctx:
        ctx["title_attr"] = html_mod.escape(str(ctx["title_attr"]))
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
        return "在线 · {} 毫秒".format(ms) if ms is not None else "在线"
    if up is False:
        return "异常 · {}".format(detail) if detail else "异常"
    return "未探活"


def metrics_block_html(cfg: dict) -> str:
    """资源设置：保留多久、以及要不要用原来那套 6 分钟模式。"""
    mx = cfg.get("metrics") or {}
    short_checked = " checked" if mx.get("short") else ""
    hours = mx.get("hours", 24)
    st = metrics.state()
    sec = st.get("span") or 0
    if st["points"] < 2:
        headline = "正在收集数据"
    elif sec < 90:
        headline = "已记录 {} 秒".format(sec)
    elif sec < 5400:
        headline = "已记录 {} 分钟".format(round(sec / 60))
    else:
        headline = "已记录 {:.1f} 小时".format(sec / 3600)
    note = "{}。共 {} 个点，每 {} 秒聚合。服务重启可恢复，机器重启清空。".format(
        headline, st["points"], st["bucket"])
    return (
        '<form method="post" action="/admin/metrics" class="settings">'
        '<div class="settings-row">'
        '<label class="settings-label" for="mx-hours">保留时长</label>'
        '<input class="settings-input" id="mx-hours" type="number" name="hours" '
        'min="1" max="168" step="1" value="{}" required>'
        '<span class="settings-unit">小时</span>'
        '</div>'
        '<label class="check"><input type="checkbox" name="short" value="1"{}> '
        '仅保留最近 6 分钟（每 3 秒采样）</label>'
        '<p class="settings-note">{}</p>'
        '<button type="submit" class="btn primary">保存资源设置</button>'
        '</form>'
    ).format(hours, short_checked, note)


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
                name=html_mod.escape(str(svc.get("name", "未命名卡片"))),
                desc=html_mod.escape(str(svc.get("desc", ""))),
                cls=cls,
                txt=html_mod.escape(txt),
            )
        )
    return "\n".join(rows) or '<p class="empty">暂无启用的卡片，请前往入口设置。</p>'


def admin_rows(services: list[dict]) -> str:
    rows = []
    for i, svc in enumerate(services):
        checked = "checked" if svc.get("enabled", True) else ""
        rows.append(
            '<tr>'
            '<td><input type="hidden" name="id_{i}" value="{sid}">'
            '<input aria-label="卡片 {i}：图标" name="icon_{i}" value="{icon}" class="w-icon"></td>'
            '<td><input aria-label="卡片 {i}：名称" name="name_{i}" value="{name}" class="w-name"></td>'
            '<td><input aria-label="卡片 {i}：说明" name="desc_{i}" value="{desc}" class="w-desc"></td>'
            '<td><input aria-label="卡片 {i}：链接" name="url_{i}" value="{url}" class="w-url"></td>'
            '<td><input aria-label="卡片 {i}：探活地址" name="check_{i}" value="{check}" class="w-check"></td>'
            '<td><input aria-label="卡片 {i}：服务单元" name="unit_{i}" value="{unit}" class="w-unit" placeholder="服务单元名称"></td>'
            '<td><input aria-label="卡片 {i}：日志文件" name="log_{i}" value="{log}" class="w-log" placeholder="日志文件路径"></td>'
            '<td class="center"><input type="checkbox" aria-label="卡片 {i}：启用" name="enabled_{i}" {checked}></td>'
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

    def handle_one_request(self):
        # 每次请求固定一份不可变配置；keep-alive 的下一次请求重新取快照。
        with CFG_LOCK:
            self.cfg = type(self).cfg
        self._csp_nonce = secrets_token()
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError):
            self.close_connection = True

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
        cfg = type(self).cfg
        return bool(cfg.get("password_hash")) and valid_session(cfg.get("secret", ""), cfg.get("session_epoch", ""),
                             self._cookies().get(COOKIE, ""))

    def _cookie_header(self, value: str, max_age: int) -> str:
        parts = ["{}={}".format(COOKIE, value), "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age={}".format(max_age)]
        if COOKIE_DOMAIN:
            parts.append("Domain=" + COOKIE_DOMAIN)
        if SECURE_COOKIE or self._is_https():
            parts.append("Secure")
        return "; ".join(parts)

    def _want_scheme(self) -> str | None:
        """外部协议怎么判：显式 PORTAL_SECURE 最可信，其次反代覆盖写的 X-Forwarded-Proto。

        两者都没有时返回 None——此时只比主机，不拿猜出来的协议去否掉正常提交。
        """
        if SECURE_COOKIE:
            return "https"
        proto = (self.headers.get("X-Forwarded-Proto") or "").strip().lower() if self._trusted_proxy() else ""
        return proto if proto in ("http", "https") else None

    def _is_https(self) -> bool:
        return self._want_scheme() == "https"

    def _send(self, body: bytes, code: int = 200, ctype: str = "text/html; charset=utf-8", extra: list[str] | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
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
        self._security_headers()
        for h in extra or []:
            self.send_header(*h.split(": ", 1))
        self.end_headers()

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'nonce-{}'; style-src 'self' 'unsafe-inline'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".format(self._csp_nonce))

    def _body(self) -> dict:
        self._too_large = False
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            self._too_large = True
            return {}
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > MAX_BODY:
            self._too_large = True      # 负数会让 read() 一直读到 EOF，必须挡掉
            return {}
        raw = self.rfile.read(length) if length else b""
        if len(raw) != length:
            self._too_large = True
            return {}
        try:
            return {k: v[0] for k, v in parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                                               max_num_fields=2048).items()}
        except (ValueError, UnicodeError):
            self._too_large = True
            return {}

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
                return self._send(b"<h1>403</h1><p>\xe8\xaf\xb7\xe4\xbd\xbf\xe7\x94\xa8\xe6\x9c\x89\xe6\x95\x88\xe7\x9a\x84\xe5\x88\x9d\xe5\xa7\x8b\xe8\xae\xbe\xe7\xbd\xae\xe9\x93\xbe\xe6\x8e\xa5</p>", 403)
            return self._send(self.render("setup.html", error_block="",
                                          setup_token=self.cfg.get("setup_token", "")))
        if path == "/login":
            slow = parse_qs(urlparse(self.path).query).get("slow") == ["1"]
            note = card_msg("请求频繁，请稍后重试", "err") if slow else ""
            return self._send(self.render("login.html", error_block=note, next=quote(self._next())))
        if path == "/logout":
            # 登出改成 POST：GET 会被外站用一张图片或链接触发（SameSite=Lax 拦不住顶层导航）
            return self._send(b"<h1>405</h1><p>\xe8\xaf\xb7\xe7\x94\xa8\xe9\xa1\xb5\xe9\x9d\xa2\xe4\xb8\x8a\xe7\x9a\x84\xe9\x80\x80\xe5\x87\xba\xe6\x8c\x89\xe9\x92\xae</p>", 405,
                              extra=["Allow: POST"])
        if not self._logged_in():
            return self._redirect("/login?next=" + quote(self.path))
        if path == "/":
            return self._send(self.render("index.html", cards=cards_html(probe_all(self.cfg["services"])),
                                     stats_strip=stats_strip(),
                                     when=time.strftime("%Y-%m-%d %H:%M:%S")))
        if path == "/admin":
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block="", path=CFG_PATH,
                                     metrics_block=metrics_block_html(self.cfg)))
        if path == "/stats":
            return self._redirect("/")      # 资源已经并在首页，旧书签回到首页
        if path == "/api/metrics":
            metrics.ensure_sampler()
            try:
                payload = metrics.last()
            except RuntimeError:
                return self._send(b'{"error":"metrics_unavailable"}', 503, "application/json")
            payload["services"] = metrics.last_services()
            return self._send(json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                              200, "application/json; charset=utf-8",
                              extra=["Cache-Control: no-store"])
        if path == "/detail":
            qs = parse_qs(urlparse(self.path).query)
            key = (qs.get("id") or [""])[0]
            svc = next((s for s in self.cfg["services"]
                        if key and key in (s.get("name"), s.get("id"))), None)
            if not svc:
                return self._send("<h1>404 — 服务不存在</h1>".encode("utf-8"), 404)
            snap = service_status.snapshot(svc)
            st = snap["state"]
            return self._send(self.render(
                "detail.html",
                name=html_mod.escape(svc.get("name", "")),
                desc=html_mod.escape(svc.get("desc", "")),
                unit=html_mod.escape(svc.get("unit", "") or "未配置服务单元"),
                active=html_mod.escape(st["active"] or "—"),
                enabled=html_mod.escape(st["enabled"] or "—"),
                rss=st["rss"] if st["rss"] is not None else "—",
                active_cls="ok" if st["active"] == "active" else "down",
                enabled_cls="ok" if st["enabled"] == "enabled" else "unknown",
                health_cls=status_class(snap["health"]["ok"]),
                health_text="未配置" if snap["health"]["ok"] is None else ("正常" if snap["health"]["ok"] else "失败"),
                health_ok=snap["health"]["ok"],
                health_detail=html_mod.escape(snap["health"]["detail"]),
                log=html_mod.escape("\n".join(snap["log"]) or "未配置日志文件"),
            ))
        return self._send(b"<h1>404</h1>", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._body()
        if getattr(self, "_too_large", False):
            self.close_connection = True    # 残余 body 不能被当成下一个请求解析
            return self._send(b"\xe6\x8f\x90\xe4\xba\xa4\xe5\x86\x85\xe5\xae\xb9\xe8\xbf\x87\xe5\xa4\xa7", 413, "text/plain",
                              extra=["Connection: close"])
        if not self._same_origin():
            return self._send(b"\xe4\xb8\x8d\xe5\x85\x81\xe8\xae\xb8\xe8\xb7\xa8\xe7\xab\x99\xe6\x8f\x90\xe4\xba\xa4", 403, "text/plain")
        if path == "/logout":
            return self._redirect("/login", extra=["Set-Cookie: " + self._cookie_header("", 0)])
        if path == "/setup":
            if self.cfg.get("password_hash"):
                return self._redirect("/login")
            if not self._setup_allowed(form.get("t", "")):
                return self._send(b"<h1>403</h1><p>\xe8\xaf\xb7\xe4\xbd\xbf\xe7\x94\xa8\xe6\x9c\x89\xe6\x95\x88\xe7\x9a\x84\xe5\x88\x9d\xe5\xa7\x8b\xe8\xae\xbe\xe7\xbd\xae\xe9\x93\xbe\xe6\x8e\xa5</p>", 403)
            pw = form.get("password", "")
            if len(pw) < MIN_PASSWORD:
                return self._send(self.render("setup.html",
                                         error_block=card_msg("密码至少需要 {} 个字符".format(MIN_PASSWORD), "err"),
                                         setup_token=self.cfg.get("setup_token", "")), 400)
            if pw != form.get("confirm", ""):
                return self._send(self.render("setup.html", error_block=card_msg("两次输入的密码不一致", "err"),
                                         setup_token=self.cfg.get("setup_token", "")), 400)
            new_hash = hash_password(pw)
            def _apply(cfg):
                if cfg.get("password_hash") or cfg.get("setup_token") != form.get("t", ""):
                    raise ValueError("首次设置链接已失效")
                cfg["password_hash"] = new_hash
                cfg["setup_token"] = ""
                cfg["session_epoch"] = secrets_token()
            err = self._commit(_apply)
            if err:
                return self._send(self.render("setup.html",
                                         error_block=card_msg(err, "err"),
                                         setup_token=self.cfg.get("setup_token", "")), 500)
            return self._redirect("/", extra=["Set-Cookie: " + self._cookie_header(
                make_session(self.cfg["secret"], self.cfg["session_epoch"]), SESSION_SECONDS)])
        if path == "/login":
            blocked, wait = self._login_blocked()
            if blocked:
                return self._send(self.render("login.html",
                                         error_block=card_msg("尝试过多，请在 {} 秒后重试".format(wait), "err"),
                                         next=quote(form.get("next", "/"))), 429,
                                  extra=["Retry-After: {}".format(max(wait, 1))])
            if self._global_slow():
                time.sleep(2)      # 全局降速：只让人变慢，绝不把所有人挡在门外
            pw = form.get("password", "")
            # 排队也要有上限：否则大量并发请求会堆在这里等着算哈希
            if not LOGIN_SEM.acquire(blocking=False):
                return self._send(self.render("login.html",
                                         error_block=card_msg("请求频繁，请稍后重试", "err"),
                                         next=quote(form.get("next", "/"))), 503,
                                  extra=["Retry-After: 5"])
            try:
                blocked, wait = self._login_blocked()      # 排队期间可能已经被封
                if blocked:
                    return self._send(self.render("login.html",
                                             error_block=card_msg("尝试过多，请在 {} 秒后重试".format(wait), "err"),
                                             next=quote(form.get("next", "/"))), 429,
                                      extra=["Retry-After: {}".format(max(wait, 1))])
                # 三个值在同一把锁里取，避免「旧哈希 + 新 epoch」这种半新半旧的快照
                with CFG_LOCK:
                    current = type(self).cfg
                    snap_hash = current.get("password_hash", "")
                    snap_epoch = current.get("session_epoch", "")
                    snap_secret = current.get("secret", "")
                ok = verify_password(pw, snap_hash)
                if ok:
                    # 复核：验证期间改过密码就作废这次通过
                    with CFG_LOCK:
                        ok = type(self).cfg.get("session_epoch", "") == snap_epoch
            finally:
                LOGIN_SEM.release()
            self._note_login(ok)      # 只记最终结果：被作废的通过不能记成 OK
            if ok:
                target = form.get("next") or "/"
                if not safe_next(target):
                    target = "/"
                return self._redirect(target, extra=["Set-Cookie: " + self._cookie_header(
                    make_session(snap_secret, snap_epoch), SESSION_SECONDS)])
            time.sleep(0.4)
            return self._send(self.render("login.html", error_block=card_msg("密码错误", "err"),
                                     next=quote(form.get("next", "/"))), 401)
        if not self._logged_in():
            return self._redirect("/login")
        if path == "/admin/title":
            name = (form.get("title") or "").strip()[:40]
            if name:
                err = self._commit(lambda cfg: cfg.__setitem__("title", name))
                if err:
                    return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                             msg_block=card_msg(err, "err"), path=CFG_PATH,
                                             metrics_block=metrics_block_html(self.cfg)), 500)
            return self._redirect("/admin")
        if path == "/admin/services":
            return self._save_services(form)
        if path == "/admin/metrics":
            try:
                hours = int(form.get("hours") or 24)
            except ValueError:
                hours = 24
            hours = max(1, min(168, hours))
            short = (form.get("short") or "") not in ("", "0", "off", "false")
            def _apply(cfg):
                mx = cfg.setdefault("metrics", {})
                mx.pop("persist", None)                      # 旧版本留下的键，已不用
                mx["hours"] = hours
                mx["short"] = short
            err = self._commit(_apply)
            if err:
                return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                         msg_block=card_msg(err, "err"), path=CFG_PATH,
                                         metrics_block=metrics_block_html(self.cfg)), 500)
            return self._redirect("/admin")
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

        仅信任本机反代用 $remote_addr 覆盖写的 X-Client-IP；其他连接用对端地址。
        不读取 X-Forwarded-For，避免客户端伪造身份绕过限流。
        """
        raw = ((self.headers.get("X-Client-IP") or "").strip() if self._trusted_proxy() else "") or self.client_address[0]
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
        now = time.monotonic()
        with LOGIN_LOCK:
            fails, until = LOGIN_FAILS.get(self._client_ip(), (0, 0.0))
            if fails >= MAX_FAILS and now < until:
                return True, int(until - now)
        return False, 0

    def _global_slow(self) -> bool:
        with LOGIN_LOCK:
            return time.monotonic() < GLOBAL_SLOW_UNTIL

    def _note_login(self, ok: bool) -> None:
        """记一次登录结果。锁里只动内存计数；审计写盘在锁外。"""
        global GLOBAL_SLOW_UNTIL
        ip = self._client_ip()
        now = time.monotonic()
        with LOGIN_LOCK:
            if ok:
                LOGIN_FAILS.pop(ip, None)
                GLOBAL_FAILS.clear()
                GLOBAL_SLOW_UNTIL = 0.0
            else:
                fails, until = LOGIN_FAILS.get(ip, (0, 0.0))
                if fails < MAX_FAILS and until <= now:
                    fails = 0
                fails += 1
                if fails >= MAX_FAILS:
                    fails = min(fails, MAX_FAILS + 6)
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
                with AUDIT_LOCK:      # 并发登录撞上轮转会把刚保留的 .1 覆盖掉
                    if os.path.exists(LOGIN_LOG) and os.path.getsize(LOGIN_LOG) > 1024 * 1024:
                        os.replace(LOGIN_LOG, LOGIN_LOG + ".1")
                    fd = os.open(LOGIN_LOG, os.O_APPEND | os.O_WRONLY | os.O_CREAT
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o600)
                    with io.open(fd, "a", encoding="utf-8") as fh:
                        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                            raise OSError("审计日志不是普通文件")
                        os.chmod(LOGIN_LOG, 0o600)
                        fh.write(line)
                return
            except Exception as exc:
                print("audit write failed: {} | {}".format(type(exc).__name__, line.strip()), flush=True)
                return
        print(line.rstrip(), flush=True)

    def _same_origin(self) -> bool:
        """浏览器发起的跨站 POST 要挡掉：Origin（其次 Referer）的主机必须与 Host 一致。

        SameSite=Lax 只挡跨站，同父域下的兄弟子域仍算 same-site，所以这里再核一次主机。
        缺少来源头时拒绝；脚本调用也须显式提供本入口的 Origin。
        """
        ref = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not ref:
            return False
        try:
            origin = urlparse(ref)
            host = (self.headers.get("Host", "") or "").lower()
            if origin.scheme not in ("http", "https") or origin.username is not None or origin.netloc.lower() != host:
                return False
            # 协议不同也算跨源（防止 https 页面被 http 提交）；判不出来就只比主机
            want = self._want_scheme()
            return True if want is None else (origin.scheme or want).lower() == want
        except Exception:
            return False

    def _trusted_proxy(self) -> bool:
        # 默认仅信任本机反代；远程反代需通过网络隔离或本机转发接入。
        return ipaddress.ip_address(self.client_address[0]).is_loopback

    def render(self, template: str, **ctx) -> bytes:
        """模板渲染：标题优先用配置里改过的名字，没改过才用环境变量。"""
        title = self.cfg.get("title") or TITLE
        # 标题是用户可改的自由文本：这里只给原文，转义统一在模板渲染时做（否则会转两次）
        ctx.setdefault("title", title)
        ctx.setdefault("title_attr", title)
        ctx.setdefault("brand_mark", html_mod.escape(brand_mark(title)))
        if "path" in ctx:
            ctx["path"] = html_mod.escape(str(ctx["path"]))
        if "next" in ctx:
            # 隐藏字段保存实际目标；URL 编码只用于 Location 查询串。
            ctx["next"] = html_mod.escape(unquote(ctx["next"]))
        return render(template, **ctx).replace(b"<script>", ('<script nonce="' + self._csp_nonce + '">').encode("ascii"))

    def _setup_allowed(self, given: str | None = None) -> bool:
        """首次设密码必须有 setup_token。

        链接里的 ?t= 和表单里的隐藏字段都认：表单 action 是 /setup（不带查询串），
        只看查询串的话第一次提交必然 403，谁都设不成密码。
        """
        if given is None:
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
        rel = unquote(path[len("/static/"):])
        if "\\" in rel or "\x00" in rel:
            return self._send(b"400", 400, "text/plain")
        root = os.path.realpath(STATIC_DIR)
        full = os.path.realpath(os.path.join(root, rel))
        try:
            inside = os.path.commonpath([root, full]) == root
        except ValueError:
            inside = False
        if "\\" in rel or "\x00" in rel or not inside:
            return self._send(b"\xe8\xaf\xb7\xe6\xb1\x82\xe6\x97\xa0\xe6\x95\x88", 400, "text/plain")
        if not os.path.isfile(full):
            return self._send(b"\xe6\x96\x87\xe4\xbb\xb6\xe4\xb8\x8d\xe5\xad\x98\xe5\x9c\xa8", 404, "text/plain")
        ext = os.path.splitext(full)[1].lower()
        ctype = {".css": "text/css", ".js": "application/javascript", ".svg": "image/svg+xml",
                 ".png": "image/png", ".ico": "image/x-icon"}.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._send(b"404", 404, "text/plain")
        return self._send(body, 200, ctype)

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
        err = self._commit(lambda cfg: cfg.__setitem__("services", services))
        if err:
            return self._send(self.render("admin.html", rows=admin_rows(services),
                                     msg_block=card_msg(err, "err"), path=CFG_PATH,
                                     metrics_block=metrics_block_html(self.cfg)), 500)
        return self._send(self.render("admin.html", rows=admin_rows(services),
                                 msg_block=card_msg("卡片设置已保存", "ok"), path=CFG_PATH, metrics_block=metrics_block_html(self.cfg)))

    def _commit(self, mutate) -> str | None:
        """改配置：先在副本上改、成功写盘，再发布到运行态。

        之前是「先改内存再写盘」，写盘失败时运行中的密码/配置已经变了，重启又退回旧值，
        旧密码会在重启后重新可用。
        """
        with CFG_WRITE_LOCK:
            with CFG_LOCK:
                current = type(self).cfg
            if self.cfg.get("session_epoch") != current.get("session_epoch"):
                return "认证配置已更新，请重新登录"
            new_cfg = copy.deepcopy(current)
            try:
                mutate(new_cfg)
                validate_config(new_cfg)
                save_config(new_cfg)
            except ValueError as exc:
                return str(exc)
            except Exception as exc:
                return "保存配置失败：{}".format(type(exc).__name__)
            # 不修改已发布的字典，避免读线程混用不同版本的密钥与配置。
            mx = new_cfg["metrics"]
            metrics.configure(hours=mx.get("hours", 24), short=bool(mx.get("short")))
            with CFG_LOCK:
                type(self).cfg = new_cfg
                self.cfg = new_cfg
        return None

    def _save_password(self, form: dict):
        old = form.get("old", "")
        new = form.get("new", "")
        if not verify_password(old, self.cfg.get("password_hash", "")):
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("原密码错误", "err"), path=CFG_PATH, metrics_block=metrics_block_html(self.cfg)), 401)
        if len(new) < MIN_PASSWORD:
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("新密码至少需要 {} 个字符".format(MIN_PASSWORD), "err"),
                                     path=CFG_PATH, metrics_block=metrics_block_html(self.cfg)), 400)
        if new != form.get("confirm", ""):
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg("两次输入的密码不一致", "err"), path=CFG_PATH, metrics_block=metrics_block_html(self.cfg)), 400)
        new_hash = hash_password(new)
        def _apply(cfg):
            if cfg["password_hash"] != self.cfg["password_hash"]:
                raise ValueError("密码已更新，请重新登录")
            cfg["password_hash"] = new_hash
            cfg["session_epoch"] = secrets_token()        # 其它设备上的旧 cookie 立即失效
        err = self._commit(_apply)
        if err:
            return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                     msg_block=card_msg(err, "err"), path=CFG_PATH,
                                     metrics_block=metrics_block_html(self.cfg)), 500)
        return self._send(self.render("admin.html", rows=admin_rows(self.cfg["services"]),
                                 msg_block=card_msg("密码已更新，其他设备需重新登录", "ok"), path=CFG_PATH, metrics_block=metrics_block_html(self.cfg)),
                          extra=["Set-Cookie: " + self._cookie_header(
                              make_session(self.cfg["secret"], self.cfg["session_epoch"]),
                              SESSION_SECONDS)])

    def log_message(self, fmt, *args):
        pass


class PortalServer(ThreadingHTTPServer):
    """限制活动连接数；慢连接和登录排队不能无限创建线程。"""

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main() -> None:
    cfg = load_config()
    Handler.cfg = cfg
    # 窗口长度与落盘开关先应用（来自配置，可在 /admin 改），再起采样线程。
    # 只留 metrics 里那一个线程：两处各起一个会让采样节奏变成 1.5 秒。
    mx = cfg.get("metrics") or {}
    mx.pop("persist", None)                                  # 旧版本留下的键，已不用
    metrics.configure(hours=int(mx.get("hours") or 24), short=bool(mx.get("short")))
    metrics.ensure_sampler()

    srv = PortalServer((BIND, PORT), Handler)
    print("lyco-control on http://{}:{}/ (config {})".format(BIND, PORT, CFG_PATH), flush=True)
    if COOKIE_DOMAIN and not SECURE_COOKIE:
        print("警告：PORTAL_COOKIE_DOMAIN={} 但 PORTAL_SECURE=0 —— 上 HTTPS 后务必改成 1"
              .format(COOKIE_DOMAIN), flush=True)
    if not cfg.get("password_hash") and cfg.get("setup_token"):
        print("首次使用：打开 /setup?t={} 设置密码（设完这条链接即失效）".format(cfg["setup_token"]),
              flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
