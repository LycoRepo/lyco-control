"""服务状态采集：只读 systemd / /proc / 本地 HTTP，供门户的详情页使用。

不依赖任何第三方库；也不是必须的 —— 卡片没有配置 unit / log 时，详情页只显示探活结果。
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def valid_http_url(url: str) -> bool:
    try:
        if any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
            return False
        parts = urlsplit(url)
        return (parts.scheme in ("http", "https") and bool(parts.hostname)
                and parts.username is None and parts.password is None
                and (parts.port is None or 1 <= parts.port <= 65535))
    except ValueError:
        return False


def valid_unit(unit: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:\\-]{0,254}", unit))


def unit_state(unit: str) -> dict:
    """返回 systemd 单元的状态与主进程 RSS（MB）。不是 systemd 环境时返回 unknown。"""
    if not unit or not valid_unit(unit):
        return {"active": None, "enabled": None, "rss": None}
    out = {"active": None, "enabled": None, "rss": None}
    try:
        # 一次命令取齐属性，避免每张卡片串行等待三个超时。
        res = subprocess.run(["systemctl", "show", "--no-pager", "-p", "ActiveState",
                              "-p", "UnitFileState", "-p", "MainPID", "--", unit],
                             capture_output=True, timeout=3, text=True, errors="replace")
        props = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
        out["active"] = props.get("ActiveState") or "unknown"
        out["enabled"] = props.get("UnitFileState") or "unknown"
        pid = props.get("MainPID", "")
        if pid.isdigit() and os.path.isdir("/proc/" + pid):
            with open("/proc/{}/status".format(pid), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        out["rss"] = int(line.split()[1]) // 1024
                        break
    except Exception:
        out["active"] = out["active"] or "unknown"
        out["enabled"] = out["enabled"] or "unknown"
    return out


MAX_TAIL_BYTES = 256 * 1024      # 只从尾部读这么多，别把整个日志读进内存


def tail(path: str, n: int = 14) -> list[str]:
    """读日志的最后 n 行：从文件尾部按块往回读，不整份加载。"""
    if not path:
        return []
    try:
        # 先以非阻塞方式打开，再检查同一描述符，避免日志轮转时的检查/打开竞态。
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return ["（不是普通日志文件）"]
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            start = max(0, size - MAX_TAIL_BYTES)
            fh.seek(start)
            data = fh.read(MAX_TAIL_BYTES)
        text = data.decode("utf-8", "replace")
        lines = text.splitlines()
        if start > 0 and lines:
            lines = lines[1:]                 # 第一行可能被截断，丢掉
        return lines[-max(1, min(n, 1000)):]
    except Exception as exc:
        return ["（读不到日志：{}）".format(type(exc).__name__)]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def health(url: str, timeout: float = 3.0) -> dict:
    if not url:
        return {"ok": None, "detail": "未配置"}
    if not valid_http_url(url):
        return {"ok": None, "detail": "探活地址无效"}
    try:
        # 与卡片探活一致：只看响应头，不跟随跳转，也不展示可能包含凭据的响应正文。
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(url, timeout=timeout) as resp:
            return {"ok": resp.status < 500, "detail": "HTTP {}".format(resp.status)}
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        return {"ok": code < 500, "detail": "HTTP {}".format(code)}
    except Exception as exc:
        return {"ok": False, "detail": "{}".format(type(exc).__name__)}


def snapshot(service: dict) -> dict:
    """一个卡片的详情快照。"""
    return {
        "state": unit_state(service.get("unit", "")),
        "health": health(service.get("check", "")),
        "log": tail(service.get("log", "")),
    }
