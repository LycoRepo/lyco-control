"""服务状态采集：只读 systemd / /proc / 本地 HTTP，供门户的详情页使用。

不依赖任何第三方库；也不是必须的 —— 卡片没有配置 unit / log 时，详情页只显示探活结果。
"""
from __future__ import annotations

import os
import subprocess
import urllib.request


def unit_state(unit: str) -> dict:
    """返回 systemd 单元的状态与主进程 RSS（MB）。不是 systemd 环境时返回 unknown。"""
    if not unit:
        return {"active": None, "enabled": None, "rss": None}
    out = {"active": None, "enabled": None, "rss": None}
    for flag, key in (("is-active", "active"), ("is-enabled", "enabled")):
        try:
            res = subprocess.run(["systemctl", flag, unit], capture_output=True, timeout=5, text=True)
            out[key] = (res.stdout or "").strip() or "unknown"
        except Exception:
            out[key] = "unknown"
    try:
        res = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                             capture_output=True, timeout=5, text=True)
        pid = (res.stdout or "").strip()
        if pid.isdigit() and os.path.isdir("/proc/" + pid):
            with open("/proc/{}/status".format(pid), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        out["rss"] = int(line.split()[1]) // 1024
                        break
    except Exception:
        pass
    return out


def tail(path: str, n: int = 14) -> list[str]:
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in fh.readlines()[-n:]]
    except Exception as exc:
        return ["（读不到日志：{}）".format(type(exc).__name__)]


def health(url: str, timeout: float = 3.0) -> dict:
    if not url:
        return {"ok": None, "detail": "未配置"}
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
        return {"ok": True, "detail": body[:2000]}
    except Exception as exc:
        return {"ok": False, "detail": "{}".format(type(exc).__name__)}


def snapshot(service: dict) -> dict:
    """一个卡片的详情快照。"""
    return {
        "state": unit_state(service.get("unit", "")),
        "health": health(service.get("check", "")),
        "log": tail(service.get("log", "")),
    }
