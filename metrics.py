"""本机资源占用采集：只用标准库读 /proc 与 statvfs，不依赖任何监控组件。

设计取舍：
- CPU / 网络是「两次采样的差值」，所以进程内保留上一次的时间戳；
- 历史放在内存环形缓冲里，进程重启即清空（这是看「最近几分钟」的面板，不做长期存储）。
"""
from __future__ import annotations

import os
import time
from collections import deque

HISTORY_LEN = 120          # 3 秒一次 → 约 6 分钟
_last_cpu: tuple[int, int] | None = None   # (busy, total)
_last_net: tuple[float, int, int] | None = None  # (ts, rx, tx)
_last_sample_ts = 0.0
_latest: dict | None = None

history: deque[dict] = deque(maxlen=HISTORY_LEN)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _cpu_times() -> tuple[int, int]:
    """返回 (忙碌 jiffies, 总 jiffies)。"""
    parts = _read("/proc/stat").splitlines()[0].split()
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)      # idle + iowait
    total = sum(nums[:8])
    return total - idle, total


def _meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        out[key] = int(rest.split()[0])      # kB
    return out


def _net_bytes() -> tuple[int, int]:
    rx = tx = 0
    for line in _read("/proc/net/dev").splitlines()[2:]:
        iface, _, data = line.partition(":")
        if iface.strip() == "lo":
            continue
        cols = data.split()
        rx += int(cols[0])
        tx += int(cols[8])
    return rx, tx


def sample() -> dict:
    """采一次样，返回当前值（同时把历史推入环形缓冲）。"""
    global _last_cpu, _last_net, _last_sample_ts, _latest
    now = time.time()

    busy, total = _cpu_times()
    cpu_pct = 0.0
    if _last_cpu is not None:
        d_busy = busy - _last_cpu[0]
        d_total = total - _last_cpu[1]
        if d_total > 0:
            cpu_pct = max(0.0, min(100.0, 100.0 * d_busy / d_total))
    _last_cpu = (busy, total)

    mi = _meminfo()
    total_kb = mi.get("MemTotal", 0)
    avail_kb = mi.get("MemAvailable", mi.get("MemFree", 0))
    used_kb = max(0, total_kb - avail_kb)
    swap_total_kb = mi.get("SwapTotal", 0)
    swap_free_kb = mi.get("SwapFree", 0)
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)

    st = os.statvfs("/")
    disk_total = st.f_blocks * st.f_frsize
    disk_free = st.f_bavail * st.f_frsize
    disk_used = disk_total - disk_free

    rx, tx = _net_bytes()
    rx_kbs = tx_kbs = 0.0
    if _last_net is not None:
        dt = now - _last_net[0]
        if dt > 0.5:
            rx_kbs = (rx - _last_net[1]) / 1024.0 / dt
            tx_kbs = (tx - _last_net[2]) / 1024.0 / dt
    _last_net = (now, rx, tx)

    load1, load5, load15 = os.getloadavg()
    uptime_s = float(_read("/proc/uptime").split()[0])

    mem_pct = 100.0 * used_kb / total_kb if total_kb else 0.0
    item = {
        "ts": int(now),
        "cpu": round(cpu_pct, 1),
        "mem_pct": round(mem_pct, 1),
        "swap_pct": round(100.0 * swap_used_kb / swap_total_kb, 1) if swap_total_kb else 0.0,
        "rx_kbs": round(rx_kbs, 1),
        "tx_kbs": round(tx_kbs, 1),
    }
    history.append(item)

    result = {
        **item,
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "uptime_h": round(uptime_s / 3600.0, 1),
        "mem": {
            "total_mb": round(total_kb / 1024.0),
            "used_mb": round(used_kb / 1024.0),
            "avail_mb": round(avail_kb / 1024.0),
            "swap_total_mb": round(swap_total_kb / 1024.0),
            "swap_used_mb": round(swap_used_kb / 1024.0),
        },
        "disk": {
            "total_gb": round(disk_total / 1024 ** 3, 1),
            "used_gb": round(disk_used / 1024 ** 3, 1),
            "free_gb": round(disk_free / 1024 ** 3, 1),
            "pct": round(100.0 * disk_used / disk_total, 1) if disk_total else 0.0,
        },
        "history": list(history),
    }
    _latest = result
    return result


def last() -> dict:
    """取最近一次采样结果；还没采过就现采一次。不推进历史（页面渲染用）。"""
    if _latest is None:
        return sample()
    return _latest
