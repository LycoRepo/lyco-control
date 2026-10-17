"""本机资源占用采集：只用标准库读 /proc 与 statvfs，不依赖任何监控组件。

设计取舍：
- CPU / 网络是「两次采样的差值」，所以进程内保留上一次的时间戳；
- 历史放在内存环形缓冲里，进程重启即清空（这是看「最近几分钟」的面板，不做长期存储）。
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque

BUCKET_SECONDS = 60        # 历史按分钟聚合：3 秒一采，一分钟一个点
HISTORY_LEN = 24 * 60      # 1440 个点 → 24 小时
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
    # 写进当前这一分钟的桶：同一分钟内的采样做平均，跨分钟才新增一个点
    minute = int(now // BUCKET_SECONDS) * BUCKET_SECONDS
    if history and history[-1]["ts"] == minute:
        b = history[-1]
        n = b["n"] + 1
        b["cpu"] = (b["cpu"] * (n - 1) + item["cpu"]) / n
        b["mem_pct"] = (b["mem_pct"] * (n - 1) + item["mem_pct"]) / n
        b["rx_kbs"] = (b["rx_kbs"] * (n - 1) + item["rx_kbs"]) / n
        b["tx_kbs"] = (b["tx_kbs"] * (n - 1) + item["tx_kbs"]) / n
        b["n"] = n
    else:
        history.append({"ts": minute, "cpu": item["cpu"], "mem_pct": item["mem_pct"],
                        "rx_kbs": item["rx_kbs"], "tx_kbs": item["tx_kbs"], "n": 1})

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
        "history": [
            {"ts": b["ts"], "cpu": round(b["cpu"], 2), "mem_pct": round(b["mem_pct"], 2),
             "rx_kbs": round(b["rx_kbs"], 1), "tx_kbs": round(b["tx_kbs"], 1)}
            for b in history
        ],
    }
    _latest = result
    return result


SAMPLER_INTERVAL = 3.0     # 后端自己按这个节奏采样，与有多少客户端访问无关
_sampler_started = False


def _sampler_loop() -> None:
    while True:
        try:
            sample()
        except Exception:
            pass
        time.sleep(SAMPLER_INTERVAL)


def ensure_sampler() -> None:
    """启动后台采样线程；重复调用无副作用。

    历史必须按固定节奏记录：早先的实现是「每次请求记一个点」，于是标签页开两个、
    或者有人直接 curl 接口，点数攒得比时间快，120 个点只覆盖两三分钟。
    """
    global _sampler_started
    if _sampler_started:
        return
    _sampler_started = True
    threading.Thread(target=_sampler_loop, name="metrics-sampler", daemon=True).start()


def last() -> dict:
    """取最近一次采样结果；还没采过就现采一次。不推进历史（页面渲染用）。"""
    if _latest is None:
        return sample()
    return _latest


# ---------- 按服务/容器拆分（cgroup v2） ----------

CGROUP_ROOT = "/sys/fs/cgroup/system.slice"
NAMES_PATH = "/var/lib/lyco-portal-ceil/containers.json"   # 由 lyco-container-names.timer 生成
_prev_cg: dict[str, tuple[float, int]] = {}


def _read_int(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except Exception:
        return 0


def _cg_cpu_usec(directory: str) -> int:
    try:
        with open(os.path.join(directory, "cpu.stat"), "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0


def _container_names() -> dict[str, str]:
    try:
        with open(NAMES_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def services(limit: int = 8) -> list[dict]:
    """按 cgroup 统计每个服务/容器的内存与 CPU 占用，按内存降序取前 limit 个。

    CPU 是两次调用的差值，所以第一次调用会全是 0（页面每 3 秒调一次，很快就正常）。
    """
    names = _container_names()
    now = time.time()
    cores = os.cpu_count() or 1
    try:
        entries = os.listdir(CGROUP_ROOT)
    except OSError:
        return []

    total_mb = _meminfo().get("MemTotal", 0) / 1024.0 or 1.0
    rows = []
    for entry in entries:
        is_container = entry.startswith("docker-") and entry.endswith(".scope")
        is_unit = entry.endswith(".service")
        if not (is_container or is_unit):
            continue
        directory = os.path.join(CGROUP_ROOT, entry)
        mem = _read_int(os.path.join(directory, "memory.current"))
        if mem <= 0:
            continue
        if is_container:
            cid = entry[len("docker-"):-len(".scope")]
            label = names.get(cid) or cid[:12]
            kind = "container"
        else:
            label = entry[:-len(".service")]
            kind = "service"
            if label.startswith(("systemd-", "user@", "getty@", "cron", "dbus", "polkit")):
                continue

        usec = _cg_cpu_usec(directory)
        prev = _prev_cg.get(entry)
        cpu_pct = 0.0
        if prev is not None:
            dt = now - prev[0]
            if dt > 0.2:
                cpu_pct = max(0.0, (usec - prev[1]) / 1e6 / dt / cores * 100.0)
        _prev_cg[entry] = (now, usec)

        mem_mb = round(mem / 1048576.0, 1)
        rows.append({
            "name": label,
            "kind": kind,
            "mem_mb": mem_mb,
            "mem_pct": round(100.0 * mem_mb / total_mb, 1),
            "cpu": round(min(cpu_pct, 100.0 * cores), 1),
        })

    rows.sort(key=lambda r: r["mem_mb"], reverse=True)
    return rows[:limit]
