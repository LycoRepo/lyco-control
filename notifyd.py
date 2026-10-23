#!/usr/bin/env python3
"""lyco-notify —— 把 Lyco Control 的登录事件转成 QQ 私聊。

做法：常驻连着 OneBot 网关的 portal_notify 端点（连接一直挂着，网关那边
不会因为下游离线而刷 deny 日志），本机再开一个只绑 127.0.0.1 的 HTTP：
    POST /notify   body = 要发的文本
就把它转成 send_private_msg 发给 PORTAL_NOTIFY_TARGET 指定的 QQ。

依赖：websockets（`pip install websockets`）。
用 systemd 跑见 deploy/lyco-notify.service；PORTAL_NOTIFY_TARGET 必填。
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from websockets.sync.client import connect

WS_URL = os.environ.get("PORTAL_NOTIFY_WS", "ws://127.0.0.1:3016")
TOKEN = os.environ.get("PORTAL_NOTIFY_TOKEN", "")
LISTEN = os.environ.get("PORTAL_NOTIFY_LISTEN", "127.0.0.1:3019")
_target = os.environ.get("PORTAL_NOTIFY_TARGET", "").strip()
TARGET = int(_target) if _target.isdigit() else 0
MAX_BODY = 4096

outbox: "queue.Queue[str]" = queue.Queue(maxsize=64)
_seq = 0
_seq_lock = threading.Lock()


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def next_echo() -> str:
    global _seq
    with _seq_lock:
        _seq += 1
        return "n%d" % _seq


def sender_loop() -> None:
    """保持一条到网关的连接；有活就发，没活就排空上游事件。"""
    backoff = 1
    while True:
        try:
            with connect(WS_URL, additional_headers={"Authorization": "Bearer " + TOKEN},
                         open_timeout=8, close_timeout=3, max_size=262144) as ws:
                log("connected %s" % WS_URL)
                backoff = 1
                while True:
                    try:
                        text = outbox.get(timeout=1.0)
                    except queue.Empty:
                        text = None
                    if text is not None:
                        echo = next_echo()
                        ws.send(json.dumps({"action": "send_private_msg",
                                            "params": {"user_id": TARGET, "message": text},
                                            "echo": echo}, ensure_ascii=False))
                        deadline = time.time() + 8
                        while time.time() < deadline:
                            try:
                                raw = ws.recv(timeout=deadline - time.time())
                            except TimeoutError:
                                log("timeout waiting for echo %s" % echo)
                                break
                            try:
                                msg = json.loads(raw)
                            except ValueError:
                                continue
                            if msg.get("echo") == echo:
                                if msg.get("retcode") == 0:
                                    log("sent message_id=%s" % (msg.get("data") or {}).get("message_id"))
                                else:
                                    log("send failed: %s" % raw[:200])
                                break
                        continue
                    # 没有待发消息：收一下上游事件（直接丢掉），顺便当心跳
                    try:
                        ws.recv(timeout=1.0)
                    except TimeoutError:
                        pass
        except Exception as exc:  # 连接失败 / 断线
            log("ws error: %s: %s (retry in %ss)" % (type(exc).__name__, exc, backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


class Handler(BaseHTTPRequestHandler):
    server_version = "lyco-notify/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 – 静音默认访问日志
        pass

    def do_POST(self):
        if self.path.split("?")[0] != "/notify":
            self._reply(404, "not found")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            self._reply(413, "bad length")
            return
        body = self.rfile.read(n).decode("utf-8", "replace").strip()
        if not body:
            self._reply(400, "empty")
            return
        try:
            outbox.put_nowait(body)
        except queue.Full:
            self._reply(503, "busy")
            return
        self._reply(200, "queued")

    def do_GET(self):
        self._reply(200, "lyco-notify up")

    def _reply(self, code: int, text: str) -> None:
        data = (text + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    if TARGET <= 0:
        log("PORTAL_NOTIFY_TARGET is required: the QQ number to send notifications to")
        sys.exit(2)
    host, _, port = LISTEN.partition(":")
    threading.Thread(target=sender_loop, name="ws", daemon=True).start()
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    log("http listening on %s, target=%s" % (LISTEN, TARGET))
    srv.serve_forever()


if __name__ == "__main__":
    main()
