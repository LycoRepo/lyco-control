"""安全、配置发布与指标边界的标准库回归测试；不访问服务器或真实 /proc。"""
import copy
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import app
import metrics
import service_status


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=app.ROOT)
        self.cfg_path = os.path.join(self.tmp.name, "portal.json")
        self.path_patch = patch.object(app, "CFG_PATH", self.cfg_path)
        self.path_patch.start()
        self.handler = type("TestHandler", (app.Handler,), {})
        self.handler.cfg = copy.deepcopy(app.DEFAULT_CONFIG)
        self.handler.cfg.update(secret="s" * 64, session_epoch="e" * 64,
                                setup_token="t" * 64, services=[])
        self.server = app.PortalServer(("127.0.0.1", 0), self.handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        with app.LOGIN_LOCK:
            app.LOGIN_FAILS.clear()
            app.GLOBAL_FAILS.clear()
            app.GLOBAL_SLOW_UNTIL = 0

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.path_patch.stop()
        self.tmp.cleanup()

    def request(self, path, body=None, origin=True, cookie=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        hdr = dict(headers or {})
        if origin:
            hdr["Origin"] = self.origin if origin is True else origin
        if cookie:
            hdr["Cookie"] = app.COOKIE + "=" + cookie
        conn.request("POST" if body is not None else "GET", path, body=body, headers=hdr)
        res = conn.getresponse()
        result = res.status, dict(res.getheaders()), res.read()
        conn.close()
        return result

    def authenticate(self):
        self.handler.cfg = {**self.handler.cfg, "password_hash": app.hash_password("password123")}
        return app.make_session(self.handler.cfg["secret"], self.handler.cfg["session_epoch"])

    def test_csrf_requires_matching_origin(self):
        token = self.authenticate()
        self.assertEqual(self.request("/admin/title", "title=changed", origin=False, cookie=token)[0], 403)
        self.assertEqual(self.request("/admin/title", "title=changed", origin="http://evil.example", cookie=token)[0], 403)
        self.assertEqual(self.request("/admin/title", "title=changed", cookie=token)[0], 302)
        self.assertEqual(self.handler.cfg["title"], "changed")

    def test_concurrent_setup_only_one_wins(self):
        barrier = threading.Barrier(2)
        real_hash = app.hash_password

        def slow_hash(password):
            result = real_hash(password)
            barrier.wait(timeout=5)
            return result

        body = "t=" + self.handler.cfg["setup_token"] + "&password=password123&confirm=password123"
        with patch.object(app, "hash_password", side_effect=slow_hash), ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.request("/setup", body), range(2)))
        self.assertEqual(sum(status == 302 for status, _, _ in results), 1)
        self.assertEqual(self.handler.cfg["setup_token"], "")

    def test_password_change_revokes_old_cookie(self):
        token = self.authenticate()
        status, headers, _ = self.request("/admin/password", "old=password123&new=newpassword123&confirm=newpassword123", cookie=token)
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)
        self.assertEqual(self.request("/auth", cookie=token)[0], 401)
        current = headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
        self.assertEqual(self.request("/auth", cookie=current)[0], 200)

    def test_failed_save_keeps_published_config(self):
        token = self.authenticate()
        before = self.handler.cfg
        with patch.object(app, "save_config", side_effect=OSError("disk full")):
            self.assertEqual(self.request("/admin/title", "title=changed", cookie=token)[0], 500)
        self.assertIs(self.handler.cfg, before)

    def test_next_round_trip_and_escaping(self):
        token = self.authenticate()
        body = "password=password123&next=%2Fdetail%3Fid%3Da%26x%3D1"
        self.assertEqual(self.request("/login", body)[1]["Location"], "/detail?id=a&x=1")
        self.handler.cfg = {**self.handler.cfg, "title": '<img src=x onerror="alert(1)">'}
        html = self.request("/admin", cookie=token)[2].decode()
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;img', html)

    def test_script_nonce_and_template_placeholders(self):
        token = self.authenticate()
        for path in ("/", "/admin", "/login"):
            status, headers, body = self.request(path, cookie=token)
            self.assertEqual(status, 200)
            html = body.decode()
            for name in ("$rows", "$metrics_block", "$msg_block", "$path", "$when", "$title", "$title_attr", "$cards", "$stats_strip"):
                self.assertNotIn(name, html)
            nonce = headers["Content-Security-Policy"].split("'nonce-", 1)[1].split("'", 1)[0]
            self.assertNotIn("<script>", html)
            if "<script " in html:
                self.assertIn('<script nonce="' + nonce + '">', html)
            self.assertEqual(headers["Cache-Control"], "no-store")

    def test_invalid_framing_and_static_paths(self):
        self.assertEqual(self.request("/login", "", headers={"Content-Length": "bad"})[0], 413)
        self.assertEqual(self.request("/static/%2e%2e/app.py")[0], 400)
        self.assertEqual(self.request("/static/%00")[0], 400)
        self.assertEqual(self.request("/static/style.css")[0], 200)


class BoundaryTests(unittest.TestCase):
    def test_urls_sessions_and_units(self):
        for url in ("javascript:alert(1)", "/\\evil.example", "//evil.example", "/\t/evil"):
            self.assertFalse(app.safe_url(url))
        self.assertFalse(service_status.valid_http_url("http://[broken"))
        self.assertFalse(service_status.valid_unit("--help"))
        self.assertFalse(service_status.valid_unit("*.service"))
        self.assertFalse(app.valid_session("", "", app.make_session("", "")))
        self.assertFalse(app.valid_session("secret", "epoch", "1.bad"))

    def test_atomic_save_cleans_failed_temp(self):
        with tempfile.TemporaryDirectory(dir=app.ROOT) as tmp, patch.object(app, "CFG_PATH", os.path.join(tmp, "cfg.json")):
            app.save_config({"old": True})
            with patch.object(app.os, "replace", side_effect=OSError("full")):
                with self.assertRaises(OSError):
                    app.save_config({"new": True})
            self.assertEqual(json.loads(Path(app.CFG_PATH).read_text()), {"old": True})
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    def test_metrics_sampling_and_copy_isolation(self):
        vfs = type("VFS", (), dict(f_blocks=100, f_bfree=40, f_bavail=30, f_frsize=1024))()
        with patch.multiple(metrics, history=deque(maxlen=60), _latest=None, _last_cpu=None,
                            _last_net=None, PERSIST=False, HISTORY_HOURS=1, HISTORY_LEN=60,
                            BUCKET_SECONDS=60, _last_error=None, _svc_error=None, _persist_error=None), \
                patch.object(metrics, "_cpu_times", side_effect=[(20, 100), (70, 200)]), \
                patch.object(metrics, "_meminfo", return_value={"MemTotal": 1000, "MemAvailable": 400}), \
                patch.object(metrics.os, "statvfs", return_value=vfs, create=True), \
                patch.object(metrics.os, "getloadavg", return_value=(1, 2, 3), create=True), \
                patch.object(metrics, "_read", return_value="3600 0"), \
                patch.object(metrics, "_net_bytes", side_effect=[{"eth0": (1000, 2000)}, {"eth0": (4072, 5072), "eth1": (999999, 999999)}]), \
                patch.object(metrics.time, "monotonic", side_effect=[10, 10, 13, 13]):
            metrics.sample()
            data = metrics.sample()
            self.assertEqual(data["cpu"], 50)
            self.assertEqual(data["rx_kbs"], 1)
            self.assertEqual(data["disk"]["used_gb"], 0)
            self.assertEqual(data["disk"]["pct"], 66.7)
        # 切换模式和读快照不能触发采样或让调用者改动已发布数据。
        with patch.multiple(metrics, history=deque([{"ts": 60, "cpu": 1, "mem_pct": 2, "rx_kbs": 3, "tx_kbs": 4, "n": 1}], maxlen=60),
                            _latest={"mem": {"used_mb": 5}}, _last_ok=time.monotonic(),
                            _svc_ok=time.monotonic(), BUCKET_SECONDS=60, SHORT_MODE=False):
            data = metrics.last()
            data["mem"]["used_mb"] = 99
            self.assertEqual(metrics.last()["mem"]["used_mb"], 5)
            metrics.configure(short=True)
            self.assertEqual(metrics.last()["history"], [])

    def test_log_tail_bounds(self):
        with tempfile.TemporaryDirectory(dir=app.ROOT) as tmp:
            path = Path(tmp, "log")
            path.write_bytes(b"x" * (service_status.MAX_TAIL_BYTES + 10) + b"\nlast\n")
            self.assertEqual(service_status.tail(str(path), 1), ["last"])

    def test_service_command_and_health_status(self):
        output = type("Result", (), {"stdout": "ActiveState=active\nUnitFileState=enabled\nMainPID=0\n"})()
        with patch.object(service_status.subprocess, "run", return_value=output) as run:
            state = service_status.unit_state("example.service")
            self.assertEqual(state["active"], "active")
            self.assertEqual(run.call_args.kwargs["timeout"], 3)
            self.assertIn("--", run.call_args.args[0])
        with patch.object(service_status.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = service_status.urllib.error.HTTPError("http://localhost/", 403, "Forbidden", {}, None)
            self.assertTrue(service_status.health("http://localhost/")["ok"])

    def test_concurrent_history_configuration(self):
        point = {"ts": int(time.time()), "cpu": 1, "mem_pct": 2, "rx_kbs": 3, "tx_kbs": 4, "n": 1}
        with patch.multiple(metrics, history=deque([point], maxlen=60), _latest={"ts": point["ts"]},
                            HISTORY_HOURS=1, HISTORY_LEN=60, BUCKET_SECONDS=60, SHORT_MODE=False):
            def configure():
                for i in range(100):
                    metrics.configure(hours=1 + i % 3, short=bool(i % 2))

            def read():
                for _ in range(200):
                    self.assertGreaterEqual(metrics.state()["span"], 0)
                    metrics.last()
                    metrics.last_services()

            with ThreadPoolExecutor(3) as pool:
                jobs = [pool.submit(configure), pool.submit(read), pool.submit(read)]
                for job in jobs:
                    job.result(timeout=10)


if __name__ == "__main__":
    unittest.main()
