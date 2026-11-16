"""HTTP 服务：仅使用标准库 http.server，多进程部署时每个进程独立运行本模块。

日志纪律：访问日志与事件日志只包含方法、路径、状态、用户名、challenge id、
session id；绝不输出 TOTP 密钥、验证码、恢复码或完整会话令牌
（这些只出现在请求体/响应体里，而请求体从不进日志）。
"""

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from . import core, db
from .syncpoints import SyncPoints, make_clock

log = logging.getLogger("mfa_service")

MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "MfaService/1.0"

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise core.ApiError(400, "bad_request")
        if length <= 0 or length > MAX_BODY:
            raise core.ApiError(400, "bad_request")
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise core.ApiError(400, "bad_request")
        if not isinstance(data, dict):
            raise core.ApiError(400, "bad_request")
        return data

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        try:
            payload = self._read_json()
            result = self._route(payload)
            self._send(200, {"ok": True, **result})
        except core.ApiError as exc:
            self._send(exc.status, {"ok": False, "error": exc.error})
        except Exception:
            log.exception("internal error method=POST path=%s", self.path)
            self._send(500, {"ok": False, "error": "internal"})

    def _route(self, p):
        cfg = self.server.cfg
        conn = db.connect(cfg.db_path)
        try:
            if self.path == "/login":
                challenge_id = core.create_challenge(
                    conn, p.get("username"), p.get("password"),
                    p.get("client_session"), cfg.clock, cfg.challenge_ttl)
                log.info("login ok user=%s challenge=%s", p.get("username"), challenge_id)
                return {"challenge_id": challenge_id}
            if self.path == "/verify/totp":
                res = core.verify_totp(
                    conn, p.get("challenge_id"), p.get("username"),
                    p.get("client_session"), p.get("code"), cfg.clock, cfg.sync)
                log.info("verify totp ok challenge=%s session=%s",
                         p.get("challenge_id"), res["session_id"])
                return res
            if self.path == "/verify/recovery":
                res = core.verify_recovery(
                    conn, p.get("challenge_id"), p.get("username"),
                    p.get("client_session"), p.get("code"), cfg.clock, cfg.sync)
                log.info("verify recovery ok challenge=%s session=%s",
                         p.get("challenge_id"), res["session_id"])
                return res
            raise core.ApiError(404, "not_found")
        finally:
            conn.close()

    def log_message(self, fmt, *args):
        # 只记录请求行（方法+路径），请求体（含验证码/恢复码）永不进日志
        log.info("%s %s", self.address_string(), fmt % args)


def run_server(db_path, host, port):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    httpd.cfg = SimpleNamespace(
        db_path=db_path,
        clock=make_clock(),
        sync=SyncPoints.from_env(),
        challenge_ttl=float(os.environ.get("MFA_CHALLENGE_TTL", "120")),
    )
    log.info("listening host=%s port=%d db=%s pid=%d", host, port, db_path, os.getpid())
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
