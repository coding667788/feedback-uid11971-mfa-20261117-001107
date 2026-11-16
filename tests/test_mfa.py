# -*- coding: utf-8 -*-
"""端到端、并发与崩溃恢复测试。

测试纪律：
* TOTP 期望值一律由独立参考实现 mfa_service.totp_reference 计算，
  绝不调用被测服务端的验证/计算函数；
* 并发断言只依据 HTTP 响应与直接读取的数据库状态；
* 多进程测试启动 >=4 个独立服务进程共享同一数据库文件。
"""

import glob
import http.client
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mfa_service import totp_reference            # 独立参考实现（服务端不 import 它）
from mfa_service.init_cmd import run_init         # 仅用于 provisioning，不是被测验证函数

TOTP_STEP = 30


# ------------------------------------------------------------------ 工具

def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_req(method, port, path, payload=None, timeout=30):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    body = json.dumps(payload) if payload is not None else None
    conn.request(method, path, body,
                 {"Content-Type": "application/json"} if body is not None else {})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


def post(port, path, payload, timeout=30):
    return http_req("POST", port, path, payload, timeout)


class ServerHandle:
    """一个独立的服务进程。"""

    def __init__(self, case, extra_env=None):
        self.case = case
        self.port = free_port()
        env = dict(os.environ)
        env["MFA_CLOCK_FILE"] = case.clock_file
        env["MFA_SYNC_DIR"] = case.sync_dir
        if extra_env:
            env.update(extra_env)
        self.log_path = os.path.join(case.tmp, "server-%d.log" % self.port)
        self.log_file = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mfa_service", "serve",
             "--db", case.db, "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=ROOT, env=env, stdout=self.log_file, stderr=subprocess.STDOUT)

    def wait_ready(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.log_file.flush()
                with open(self.log_path, "rb") as fh:
                    raise RuntimeError("服务进程提前退出:\n" + fh.read().decode("utf-8", "replace"))
            try:
                status, _ = http_req("GET", self.port, "/health", timeout=1)
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("服务进程未就绪")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.log_file.close()


class MfaTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mfa-test-")
        self.db = os.path.join(self.tmp, "mfa.db")
        self.sync_dir = os.path.join(self.tmp, "sync")
        os.makedirs(self.sync_dir)
        self.clock_file = os.path.join(self.tmp, "clock.txt")
        # 初始时钟对齐到某一步的中间，避免步边界抖动
        self.t0 = (int(time.time()) // TOTP_STEP) * TOTP_STEP + 15
        self.set_clock(self.t0)
        self.seed_file = os.path.join(self.tmp, "seed.json")
        run_init(self.db, self.seed_file)
        with open(self.seed_file, encoding="utf-8") as fh:
            self.seed = json.load(fh)
        self.servers = []

    def tearDown(self):
        for srv in self.servers:
            srv.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 时钟 ----
    def set_clock(self, value):
        with open(self.clock_file, "w", encoding="ascii") as fh:
            fh.write(str(value))

    def now(self):
        with open(self.clock_file, encoding="ascii") as fh:
            return float(fh.read().strip())

    def step(self):
        return int(self.now() // TOTP_STEP)

    # ---- 服务进程 ----
    def start_server(self, extra_env=None):
        srv = ServerHandle(self, extra_env)
        srv.wait_ready()
        self.servers.append(srv)
        return srv

    # ---- 参考计算（不触碰被测代码） ----
    def secret(self, user):
        return totp_reference.decode_secret_b32(self.seed["users"][user]["totp_secret_b32"])

    def code_at(self, user, step):
        return totp_reference.hotp(self.secret(user), step)

    def wrong_code(self, user, step):
        taken = {self.code_at(user, step - 1), self.code_at(user, step),
                 self.code_at(user, step + 1)}
        for candidate in ("000000", "000001", "000002", "000003"):
            if candidate not in taken:
                return candidate
        self.fail("无法构造错误码")

    def ensure_no_local_collision(self, user, step):
        codes = {self.code_at(user, step - 1), self.code_at(user, step),
                 self.code_at(user, step + 1)}
        if len(codes) != 3:
            self.skipTest("相邻步出现极低概率同码，跳过")

    # ---- HTTP 便捷方法 ----
    def login(self, port, user="alice", client="client-1"):
        status, body = post(port, "/login", {
            "username": user,
            "password": self.seed["users"][user]["password"],
            "client_session": client,
        })
        self.assertEqual(status, 200, body)
        return body["challenge_id"]

    def verify_totp(self, port, chal, code, user="alice", client="client-1"):
        return post(port, "/verify/totp", {
            "challenge_id": chal, "username": user,
            "client_session": client, "code": code,
        })

    def verify_recovery(self, port, chal, code, user="alice", client="client-1"):
        return post(port, "/verify/recovery", {
            "challenge_id": chal, "username": user,
            "client_session": client, "code": code,
        })

    # ---- 直接读库做断言 ----
    def db_conn(self):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        return conn

    def watermark(self, user):
        conn = self.db_conn()
        try:
            return conn.execute(
                "SELECT totp_watermark FROM users WHERE username = ?", (user,)
            ).fetchone()[0]
        finally:
            conn.close()

    def count_sessions(self):
        conn = self.db_conn()
        try:
            return conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        finally:
            conn.close()

    def challenge_status(self, chal):
        conn = self.db_conn()
        try:
            return conn.execute(
                "SELECT status FROM challenges WHERE id = ?", (chal,)).fetchone()[0]
        finally:
            conn.close()

    # ---- 并发 ----
    def run_concurrent(self, fns):
        results = [None] * len(fns)

        def wrap(i, fn):
            try:
                results[i] = fn()
            except Exception as exc:                # noqa: BLE001
                results[i] = exc

        threads = [threading.Thread(target=wrap, args=(i, fn))
                   for i, fn in enumerate(fns)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(60)
        return results


# ------------------------------------------------------------------ 参考实现自校验

class TestReference(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # RFC 6238 附录 B 的 SHA-1 测试向量（8 位值取低 6 位）
        secret = b"12345678901234567890"
        self.assertEqual(totp_reference.hotp(secret, 59 // 30), "287082")
        self.assertEqual(totp_reference.hotp(secret, 1111111109 // 30), "081804")
        self.assertEqual(totp_reference.hotp(secret, 1234567890 // 30), "005924")


# ------------------------------------------------------------------ 基本流程

class TestBasicFlow(MfaTestBase):
    def test_totp_happy_path(self):
        srv = self.start_server()
        chal = self.login(srv.port)
        status, body = self.verify_totp(srv.port, chal, self.code_at("alice", self.step()))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["session_id"])
        self.assertTrue(body["token"])
        self.assertEqual(self.count_sessions(), 1)

    def test_login_wrong_password(self):
        srv = self.start_server()
        status, _ = post(srv.port, "/login", {
            "username": "alice", "password": "wrong", "client_session": "c"})
        self.assertEqual(status, 401)

    def test_input_validation(self):
        srv = self.start_server()
        chal = self.login(srv.port)
        for bad in ["12345", "1234567", "abcdef", "１２３４５６", 123456, "", None]:
            status, body = self.verify_totp(srv.port, chal, bad)
            self.assertEqual(status, 400, (bad, body))
        status, _ = self.verify_totp(srv.port, chal, self.wrong_code("alice", self.step()))
        self.assertEqual(status, 401)


# ------------------------------------------------------------------ 窗口与水位

class TestWindowAndWatermark(MfaTestBase):
    def test_window_and_watermark(self):
        self.ensure_no_local_collision("alice", self.step())
        srv = self.start_server()
        t = self.step()
        # 窗口外：t-2 / t+2 拒绝
        status, _ = self.verify_totp(srv.port, self.login(srv.port), self.code_at("alice", t - 2))
        self.assertEqual(status, 401)
        status, _ = self.verify_totp(srv.port, self.login(srv.port), self.code_at("alice", t + 2))
        self.assertEqual(status, 401)
        # 窗口内三步按递增顺序都可接受（水位单调前进）
        for s in (t - 1, t, t + 1):
            status, body = self.verify_totp(srv.port, self.login(srv.port),
                                            self.code_at("alice", s))
            self.assertEqual(status, 200, (s, body))
        # 重放任何已消费步 → 409
        for s in (t - 1, t, t + 1):
            status, body = self.verify_totp(srv.port, self.login(srv.port),
                                            self.code_at("alice", s))
            self.assertEqual(status, 409, (s, body))
        self.assertEqual(self.watermark("alice"), t + 1)
        self.assertEqual(self.count_sessions(), 3)


class TestSameCodeMultipleSteps(MfaTestBase):
    def test_largest_step_wins(self):
        # 用参考实现离线扫描一对相邻同码步 (k, k+1)
        secret = self.secret("alice")
        start = 2_000_000_000
        found = None
        prev = totp_reference.hotp(secret, start)
        for k in range(start + 1, start + 4_000_000):
            cur = totp_reference.hotp(secret, k)
            if cur == prev and totp_reference.hotp(secret, k + 1) != cur:
                found = (k - 1, k, cur)
                break
            prev = cur
        if not found:
            self.skipTest("扫描范围内未找到相邻步同码")
        k_small, k_large, code = found
        srv = self.start_server()
        # 时钟置于 k_small：候选步 k_small-1 / k_small / k_large，命中 {k_small, k_large}
        self.set_clock(k_small * TOTP_STEP + 15)
        status, body = self.verify_totp(srv.port, self.login(srv.port), code)
        self.assertEqual(status, 200, body)
        # 必须按最大步号 k_large 记账
        self.assertEqual(self.watermark("alice"), k_large)
        # 时钟前进到 k_large+1：候选步 k_large..k_large+2，该码只命中 k_large <= 水位 → 拒绝
        self.set_clock((k_large + 1) * TOTP_STEP + 15)
        status, body = self.verify_totp(srv.port, self.login(srv.port), code)
        self.assertEqual(status, 409, body)


class TestClockRollback(MfaTestBase):
    def test_rollback_does_not_replay(self):
        t = self.step()
        # 避免极低概率的相邻同码干扰断言
        codes = {self.code_at("alice", t + d) for d in (-4, -3, -2, 0, 1, 2)}
        if len(codes) != 6:
            self.skipTest("相邻步出现极低概率同码，跳过")
        srv = self.start_server()
        # 接受未来步 t+1
        status, body = self.verify_totp(srv.port, self.login(srv.port),
                                        self.code_at("alice", t + 1))
        self.assertEqual(status, 200, body)
        self.assertEqual(self.watermark("alice"), t + 1)
        # 时钟回退 4 步
        self.set_clock((t - 4) * TOTP_STEP + 15)
        # 回退后窗口内的 t-3 同样 <= 水位 → 拒绝
        status, _ = self.verify_totp(srv.port, self.login(srv.port),
                                     self.code_at("alice", t - 3))
        self.assertEqual(status, 409)
        # 已消费的 t+1 不在回退后的窗口内 → 同样拒绝
        status, _ = self.verify_totp(srv.port, self.login(srv.port),
                                     self.code_at("alice", t + 1))
        self.assertEqual(status, 401)
        self.assertEqual(self.watermark("alice"), t + 1)
        self.assertEqual(self.count_sessions(), 1)


# ------------------------------------------------------------------ challenge 绑定

class TestChallengeBinding(MfaTestBase):
    def test_unknown_challenge(self):
        srv = self.start_server()
        status, _ = self.verify_totp(srv.port, "0" * 32, "123456")
        self.assertEqual(status, 404)

    def test_client_mismatch(self):
        srv = self.start_server()
        chal = self.login(srv.port, client="client-A")
        status, _ = self.verify_totp(srv.port, chal,
                                     self.code_at("alice", self.step()),
                                     client="client-B")
        self.assertEqual(status, 403)

    def test_user_mismatch(self):
        srv = self.start_server()
        chal = self.login(srv.port, user="alice")
        status, _ = self.verify_totp(srv.port, chal,
                                     self.code_at("alice", self.step()),
                                     user="bob")
        self.assertEqual(status, 403)

    def test_expired_challenge(self):
        srv = self.start_server()
        chal = self.login(srv.port)
        self.set_clock(self.t0 + 300)   # 超过默认 120s 有效期
        status, _ = self.verify_totp(srv.port, chal, self.code_at("alice", self.step()))
        self.assertEqual(status, 410)

    def test_cross_user_factor_not_consumed(self):
        t = self.step()
        bob_code = self.code_at("bob", t)
        alice_codes = {self.code_at("alice", t + d) for d in (-1, 0, 1)}
        if bob_code in alice_codes:
            self.skipTest("两用户同码的极低概率事件，跳过")
        srv = self.start_server()
        # 把 bob 的有效 TOTP 提交给 alice 的 challenge → 拒绝
        chal_alice = self.login(srv.port, user="alice")
        status, _ = self.verify_totp(srv.port, chal_alice, bob_code, user="alice")
        self.assertEqual(status, 401)
        # bob 的因子未被消费：bob 自己仍能用它完成认证
        chal_bob = self.login(srv.port, user="bob")
        status, body = self.verify_totp(srv.port, chal_bob, bob_code, user="bob")
        self.assertEqual(status, 200, body)
        # 同理：bob 的恢复码也不能用于 alice 的 challenge，且不被消费
        bob_rec = self.seed["users"]["bob"]["recovery_codes"][0]
        chal_alice2 = self.login(srv.port, user="alice")
        status, _ = self.verify_recovery(srv.port, chal_alice2, bob_rec, user="alice")
        self.assertEqual(status, 401)
        chal_bob2 = self.login(srv.port, user="bob")
        status, body = self.verify_recovery(srv.port, chal_bob2, bob_rec, user="bob")
        self.assertEqual(status, 200, body)


# ------------------------------------------------------------------ 恢复码

class TestRecoveryCodes(MfaTestBase):
    def test_recovery_happy_and_single_use(self):
        srv = self.start_server()
        code = self.seed["users"]["alice"]["recovery_codes"][0]
        status, body = self.verify_recovery(srv.port, self.login(srv.port), code)
        self.assertEqual(status, 200, body)
        # 同一恢复码不能再用
        status, _ = self.verify_recovery(srv.port, self.login(srv.port), code)
        self.assertEqual(status, 401)
        # 格式合法但不存在 → 401；格式非法 → 400
        status, _ = self.verify_recovery(srv.port, self.login(srv.port), "aaaa-aaaa-aaaa-aaaa")
        self.assertEqual(status, 401)
        status, _ = self.verify_recovery(srv.port, self.login(srv.port), "zzz")
        self.assertEqual(status, 400)

    def test_db_stores_only_digests(self):
        srv = self.start_server()
        status, body = self.verify_totp(srv.port, self.login(srv.port),
                                        self.code_at("alice", self.step()))
        self.assertEqual(status, 200, body)
        token = body["token"]
        raw = b""
        for suffix in ("", "-wal", "-shm"):
            path = self.db + suffix
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    raw += fh.read()
        # 恢复码明文（含归一化形式）不出现在数据库任何页面里
        for code in self.seed["users"]["alice"]["recovery_codes"]:
            self.assertNotIn(code.encode(), raw)
            self.assertNotIn(code.replace("-", "").encode(), raw)
        # Base32 密钥与完整会话令牌同样不落库
        self.assertNotIn(self.seed["users"]["alice"]["totp_secret_b32"].encode(), raw)
        self.assertNotIn(token.encode(), raw)


# ------------------------------------------------------------------ 并发：同一 challenge 两种凭据

class TestSameChallengeRace(MfaTestBase):
    def test_totp_vs_recovery_same_challenge(self):
        srv1 = self.start_server({"MFA_BARRIER": "pair:2"})
        srv2 = self.start_server({"MFA_BARRIER": "pair:2"})
        chal = self.login(srv1.port)
        code = self.code_at("alice", self.step())
        rec = self.seed["users"]["alice"]["recovery_codes"][0]
        results = self.run_concurrent([
            lambda: self.verify_totp(srv1.port, chal, code),
            lambda: self.verify_recovery(srv2.port, chal, rec),
        ])
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [200, 409], results)
        self.assertEqual(self.count_sessions(), 1)


# ------------------------------------------------------------------ 并发：>=4 进程争用同一凭据

class TestMultiProcessRaces(MfaTestBase):
    def start_four(self, barrier):
        return [self.start_server({"MFA_BARRIER": barrier}) for _ in range(4)]

    def test_same_totp_step_four_processes(self):
        self.ensure_no_local_collision("alice", self.step())
        servers = self.start_four("totp-race:4")
        chals = [self.login(servers[0].port, client="c%d" % i) for i in range(4)]
        code = self.code_at("alice", self.step())
        results = self.run_concurrent([
            (lambda i=i: self.verify_totp(servers[i].port, chals[i], code,
                                          client="c%d" % i))
            for i in range(4)
        ])
        oks = [r for r in results if r[0] == 200]
        self.assertEqual(len(oks), 1, results)
        for r in results:
            self.assertIn(r[0], (200, 409), results)
        self.assertEqual(self.count_sessions(), 1)
        self.assertEqual(self.watermark("alice"), self.step())

    def test_same_recovery_code_four_processes(self):
        servers = self.start_four("rec-race:4")
        chals = [self.login(servers[0].port, client="c%d" % i) for i in range(4)]
        rec = self.seed["users"]["alice"]["recovery_codes"][0]
        results = self.run_concurrent([
            (lambda i=i: self.verify_recovery(servers[i].port, chals[i], rec,
                                              client="c%d" % i))
            for i in range(4)
        ])
        oks = [r for r in results if r[0] == 200]
        self.assertEqual(len(oks), 1, results)
        for r in results:
            self.assertIn(r[0], (200, 401, 409), results)
        self.assertEqual(self.count_sessions(), 1)
        conn = self.db_conn()
        try:
            used = conn.execute(
                "SELECT COUNT(*) FROM recovery_codes WHERE used = 1").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(used, 1)


# ------------------------------------------------------------------ 管理员重置

class TestReset(MfaTestBase):
    def run_reset_cli(self, user="alice"):
        out = os.path.join(self.tmp, "reset-%s.json" % user)
        subprocess.run(
            [sys.executable, "-m", "mfa_service", "reset",
             "--db", self.db, "--user", user, "--seed-out", out],
            cwd=ROOT, check=True, capture_output=True, timeout=60)
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)

    def test_reset_invalidates_old_factor(self):
        srv = self.start_server()
        chal_old = self.login(srv.port)
        old_code = self.code_at("alice", self.step())
        old_rec = self.seed["users"]["alice"]["recovery_codes"][0]
        new_seed = self.run_reset_cli()
        # 旧版本未完成 challenge 立即失效
        status, _ = self.verify_totp(srv.port, chal_old, old_code)
        self.assertIn(status, (401, 409))
        # 旧恢复码失效
        status, _ = self.verify_recovery(srv.port, self.login(srv.port), old_rec)
        self.assertEqual(status, 401)
        # 旧 TOTP 密钥的码失效
        status, _ = self.verify_totp(srv.port, self.login(srv.port), old_code)
        self.assertEqual(status, 401)
        # 新因子可用（水位已随版本重置，同一步号可再次接受）
        self.seed["users"]["alice"] = new_seed["users"]["alice"]
        status, body = self.verify_totp(srv.port, self.login(srv.port),
                                        self.code_at("alice", self.step()))
        self.assertEqual(status, 200, body)
        status, body = self.verify_recovery(
            srv.port, self.login(srv.port),
            new_seed["users"]["alice"]["recovery_codes"][0])
        self.assertEqual(status, 200, body)

    def test_reset_verify_interleaving(self):
        srv = self.start_server()
        codes = list(self.seed["users"]["alice"]["recovery_codes"])
        results = []
        for i in range(6):
            client = "rr%d" % i
            chal = self.login(srv.port, client=client)
            code = codes[i]
            if i % 2 == 1:
                # 奇数轮：验证与重置并发，结果必须等价于某个完整先后顺序
                box = []
                th = threading.Thread(
                    target=lambda: box.append(
                        self.verify_recovery(srv.port, chal, code, client=client)))
                th.start()
                new_seed = self.run_reset_cli()
                th.join(30)
                codes = new_seed["users"]["alice"]["recovery_codes"]
                results.append((chal, box[0]))
            else:
                # 偶数轮：无并发重置，必须成功
                status, body = self.verify_recovery(srv.port, chal, code, client=client)
                self.assertEqual(status, 200, (i, body))
                results.append((chal, (status, body)))
        # 不变量：每个 challenge 至多一个会话；200 当且仅当恰好一个会话
        conn = self.db_conn()
        try:
            for chal, (status, _body) in results:
                n = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE challenge_id = ?",
                    (chal,)).fetchone()[0]
                self.assertLessEqual(n, 1)
                self.assertEqual(n, 1 if status == 200 else 0, (chal, status))
        finally:
            conn.close()


# ------------------------------------------------------------------ 崩溃恢复

class TestCrashRecovery(MfaTestBase):
    def pause(self, point):
        open(os.path.join(self.sync_dir, "pause_" + point), "w").close()

    def unpause(self, point):
        os.remove(os.path.join(self.sync_dir, "pause_" + point))

    def wait_reached(self, point, timeout=20):
        pattern = os.path.join(self.sync_dir, "reached_%s_*" % point)
        deadline = time.time() + timeout
        while time.time() < deadline:
            hits = glob.glob(pattern)
            if hits:
                return hits[0]
            time.sleep(0.05)
        self.fail("服务进程未到达同步点 " + point)

    @staticmethod
    def safe_call(fn, *args):
        try:
            return fn(*args)
        except Exception as exc:                    # noqa: BLE001
            return ("exception", str(exc))

    def fire_verify(self, srv, chal, code):
        box = []
        th = threading.Thread(
            target=lambda: box.append(self.safe_call(self.verify_totp, srv.port, chal, code)))
        th.start()
        return box, th

    def test_crash_after_consume_before_commit(self):
        self.ensure_no_local_collision("alice", self.step())
        self.pause("after_consume")
        srv = self.start_server()
        chal = self.login(srv.port)
        code = self.code_at("alice", self.step())
        box, th = self.fire_verify(srv, chal, code)
        self.wait_reached("after_consume")
        time.sleep(0.3)
        srv.proc.kill()                     # 真实终止：因子已消费、事务未提交
        srv.proc.wait(10)
        th.join(10)
        # 事务未提交 → 任何消费都不落库
        self.assertEqual(self.watermark("alice"), -1)
        self.assertEqual(self.challenge_status(chal), "pending")
        self.assertEqual(self.count_sessions(), 0)
        # 重启后同一验证码仍然可用，且只成功一次
        self.unpause("after_consume")
        srv2 = self.start_server()
        status, body = self.verify_totp(srv2.port, chal, code)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.count_sessions(), 1)

    def test_crash_after_commit_before_response(self):
        self.ensure_no_local_collision("alice", self.step())
        self.pause("after_commit")
        srv = self.start_server()
        chal = self.login(srv.port)
        code = self.code_at("alice", self.step())
        box, th = self.fire_verify(srv, chal, code)
        self.wait_reached("after_commit")
        time.sleep(0.3)
        srv.proc.kill()                     # 真实终止：事务已提交、响应未发出
        srv.proc.wait(10)
        th.join(10)
        # 已提交：消费与会话都已落库
        self.assertEqual(self.watermark("alice"), self.step())
        self.assertEqual(self.challenge_status(chal), "completed")
        self.assertEqual(self.count_sessions(), 1)
        self.unpause("after_commit")
        srv2 = self.start_server()
        # 客户端未收到响应而重试同一 challenge → 已使用，不能再签发第二个会话
        status, _ = self.verify_totp(srv2.port, chal, code)
        self.assertEqual(status, 409)
        # 换一个新 challenge 重放同一验证码 → 同样拒绝
        status, _ = self.verify_totp(srv2.port, self.login(srv2.port), code)
        self.assertEqual(status, 409)
        self.assertEqual(self.count_sessions(), 1)


if __name__ == "__main__":
    unittest.main()
