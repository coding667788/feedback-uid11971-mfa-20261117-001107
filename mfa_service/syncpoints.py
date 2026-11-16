"""可注入时钟与可控同步点（测试钩子）。

全部通过环境变量启用；正常部署不设置这些变量时完全关闭，不影响行为：

* ``MFA_CLOCK_FILE``  —— 指向一个只含 Unix 时间戳的文件，服务端每次需要
  当前时间时读它（而不是 time.time()），测试可随意拨动/回退时钟。
* ``MFA_SYNC_DIR``    —— 同步点目录。目录内存在 ``pause_<point>`` 控制文件时，
  服务进程到达对应代码点会写入 ``reached_<point>_<pid>`` 并等待
  ``resume_<point>`` 出现（或控制文件被删除）。支持的 point：
  ``after_consume``（因子已消费、事务未提交）、``after_commit``（事务已提交、
  响应未发出）。
* ``MFA_BARRIER``     —— 形如 ``<name>:<count>``，验证请求在进入数据库事务前
  等待目录下凑齐 count 个 ``bar_<name>_*`` 到达文件，用于让多个进程精确对齐
  竞争点。
"""

import glob
import os
import time


class SyncPoints:
    def __init__(self, sync_dir=None, barrier_spec=None):
        self.sync_dir = sync_dir
        self.barrier_name = None
        self.barrier_count = 0
        if barrier_spec:
            name, _, count = barrier_spec.partition(":")
            self.barrier_name = name
            self.barrier_count = int(count)

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        return cls(environ.get("MFA_SYNC_DIR") or None,
                   environ.get("MFA_BARRIER") or None)

    def barrier(self, timeout=30.0):
        """多进程对齐屏障：在进入事务前调用，凑齐 count 个进程后同时放行。"""
        if not self.sync_dir or not self.barrier_name:
            return
        path = os.path.join(self.sync_dir, "bar_%s_%d" % (self.barrier_name, os.getpid()))
        with open(path, "w") as fh:
            fh.write(str(os.getpid()))
        pattern = os.path.join(self.sync_dir, "bar_%s_*" % self.barrier_name)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(glob.glob(pattern)) >= self.barrier_count:
                return
            time.sleep(0.02)
        raise TimeoutError("barrier %s 等待超时" % self.barrier_name)

    def pause(self, point, timeout=120.0):
        """可控暂停点：仅当控制文件存在时生效，供崩溃测试在精确位置终止进程。"""
        if not self.sync_dir:
            return
        control = os.path.join(self.sync_dir, "pause_" + point)
        if not os.path.exists(control):
            return
        reached = os.path.join(self.sync_dir, "reached_%s_%d" % (point, os.getpid()))
        with open(reached, "w") as fh:
            fh.write(str(os.getpid()))
        resume = os.path.join(self.sync_dir, "resume_" + point)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(resume) or not os.path.exists(control):
                return
            time.sleep(0.05)


def make_clock(environ=None):
    """返回一个获取当前 Unix 时间的函数；设置 MFA_CLOCK_FILE 时为可注入时钟。"""
    environ = os.environ if environ is None else environ
    path = environ.get("MFA_CLOCK_FILE")
    if path:
        def clock():
            with open(path, "r", encoding="ascii") as fh:
                return float(fh.read().strip())
        return clock
    return time.time
