"""服务端 TOTP 计算（被测实现）。

RFC 6238：HMAC-SHA1，T0=0，30 秒步长，6 位数字。
测试中的期望值不来自这里，而来自独立的 totp_reference 模块。
"""

import hashlib
import hmac
import struct

STEP_SECONDS = 30
T0 = 0


def totp_code(secret: bytes, step: int) -> str:
    """计算指定步号的 6 位 TOTP 码。"""
    msg = struct.pack(">Q", step)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return "%06d" % (value % 1000000)


def step_for_time(now: float) -> int:
    return int((now - T0) // STEP_SECONDS)
