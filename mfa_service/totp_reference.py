"""独立参考 TOTP 实现（RFC 4226 / RFC 6238）。

本模块刻意不复用被测服务端的任何代码：HMAC-SHA1 按 RFC 2104 手工构造，
动态截断按 RFC 4226 手工实现，用于测试时独立计算期望值，
以及作为命令行工具手工核对：

    python -m mfa_service.totp_reference --secret-b32 <BASE32> [--time UNIX | --step N]
"""

import argparse
import base64
import hashlib
import struct
import time

STEP_SECONDS = 30
T0 = 0


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def hotp(secret: bytes, counter: int) -> str:
    """RFC 4226 HOTP，6 位数字。HMAC-SHA1 按 RFC 2104 手工构造。"""
    block = 64  # SHA-1 分组长度
    key = secret
    if len(key) > block:
        key = _sha1(key)
    key = key + b"\x00" * (block - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    mac = _sha1(opad + _sha1(ipad + struct.pack(">Q", counter)))
    # RFC 4226 动态截断
    offset = mac[19] & 0x0F
    bin_code = ((mac[offset] & 0x7F) << 24
                | mac[offset + 1] << 16
                | mac[offset + 2] << 8
                | mac[offset + 3])
    return "%06d" % (bin_code % 1000000)


def totp(secret: bytes, for_time: float = None, step_seconds: int = STEP_SECONDS) -> str:
    """RFC 6238 TOTP，T0=0，默认 30 秒步长。"""
    if for_time is None:
        for_time = time.time()
    return hotp(secret, int((for_time - T0) // step_seconds))


def decode_secret_b32(text: str) -> bytes:
    cleaned = text.strip().replace(" ", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m mfa_service.totp_reference",
        description="独立参考 TOTP 实现（与被测服务端代码无共享）")
    parser.add_argument("--secret-b32", required=True, help="Base32 编码的 TOTP 密钥")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--time", type=float, default=None, help="Unix 时间戳（默认当前时间）")
    group.add_argument("--step", type=int, default=None, help="直接指定步号")
    args = parser.parse_args(argv)
    secret = decode_secret_b32(args.secret_b32)
    if args.step is not None:
        print(hotp(secret, args.step))
    else:
        print(totp(secret, args.time))


if __name__ == "__main__":
    main()
