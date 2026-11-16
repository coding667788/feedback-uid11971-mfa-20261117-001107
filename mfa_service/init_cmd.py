"""初始化命令：建库、预置本地测试用户、TOTP 密钥与一次性恢复码。

预置的测试凭据（第一因素，仅用于本地测试，不做注册）：
    alice / password-alice-123
    bob   / password-bob-123

TOTP 密钥与恢复码只在初始化输出（seed JSON）中出现一次；
服务运行日志绝不包含它们。
"""

import base64
import json
import os
import secrets
import sys

from . import core, db

DEFAULT_USERS = {
    "alice": "password-alice-123",
    "bob": "password-bob-123",
}


def _insert_user(conn, username, password):
    pw_salt = secrets.token_bytes(16)
    secret = secrets.token_bytes(20)
    cur = conn.execute(
        "INSERT INTO users (username, password_salt, password_hash, totp_secret,"
        " factor_version, totp_watermark) VALUES (?,?,?,?,1,-1)",
        (username, pw_salt, core.hash_password(password, pw_salt), secret))
    user_id = cur.lastrowid
    codes = []
    for _ in range(core.RECOVERY_CODE_COUNT):
        code = core.make_recovery_code()
        salt = secrets.token_bytes(16)
        conn.execute(
            "INSERT INTO recovery_codes (user_id, factor_version, salt, digest, used)"
            " VALUES (?,?,?,?,0)",
            (user_id, 1, salt, core.recovery_digest(salt, core.normalize_recovery(code))))
        codes.append(code)
    return {
        "password": password,
        "totp_secret_b32": base64.b32encode(secret).decode("ascii"),
        "recovery_codes": codes,
        "factor_version": 1,
    }


def run_init(db_path, seed_out=None, force=False):
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db_path + suffix):
            if not force:
                raise SystemExit("数据库已存在: %s（使用 --force 覆盖）" % db_path)
            os.remove(db_path + suffix)
    conn = db.connect(db_path)
    try:
        db.init_schema(conn)
        seed = {"users": {}}
        for username, password in DEFAULT_USERS.items():
            seed["users"][username] = _insert_user(conn, username, password)
    finally:
        conn.close()
    text = json.dumps(seed, indent=2, ensure_ascii=False)
    if seed_out:
        with open(seed_out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("初始化完成 db=%s seed=%s" % (db_path, seed_out), file=sys.stderr)
    else:
        print(text)
    return seed
