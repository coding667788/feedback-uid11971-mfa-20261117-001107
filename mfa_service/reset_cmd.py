"""管理员重置命令：递增用户因子版本。

在同一事务里：轮换 TOTP 密钥、重置 TOTP 水位、作废旧版本全部未完成
challenge、删除旧恢复码并签发新恢复码。与服务进程并发时由 SQLite
写锁保证串行化。
"""

import base64
import json
import sys

from . import core, db
from .init_cmd import DEFAULT_USERS


def run_reset(db_path, username, seed_out=None):
    conn = db.connect(db_path)
    try:
        db.init_schema(conn)
        new_version, new_secret, codes = core.reset_user(conn, username)
    finally:
        conn.close()
    seed = {"users": {username: {
        "password": DEFAULT_USERS.get(username, "<unchanged>"),
        "totp_secret_b32": base64.b32encode(new_secret).decode("ascii"),
        "recovery_codes": codes,
        "factor_version": new_version,
    }}}
    text = json.dumps(seed, indent=2, ensure_ascii=False)
    if seed_out:
        with open(seed_out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("重置完成 user=%s factor_version=%d seed=%s"
              % (username, new_version, seed_out), file=sys.stderr)
    else:
        print(text)
    return seed
