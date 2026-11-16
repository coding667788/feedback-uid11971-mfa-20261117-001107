"""SQLite 连接与 schema。

多进程一致性完全依赖 SQLite 自身的事务/文件锁机制：
所有写路径使用 ``BEGIN IMMEDIATE``，SQLite 保证同一时刻全库只有一个写事务，
因此 4 个（或更多）独立服务进程共享同一数据库文件时，因子消费天然串行化，
不需要任何单进程锁。
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_salt   BLOB NOT NULL,
    password_hash   BLOB NOT NULL,
    totp_secret     BLOB NOT NULL,
    factor_version  INTEGER NOT NULL,
    -- 当前因子版本内已接受的最大 TOTP 步号（水位），只保存整数，绝不保存验证码字符串
    totp_watermark  INTEGER NOT NULL DEFAULT -1
);

CREATE TABLE IF NOT EXISTS challenges (
    id              TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    client_session  TEXT NOT NULL,
    factor_version  INTEGER NOT NULL,
    expires_at      REAL NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending / completed / failed
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    factor_version  INTEGER NOT NULL,
    salt            BLOB NOT NULL,
    digest          BLOB NOT NULL,                     -- sha256(salt || 归一化恢复码)
    used            INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    challenge_id    TEXT NOT NULL UNIQUE REFERENCES challenges(id),  -- 一个 challenge 至多一个会话
    user_id         INTEGER NOT NULL REFERENCES users(id),
    token_hash      TEXT NOT NULL,                     -- 只存令牌摘要，不落明文
    created_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_challenges_user ON challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id, factor_version, used);
"""


def connect(db_path):
    """新建一个连接（每个请求/命令一个连接，线程间不共享）。"""
    conn = sqlite3.connect(db_path, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_schema(conn):
    conn.executescript(SCHEMA)
