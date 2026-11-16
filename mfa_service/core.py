"""核心业务逻辑。

一致性设计要点：

* 因子消费 + challenge 完成 + 登录会话创建，全部在同一个
  ``BEGIN IMMEDIATE`` 事务内完成；SQLite 写锁把跨进程的并发写串行化，
  因此不同 challenge 争用同一 TOTP 步 / 同一恢复码时最多成功一次。
* TOTP 按（用户， 因子版本）保存“已接受水位”——已消费的最大步号，
  只接受严格更大的步号；只存整数，绝不保存验证码字符串。
  时钟回退后，回退窗口内的步号都 <= 水位，天然被拒绝。
* 恢复码只存 sha256(salt || 归一化码)，消费即在同一事务里置 used=1。
* 管理员重置递增 factor_version 并重置水位，旧版本的未完成 challenge
  与恢复码在同一事务里失效；重置事务与验证事务由 SQLite 写锁串行化，
  任何交错都等价于某个完整先后顺序。
"""

import hashlib
import hmac
import secrets
import uuid

from . import totp

TOTP_STEP_SECONDS = totp.STEP_SECONDS
TOTP_WINDOW = 1                 # 检查前一、当前、后一共 3 步
PBKDF2_ITERATIONS = 200_000
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # 去掉易混淆字符
RECOVERY_GROUPS = (4, 4, 4, 4)
RECOVERY_CODE_COUNT = 8


class ApiError(Exception):
    """携带 HTTP 状态码与机器可读错误码的业务异常。"""

    def __init__(self, status, error, message=""):
        super().__init__(message or error)
        self.status = status
        self.error = error


# ---------------------------------------------------------------- 基础工具

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def make_recovery_code() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(sum(RECOVERY_GROUPS)))
    parts, i = [], 0
    for group in RECOVERY_GROUPS:
        parts.append(raw[i:i + group])
        i += group
    return "-".join(parts)


def normalize_recovery(code):
    """归一化恢复码；非法输入返回 None。"""
    if not isinstance(code, str):
        return None
    norm = code.strip().lower().replace("-", "").replace(" ", "")
    if len(norm) != sum(RECOVERY_GROUPS):
        return None
    if any(c not in RECOVERY_ALPHABET for c in norm):
        return None
    return norm


def recovery_digest(salt: bytes, norm: str) -> bytes:
    return hashlib.sha256(salt + norm.encode("ascii")).digest()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _require_str(**fields):
    for name, value in fields.items():
        if not isinstance(value, str) or not value:
            raise ApiError(400, "bad_request", "字段缺失或类型错误: " + name)


def _rollback_quietly(conn):
    try:
        conn.execute("ROLLBACK")
    except Exception:
        pass


# ---------------------------------------------------------------- 第一因素

def create_challenge(conn, username, password, client_session, clock, challenge_ttl):
    """第一因素（本地测试口令）通过后签发短期 challenge。

    challenge 绑定用户、客户端会话与当前因子版本。
    """
    _require_str(username=username, password=password, client_session=client_session)
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        hash_password(password, b"\x00" * 16)   # 均匀耗时，避免用户枚举
        raise ApiError(401, "invalid_credentials")
    if not hmac.compare_digest(hash_password(password, user["password_salt"]),
                               user["password_hash"]):
        raise ApiError(401, "invalid_credentials")
    now = clock()
    challenge_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO challenges (id, user_id, client_session, factor_version,"
        " expires_at, status, created_at) VALUES (?,?,?,?,?,'pending',?)",
        (challenge_id, user["id"], client_session, user["factor_version"],
         now + challenge_ttl, now))
    return challenge_id


def _load_challenge(conn, challenge_id, username, client_session, clock):
    """在写事务内加载并校验 challenge 的全部绑定关系。"""
    ch = conn.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    if ch is None:
        raise ApiError(404, "challenge_not_found")
    user = conn.execute("SELECT * FROM users WHERE id = ?", (ch["user_id"],)).fetchone()
    if user["username"] != username:
        raise ApiError(403, "user_mismatch", "challenge 不属于该用户")
    if ch["client_session"] != client_session:
        raise ApiError(403, "client_mismatch", "challenge 不属于该客户端会话")
    if ch["status"] != "pending":
        raise ApiError(409, "already_used", "challenge 已完成或已失效")
    if clock() > ch["expires_at"]:
        raise ApiError(410, "challenge_expired")
    if ch["factor_version"] != user["factor_version"]:
        raise ApiError(409, "factor_reset", "因子已重置，challenge 失效")
    return ch, user


def _complete_challenge(conn, ch, user, clock, sync):
    """在因子已消费的同一事务里完成 challenge 并创建登录会话。"""
    sync.pause("after_consume")   # 测试钩子：因子已消费、事务未提交
    cur = conn.execute(
        "UPDATE challenges SET status = 'completed' WHERE id = ? AND status = 'pending'",
        (ch["id"],))
    if cur.rowcount != 1:
        raise ApiError(409, "already_used")
    session_id = uuid.uuid4().hex
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (id, challenge_id, user_id, token_hash, created_at)"
        " VALUES (?,?,?,?,?)",
        (session_id, ch["id"], user["id"], token_digest(token), clock()))
    return session_id, token


# ---------------------------------------------------------------- 第二因素：TOTP

def verify_totp(conn, challenge_id, username, client_session, code, clock, sync):
    _require_str(challenge_id=challenge_id, username=username, client_session=client_session)
    # 输入必须是恰好 6 位 ASCII 数字（全角数字等一律拒绝）
    if not (isinstance(code, str) and len(code) == 6 and code.isascii() and code.isdigit()):
        raise ApiError(400, "bad_code_format", "TOTP 必须是恰好 6 位 ASCII 数字")
    sync.barrier()                # 测试钩子：多进程对齐竞争点（在事务外）
    conn.execute("BEGIN IMMEDIATE")
    try:
        ch, user = _load_challenge(conn, challenge_id, username, client_session, clock)
        now_step = totp.step_for_time(clock())
        candidates = (now_step - TOTP_WINDOW, now_step, now_step + TOTP_WINDOW)
        matching = [s for s in candidates
                    if totp.totp_code(user["totp_secret"], s) == code]
        if not matching:
            raise ApiError(401, "invalid_code")
        step = max(matching)      # 多个候选步碰巧同码时，按最大步号判断
        if step <= user["totp_watermark"]:
            raise ApiError(409, "already_used", "该 TOTP 步已被消费")
        cur = conn.execute(
            "UPDATE users SET totp_watermark = ?"
            " WHERE id = ? AND factor_version = ? AND totp_watermark < ?",
            (step, user["id"], user["factor_version"], step))
        if cur.rowcount != 1:
            raise ApiError(409, "already_used")
        session_id, token = _complete_challenge(conn, ch, user, clock, sync)
        conn.execute("COMMIT")
    except BaseException:
        _rollback_quietly(conn)
        raise
    sync.pause("after_commit")    # 测试钩子：事务已提交、响应未发出
    return {"session_id": session_id, "token": token}


# ---------------------------------------------------------------- 第二因素：恢复码

def verify_recovery(conn, challenge_id, username, client_session, code, clock, sync):
    _require_str(challenge_id=challenge_id, username=username, client_session=client_session)
    norm = normalize_recovery(code)
    if norm is None:
        raise ApiError(400, "bad_code_format", "恢复码格式非法")
    sync.barrier()
    conn.execute("BEGIN IMMEDIATE")
    try:
        ch, user = _load_challenge(conn, challenge_id, username, client_session, clock)
        rows = conn.execute(
            "SELECT id, salt, digest FROM recovery_codes"
            " WHERE user_id = ? AND factor_version = ? AND used = 0",
            (user["id"], user["factor_version"])).fetchall()
        matched = None
        for row in rows:
            if hmac.compare_digest(recovery_digest(row["salt"], norm), row["digest"]):
                matched = row
                break
        if matched is None:
            raise ApiError(401, "invalid_code")
        cur = conn.execute("UPDATE recovery_codes SET used = 1 WHERE id = ? AND used = 0",
                           (matched["id"],))
        if cur.rowcount != 1:
            raise ApiError(409, "already_used")
        session_id, token = _complete_challenge(conn, ch, user, clock, sync)
        conn.execute("COMMIT")
    except BaseException:
        _rollback_quietly(conn)
        raise
    sync.pause("after_commit")
    return {"session_id": session_id, "token": token}


# ---------------------------------------------------------------- 管理员重置

def reset_user(conn, username):
    """递增因子版本：旧版本的未完成 challenge 与全部恢复码立即失效。

    整个重置是一个 ``BEGIN IMMEDIATE`` 事务，与任何进行中的验证事务
    由 SQLite 写锁串行化，交错结果必然等价于某个完整先后顺序。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            raise ApiError(404, "user_not_found")
        new_version = user["factor_version"] + 1
        new_secret = secrets.token_bytes(20)
        conn.execute(
            "UPDATE users SET factor_version = ?, totp_secret = ?, totp_watermark = -1"
            " WHERE id = ?",
            (new_version, new_secret, user["id"]))
        conn.execute(
            "UPDATE challenges SET status = 'failed' WHERE user_id = ? AND status = 'pending'",
            (user["id"],))
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        codes = []
        for _ in range(RECOVERY_CODE_COUNT):
            code = make_recovery_code()
            salt = secrets.token_bytes(16)
            conn.execute(
                "INSERT INTO recovery_codes (user_id, factor_version, salt, digest, used)"
                " VALUES (?,?,?,?,0)",
                (user["id"], new_version, salt,
                 recovery_digest(salt, normalize_recovery(code))))
            codes.append(code)
        conn.execute("COMMIT")
    except BaseException:
        _rollback_quietly(conn)
        raise
    return new_version, new_secret, codes
