# 本地多因素认证服务（TOTP + 恢复码）

仅使用 **Windows 原生 Python 3.12 标准库 + SQLite**，仅需 CPU。
不使用 Docker、外部身份服务或任何现成 MFA 组件。

核心目标：TOTP 与恢复码在**多进程竞争**下都只能完成**一次**有效认证。

## 目录结构

```
mfa_service/
  __main__.py        # 命令行入口：python -m mfa_service <init|serve|reset>
  init_cmd.py        # 初始化命令：建库、预置测试用户/密钥/恢复码
  reset_cmd.py       # 管理员重置命令：递增因子版本
  serve.py           # HTTP 服务（http.server，每进程独立运行）
  core.py            # 业务逻辑：challenge、TOTP/恢复码校验、原子事务
  db.py              # SQLite 连接与 schema
  totp.py            # 服务端 TOTP 计算（被测实现）
  totp_reference.py  # 独立参考 TOTP 实现（手工 HMAC-SHA1，与服务端零共享）
  syncpoints.py      # 可注入时钟与可控同步点（测试钩子）
tests/
  test_mfa.py        # 21 个自动化测试（含 4 进程并发与真实杀进程崩溃测试）
run_tests.cmd        # Windows 一键运行测试
```

## 快速开始（Windows）

```bat
REM 1. 初始化数据库（预置 alice / bob 两个测试用户，seed 含密钥与恢复码，只输出一次）
python -m mfa_service init --db mfa.db --seed-out seed.json

REM 2. 启动服务（可重复启动多个进程，共享同一 mfa.db）
python -m mfa_service serve --db mfa.db --port 8080
python -m mfa_service serve --db mfa.db --port 8081

REM 3. 用独立参考实现计算当前 TOTP（与服务端代码零共享）
python -m mfa_service.totp_reference --secret-b32 <seed.json 中的 totp_secret_b32>

REM 4. 第一因素：登录换取 challenge（预置测试口令 alice / password-alice-123）
curl -X POST http://127.0.0.1:8080/login -H "Content-Type: application/json" ^
  -d "{\"username\":\"alice\",\"password\":\"password-alice-123\",\"client_session\":\"my-client\"}"

REM 5. 第二因素：TOTP 或恢复码完成 challenge，签发登录会话
curl -X POST http://127.0.0.1:8080/verify/totp -H "Content-Type: application/json" ^
  -d "{\"challenge_id\":\"<challenge_id>\",\"username\":\"alice\",\"client_session\":\"my-client\",\"code\":\"123456\"}"
curl -X POST http://127.0.0.1:8080/verify/recovery -H "Content-Type: application/json" ^
  -d "{\"challenge_id\":\"<challenge_id>\",\"username\":\"alice\",\"client_session\":\"my-client\",\"code\":\"xxxx-xxxx-xxxx-xxxx\"}"

REM 6. 管理员重置（递增因子版本，旧 challenge/恢复码/密钥立即失效）
python -m mfa_service reset --db mfa.db --user alice --seed-out new-seed.json
```

## HTTP API

| 方法 | 路径 | 请求体 | 成功响应 |
|---|---|---|---|
| POST | `/login` | `{username, password, client_session}` | `{challenge_id}` |
| POST | `/verify/totp` | `{challenge_id, username, client_session, code}` | `{session_id, token}` |
| POST | `/verify/recovery` | 同上（code 为恢复码） | `{session_id, token}` |
| GET | `/health` | — | `{ok: true}` |

错误码：`400` 格式非法（TOTP 必须恰好 6 位 ASCII 数字）、`401` 凭据/验证码错误、
`403` 跨用户或跨客户端、`404` challenge 不存在、`409` 已消费/已重置、
`410` challenge 过期（默认 120 秒，`MFA_CHALLENGE_TTL` 可调）。

## 一致性设计

- **原子提交**：因子消费（水位推进 / 恢复码置 used）+ challenge 完成 +
  登录会话创建，全部在同一个 `BEGIN IMMEDIATE` 事务内提交。
  SQLite 写锁把跨进程写事务串行化，因此不同 challenge 争用同一 TOTP 步或
  同一恢复码时最多成功一次——不依赖任何单进程锁。
- **TOTP 水位**：按（用户， 因子版本）保存已接受的最大步号（整数，绝不存
  验证码字符串），只接受严格更大的步号。检查窗口为前一/当前/后一共 3 步；
  多个候选步碰巧同码时按最大步号记账。时钟回退后窗口内的步号都 ≤ 水位，
  已消费或更早的步号不会被重新放行。
- **challenge 绑定**：绑定用户、客户端会话、因子版本与过期时间；
  不存在/过期/跨用户/跨客户端一律拒绝，且不会消费另一个用户的因子。
- **恢复码**：`secrets` 随机生成，数据库只存 `sha256(salt ‖ 归一化码)`。
- **会话**：`sessions.challenge_id` 有 UNIQUE 约束，一个 challenge 在数据库
  层面至多一个会话；令牌只存 SHA-256 摘要。
- **重置**：单事务内递增 `factor_version`、轮换密钥、水位归零、作废旧版本
  全部未完成 challenge 与恢复码；与验证事务由写锁串行化，任何交错都等价于
  某个完整先后顺序。

## 测试钩子（可注入时钟 / 可控同步点）

通过环境变量启用，正常部署不设置即完全关闭：

| 变量 | 作用 |
|---|---|
| `MFA_CLOCK_FILE` | 指向含 Unix 时间戳的文件，服务端以此代替系统时钟（可任意拨动/回退） |
| `MFA_SYNC_DIR` | 同步点目录；存在 `pause_after_consume` / `pause_after_commit` 控制文件时，进程在对应点（消费后未提交 / 提交后未响应）暂停并写 `reached_*` 文件 |
| `MFA_BARRIER` | 形如 `name:count`，验证请求在进事务前等待 count 个进程对齐，制造精确竞争 |

## 运行测试

```bat
run_tests.cmd
REM 或：
python -m unittest discover -s tests -v
```

测试纪律：TOTP 期望值一律由独立参考实现 `totp_reference` 计算，
并发断言只依据 HTTP 响应与直接读取的数据库状态，均不调用被测验证函数。

## 日志纪律

服务日志只含方法、路径、状态、用户名、challenge id、session id；
**绝不输出** TOTP 密钥、验证码、恢复码或完整会话令牌（请求体不进日志）。
密钥与恢复码仅在 `init`/`reset` 命令的 seed 输出中出现一次。

## 测试结果（2026-11-17，Windows 11 + Python 3.12.8 + SQLite 3.45.3）

`python -m unittest discover -s tests`：**21 个测试全部通过（OK，约 28 秒）**。

| 类别 | 测试 | 结果 |
|---|---|---|
| 参考实现自校验 | RFC 6238 附录 B 向量 | 通过 |
| 基本流程 | TOTP 成功认证、错误口令、输入格式校验（含全角数字） | 通过 |
| 窗口与水位 | t±2 拒绝、t-1/t/t+1 依次接受、重放全部 409、水位=t+1 | 通过 |
| 同码多步 | 离线扫描真实相邻同码步，验证按最大步号记账 | 通过 |
| 时钟回退 | 接受未来步 t+1 后回退 4 步，t-3 与 t+1 均不再放行 | 通过 |
| challenge 绑定 | 不存在 404 / 跨客户端 403 / 跨用户 403 / 过期 410 / 跨用户因子不消费 | 通过 |
| 恢复码 | 一次性使用、错误码 401、库中无明文（密钥/恢复码/令牌） | 通过 |
| 同一 challenge 两种凭据竞争 | 2 进程屏障对齐，恰好 1×200 + 1×409，1 个会话 | 通过 |
| 4 进程争用同一 TOTP 步 | 恰好 1 成功、1 会话、水位只推进一次 | 通过 |
| 4 进程争用同一恢复码 | 恰好 1 成功、1 会话、仅 1 行 used=1 | 通过 |
| 管理员重置 | 旧 challenge/恢复码/密钥立即失效，新因子可用 | 通过 |
| 重置与验证交错 | 6 轮交错，不变量：每 challenge ≤1 会话，200 ⇔ 恰好 1 会话 | 通过 |
| 崩溃：消费后未提交杀进程 | 重启后无任何消费落库，同码可再用且仅成功一次 | 通过 |
| 崩溃：提交后未响应杀进程 | 重试返回 409，不会签发第二个会话 | 通过 |

未完成项：无。另做了命令行冒烟验证（init→serve→login→verify→重放 409→恢复码）
与日志泄漏检查（无密钥/恢复码/令牌），均通过。

## 限制

- 第一因素仅为本地测试口令（PBKDF2-SHA256），不做注册与前端。
- 会话令牌仅演示签发，未实现令牌校验/吊销接口。
- 不提供邮件、短信、音视频或硬件设备渠道。
