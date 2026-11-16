"""本地多因素认证服务（TOTP + 恢复码）。

仅依赖 Python 3.12 标准库与 SQLite，CPU only，
不依赖 Docker、外部身份服务或任何现成 MFA 组件。
"""

__version__ = "1.0.0"
