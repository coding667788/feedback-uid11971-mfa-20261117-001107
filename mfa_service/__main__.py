"""命令行入口：python -m mfa_service <init|serve|reset> ...

参考 TOTP 计算请使用独立模块：python -m mfa_service.totp_reference
"""

import argparse
import sys

from . import core


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m mfa_service", description="本地多因素认证服务")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="初始化数据库并预置测试用户")
    p_init.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    p_init.add_argument("--seed-out", default=None,
                        help="把密钥/恢复码 seed JSON 写入该文件（缺省打印到 stdout）")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的数据库")

    p_serve = sub.add_parser("serve", help="启动 HTTP 服务（可在多进程下运行多个实例）")
    p_serve.add_argument("--db", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, required=True)

    p_reset = sub.add_parser("reset", help="管理员重置用户因子（递增版本）")
    p_reset.add_argument("--db", required=True)
    p_reset.add_argument("--user", required=True)
    p_reset.add_argument("--seed-out", default=None,
                         help="把新密钥/新恢复码 seed JSON 写入该文件（缺省打印到 stdout）")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            from .init_cmd import run_init
            run_init(args.db, args.seed_out, args.force)
        elif args.command == "serve":
            from .serve import run_server
            run_server(args.db, args.host, args.port)
        elif args.command == "reset":
            from .reset_cmd import run_reset
            run_reset(args.db, args.user, args.seed_out)
    except core.ApiError as exc:
        print("错误: %s" % exc, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
