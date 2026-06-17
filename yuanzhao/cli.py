"""命令行参数解析（纯参数定义，不含业务逻辑）."""

from __future__ import annotations

import argparse
import os
import re

from yuanzhao.config import ReportFormat, ScanMode, TargetType


def _detect_target_type(target: str) -> TargetType | None:
    """自动检测目标类型."""
    if target.startswith(("http://", "https://")):
        domain = target.split("/")[2]
        if re.match(
            r"^(127\.0\.0\.1|localhost|[1`]0\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$",
            domain,
        ):
            return TargetType.INTERNAL_URL
        return TargetType.EXTERNAL_URL
    if os.path.isfile(target):
        if target.lower().endswith(".txt"):
            return _check_target_file(target)
        return TargetType.LOCAL_FILE
    if os.path.isdir(target):
        return TargetType.LOCAL_DIRECTORY
    return None


def _check_target_file(path: str) -> TargetType | None:
    try:
        with open(path, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            return None
        return TargetType.LOCAL_FILE
    except Exception:
        return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="yuanzhao",
        description="渊照 — 专业暗链扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  yuanzhao test.html
  yuanzhao ./website -d 2 -m standard -f html
  yuanzhao https://example.com -m deep -f html --verbose
  yuanzhao https://example.com --ua googlebot -m deep -f html
  yuanzhao https://example.com --headless --ua baiduspider --js-wait 5
  yuanzhao targets.txt -m deep -f html
        """,
    )

    parser.add_argument("target", help="扫描目标：文件、目录、URL 或目标列表文件(.txt)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="递归扫描深度（默认: 3）")
    parser.add_argument("-m", "--mode", choices=["fast", "standard", "deep"], default="deep", help="扫描模式（默认: deep）")
    parser.add_argument("-t", "--threads", type=int, default=8, help="并发线程数（默认: 8）")
    parser.add_argument("-o", "--output", help="报告输出目录（默认: ./reports）")
    parser.add_argument("-f", "--format", choices=["txt", "html", "json", "csv"], default="txt", help="报告格式（默认: txt）")
    parser.add_argument("--timeout", type=float, default=30.0, help="请求超时秒数（默认: 30）")
    parser.add_argument("--proxy", help="HTTP 代理，如 http://127.0.0.1:8080")
    parser.add_argument(
        "--ua", "--user-agent", dest="user_agent", default="chrome",
        help="伪装 User-Agent: chrome(默认) googlebot baiduspider bingbot yandexbot sogou googlebot-mobile 或自定义字符串",
    )
    parser.add_argument("--keyword-file", help="自定义关键字 CSV 文件路径")
    parser.add_argument("--rules-file", help="自定义检测规则 YAML 文件路径")
    parser.add_argument("--exclude", nargs="+", help="排除的文件或目录模式")
    parser.add_argument("--verbose", action="store_true", help="详细日志")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--version", action="version", version="yuanzhao 2.0.0")

    # 无头浏览器
    headless = parser.add_argument_group("无头浏览器")
    headless.add_argument("--headless", action="store_true", help="启用无头浏览器扫描")
    headless.add_argument("--headless-binary", help="Chrome 可执行文件路径")
    headless.add_argument("--headless-driver", help="ChromeDriver 路径")
    headless.add_argument("--headless-timeout", type=float, default=60.0, help="无头浏览器超时秒数（默认: 60）")
    headless.add_argument("--js-wait", type=float, default=3.0, help="JS 执行等待秒数（默认: 3）")

    # 批量目标
    batch = parser.add_argument_group("批量扫描")
    batch.add_argument("--target-file", help="目标列表文件路径，每行一个目标")

    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> list[str]:
    """验证参数，返回错误消息列表."""
    errors: list[str] = []

    if args.threads < 1 or args.threads > 100:
        errors.append("线程数必须在 1-100 之间")
    if args.depth < 0:
        errors.append("扫描深度不能为负数")
    if args.timeout <= 0:
        errors.append("超时时间必须大于 0")

    # 检查文件目标是否存在
    if not args.target.startswith(("http://", "https://")) and not os.path.exists(args.target):
        errors.append(f"目标不存在: {args.target}")

    if args.keyword_file and not os.path.exists(args.keyword_file):
        errors.append(f"关键字文件不存在: {args.keyword_file}")
    if args.target_file and not os.path.exists(args.target_file):
        errors.append(f"目标列表文件不存在: {args.target_file}")

    if args.headless and args.headless_driver and not os.path.exists(args.headless_driver):
        errors.append(f"ChromeDriver 不存在: {args.headless_driver}")

    return errors


def build_config(args: argparse.Namespace) -> dict:
    """从解析后的参数构建配置字典，供 app.py 使用."""
    target_type = _detect_target_type(args.target)
    if target_type is None:
        raise ValueError(f"无法识别目标类型: {args.target}")

    report_dir = args.output or os.path.join(os.getcwd(), "reports")

    return {
        "target": args.target,
        "target_type": target_type,
        "mode": ScanMode(args.mode),
        "depth": args.depth,
        "threads": args.threads,
        "timeout": args.timeout,
        "proxy": args.proxy,
        "keyword_file": args.keyword_file,
        "rules_file": args.rules_file,
        "exclude": args.exclude or [],
        "report_format": ReportFormat(args.format),
        "report_dir": report_dir,
        "verbose": args.verbose,
        "no_color": args.no_color,
        "headless": args.headless,
        "headless_binary": args.headless_binary,
        "headless_driver": args.headless_driver,
        "headless_timeout": args.headless_timeout,
        "js_wait": args.js_wait,
        "user_agent": args.user_agent,
        "target_file": args.target_file,
    }
