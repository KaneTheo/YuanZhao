"""python -m yuanzhao 入口."""

from __future__ import annotations

import sys

# Windows 终端 UTF-8 支持
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from yuanzhao.app import run
from yuanzhao.cli import build_config, parse_args, validate_args
from yuanzhao.config import ScanConfig


def main():
    args = parse_args()

    errors = validate_args(args)
    if errors:
        for e in errors:
            print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        cfg_dict = build_config(args)
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

    config = ScanConfig(
        target=cfg_dict["target"],
        target_type=cfg_dict["target_type"],
        mode=cfg_dict["mode"],
        depth=cfg_dict["depth"],
        threads=cfg_dict["threads"],
        timeout=cfg_dict["timeout"],
        proxy=cfg_dict["proxy"],
        keyword_file=cfg_dict.get("keyword_file"),
        exclude=cfg_dict["exclude"],
        report_format=cfg_dict["report_format"],
        report_dir=cfg_dict["report_dir"],
        verbose=cfg_dict["verbose"],
        no_color=cfg_dict["no_color"],
        headless=cfg_dict["headless"],
        headless_binary=cfg_dict["headless_binary"],
        headless_driver=cfg_dict["headless_driver"],
        headless_timeout=cfg_dict["headless_timeout"],
        js_wait=cfg_dict["js_wait"],
        user_agent=cfg_dict.get("user_agent", "chrome"),
        rules_file=cfg_dict.get("rules_file"),
    )

    exit_code = run(config, target_file=cfg_dict.get("target_file"))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
