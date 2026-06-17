"""日志配置 — Rich 控制台 + 文件输出."""

import logging
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(log_dir: str | None = None, verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("yuanzhao")
    logger.setLevel(level)
    logger.handlers.clear()

    # Rich 控制台输出（彩色、结构化）
    console = Console(stderr=True)
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_level=verbose,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
    )
    rich_handler.setLevel(level)
    fmt = logging.Formatter("%(message)s", datefmt="[%X]")
    rich_handler.setFormatter(fmt)
    logger.addHandler(rich_handler)

    # 文件输出（纯文本，保留完整日志）
    if log_dir:
        path = Path(log_dir)
        path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_handler = logging.FileHandler(
            path / f"yuanzhao_{ts}.log", encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger
