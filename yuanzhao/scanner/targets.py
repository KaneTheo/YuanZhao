"""目标解析 — 将用户输入转为待扫描目标列表."""

from __future__ import annotations

import logging
import os

from yuanzhao.config import ScanConfig, TargetType

logger = logging.getLogger("yuanzhao.scanner.targets")


def resolve_targets(config: ScanConfig, target_file: str | None = None) -> list[tuple[str, TargetType]]:
    """解析扫描目标，返回 [(target, type), ...] 列表."""
    results: list[tuple[str, TargetType]] = []

    # 目标列表文件优先
    if target_file:
        lines = _read_target_file(target_file)
        for line in lines:
            tt = _classify(line)
            if tt:
                results.append((line, tt))
        return results

    # 单目标 .txt 文件 → 当作列表文件
    if not config.target.startswith(("http://", "https://")) and \
       os.path.isfile(config.target) and config.target.lower().endswith(".txt"):
            lines = _read_target_file(config.target)
            for line in lines:
                tt = _classify(line)
                if tt:
                    results.append((line, tt))
            return results

    # 单目标
    tt = _classify(config.target)
    if tt:
        results.append((config.target, tt))
    return results


def _read_target_file(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error("读取目标列表失败 %s: %s", path, e)
        return []


def _classify(target: str) -> TargetType | None:
    import re
    if target.startswith(("http://", "https://")):
        domain = target.split("/")[2].split(":")[0]
        if re.match(
            r"^(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$",
            domain,
        ):
            return TargetType.INTERNAL_URL
        return TargetType.EXTERNAL_URL
    if os.path.isfile(target):
        return TargetType.LOCAL_FILE
    if os.path.isdir(target):
        return TargetType.LOCAL_DIRECTORY
    return None
