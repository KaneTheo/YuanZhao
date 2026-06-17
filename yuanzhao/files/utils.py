"""文件处理 — 读取、编码检测、目录遍历、二进制判断."""

from __future__ import annotations

import fnmatch
import logging
import os

import chardet

logger = logging.getLogger("yuanzhao.files")

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def read_file(path: str, max_size: int = MAX_FILE_SIZE) -> str:
    """读取文件内容，自动检测编码."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            raw = f.read(min(size, 10000))
            encoding = chardet.detect(raw).get("encoding") or "utf-8"

        with open(path, encoding=encoding, errors="replace") as f:
            return f.read(min(size, max_size))
    except Exception as e:
        logger.error("读取文件失败 %s: %s", path, e)
        return ""


def is_binary_file(path: str) -> bool:
    """检测是否为二进制文件."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        if b"\x00" in chunk:
            return True
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        non_text = sum(1 for b in chunk if b not in text_chars)
        return (non_text / len(chunk)) > 0.3
    except Exception:
        return False


def _match_exclude(path: str, patterns: list[str]) -> bool:
    p = path.replace("\\", "/")
    for pat in patterns or []:
        if fnmatch.fnmatch(p, pat):
            return True
        if pat.endswith("/") and p.startswith(pat.rstrip("/")):
            return True
    return False


def collect_files(
    directory: str,
    extensions: list[str],
    depth: int = 3,
    exclude: list[str] | None = None,
) -> list[str]:
    """递归收集目录下指定扩展名的文件，支持深度限制和排除模式."""
    result: list[str] = []
    excl = exclude or []
    exts = {e.lower() for e in extensions}
    base_depth = directory.rstrip("\\/").count(os.sep)

    for root, dirs, files in os.walk(directory):
        current_depth = root.rstrip("\\/").count(os.sep) - base_depth
        if current_depth >= depth:
            dirs[:] = []

        # 排除目录
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and not _match_exclude(os.path.join(root, d), excl)
        ]

        for fname in files:
            if fname.startswith("."):
                continue
            full = os.path.join(root, fname)
            if _match_exclude(full, excl):
                continue
            _, ext = os.path.splitext(fname.lower())
            if ext in exts:
                result.append(full)

    logger.info("收集到 %d 个待扫描文件", len(result))
    return result
