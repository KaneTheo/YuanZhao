"""规则加载器 — 从 YAML/JSON 文件加载检测规则."""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("yuanzhao.rules")

_BUILTIN_DIR = Path(__file__).parent


def load_yaml_rules(path: str | Path | None = None) -> dict[str, Any]:
    """加载 YAML 规则文件，默认使用内置 builtin.yaml."""
    filepath = Path(path) if path else _BUILTIN_DIR / "builtin.yaml"
    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        logger.info("已加载规则文件: %s (%d 个规则组)", filepath, len(data))
        return data or {}
    except Exception as e:
        logger.error("加载规则文件失败 %s: %s", filepath, e)
        return {}


def load_keywords_csv(path: str | Path | None = None) -> list[tuple[str, str, int]]:
    """加载关键字 CSV，返回 [(keyword, category, weight), ...].

    默认使用内置 keywords.csv。
    """
    filepath = Path(path) if path else _BUILTIN_DIR / "keywords.csv"
    if not filepath.exists():
        logger.warning("关键字文件不存在: %s", filepath)
        return []

    keywords: list[tuple[str, str, int]] = []
    valid_categories = {"gambling", "porn", "malware", "phishing", "other"}

    with open(filepath, encoding="utf-8") as f:
        reader = csv.reader(f)
        for _line_num, parts in enumerate(reader, 1):
            if not parts or all(p.strip() == "" for p in parts):
                continue
            if parts[0].strip().startswith("#"):
                continue
            if len(parts) < 3:
                continue

            kw = parts[0].strip()
            cat = parts[1].strip()
            if cat not in valid_categories:
                cat = "other"
            try:
                weight = max(1, min(10, int(parts[2].strip())))
            except ValueError:
                weight = 5

            keywords.append((kw, cat, weight))

    logger.info("已加载 %d 个关键字", len(keywords))
    return keywords


def load_custom_rules(path: str | Path | None = None) -> list[dict]:
    """加载自定义检测规则 YAML 文件，返回编译后的规则列表.

    每项包含: rule_id, pattern (compiled re.Pattern), severity, category,
             source_type, description
    """
    if not path:
        return []

    filepath = Path(path)
    if not filepath.exists():
        logger.warning("自定义规则文件不存在: %s", filepath)
        return []

    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error("加载自定义规则失败 %s: %s", filepath, e)
        return []

    if not data or "rules" not in data:
        logger.warning("自定义规则文件无 rules 字段: %s", filepath)
        return []

    flag_map = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE}

    compiled: list[dict] = []
    for entry in data["rules"]:
        try:
            rule_id = str(entry["rule_id"])
            raw = str(entry["pattern"])
            flags_str = str(entry.get("flags", ""))
            severity = max(1, min(10, int(entry.get("severity", 5))))
            category = str(entry.get("category", "suspicious_pattern"))
            source_type = str(entry.get("source_type", "text"))
            description = str(entry.get("description", ""))

            flags = 0
            for f in flags_str.lower():
                if f in flag_map:
                    flags |= flag_map[f]

            compiled.append({
                "rule_id": rule_id,
                "pattern": re.compile(raw, flags),
                "severity": severity,
                "category": category,
                "source_type": source_type,
                "description": description,
            })
        except re.error as e:
            logger.error("规则 %s 正则编译失败: %s", entry.get("rule_id", "?"), e)
        except Exception as e:
            logger.error("解析规则失败: %s", e)

    logger.info("已加载 %d 条自定义规则", len(compiled))
    return compiled
