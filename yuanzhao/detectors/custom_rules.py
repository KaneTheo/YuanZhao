"""自定义规则检测器 — 从 YAML 加载用户自定义正则检测规则."""

from __future__ import annotations

import logging

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.rules.loader import load_custom_rules

logger = logging.getLogger("yuanzhao.detectors.custom_rules")


class CustomRulesDetector(BaseDetector):
    """通用正则匹配检测器，从自定义 YAML 规则文件加载检测逻辑."""

    def __init__(self, rules=None, *, rules_file: str | None = None):
        super().__init__(rules)
        self._compiled_rules: list[dict] = []
        if rules_file:
            self._compiled_rules = load_custom_rules(rules_file)

    def detect(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._compiled_rules:
            try:
                for m in rule["pattern"].finditer(content):
                    ctx_start = max(0, m.start() - 80)
                    ctx_end = min(len(content), m.end() + 80)
                    findings.append(Finding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        source_type=rule["source_type"],
                        location=source,
                        evidence=m.group(0)[:200],
                        context=content[ctx_start:ctx_end].replace("\n", " ").replace("\r", " "),
                        position=(m.start(), m.end()),
                        metadata={
                            "description": rule.get("description", ""),
                            "rule_file": "custom",
                        },
                    ))
            except Exception as e:
                logger.error("自定义规则执行异常 %s: %s", rule.get("rule_id"), e)
        return findings
