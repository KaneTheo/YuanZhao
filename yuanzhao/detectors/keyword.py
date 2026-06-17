"""关键字检测器."""

from __future__ import annotations

import logging
import re

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.rules.loader import load_keywords_csv

logger = logging.getLogger("yuanzhao.detectors.keyword")

CATEGORY_NAMES = {
    "gambling": "博彩",
    "porn": "色情",
    "malware": "恶意软件",
    "phishing": "钓鱼",
    "other": "其他",
}


class KeywordDetector(BaseDetector):
    def __init__(self, keyword_file: str | None = None, rules=None):
        super().__init__(rules)
        self._keywords: list[tuple[str, str, int]] = []
        self._patterns: list[tuple[re.Pattern, str, str, int]] = []
        self._load(keyword_file)

    def _load(self, path: str | None):
        entries = load_keywords_csv(path)
        if not entries:
            entries = load_keywords_csv()  # fallback to builtin
        self._keywords = entries
        self._patterns = []
        for kw, cat, weight in entries:
            if kw.isascii() and re.fullmatch(r"[A-Za-z]+", kw) and len(kw) <= 2:
                pat = re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
            else:
                pat = re.compile(re.escape(kw), re.IGNORECASE)
            self._patterns.append((pat, kw, cat, weight))

    def detect(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for pattern, kw, category, weight in self._patterns:
            for m in pattern.finditer(content):
                key = (kw, m.start())
                if key in seen:
                    continue
                seen.add(key)

                ctx_start = max(0, m.start() - 60)
                ctx_end = min(len(content), m.end() + 60)
                ctx = content[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")

                findings.append(Finding(
                    rule_id=f"keyword:{kw}",
                    severity=weight,
                    category="keyword_match",
                    source_type="text",
                    location=source,
                    evidence=kw,
                    context=ctx[:200],
                    position=(m.start(), m.end()),
                    metadata={"keyword": kw, "category": CATEGORY_NAMES.get(category, "其他"), "weight": weight},
                ))

        findings.sort(key=lambda f: f.severity, reverse=True)
        return findings
