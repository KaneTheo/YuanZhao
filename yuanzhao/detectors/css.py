"""CSS 检测器."""

from __future__ import annotations

import logging
import re

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.network.utils import extract_urls, is_external_link, is_trusted_cdn

logger = logging.getLogger("yuanzhao.detectors.css")

_SEL_PATTERNS = [
    ("attr_js", re.compile(r'\[[^\]]+=[^\]]*(?:javascript:|data:)[^\]]*\]'), 4, "属性选择器中的 JS/Data URL"),
    ("long_class", re.compile(r'\.[a-zA-Z0-9_$]{15,}'), 2, "异常长的类名"),
    ("long_id", re.compile(r'#\w{15,}'), 2, "异常长的 ID 名"),
]

_PROP_PATTERNS = [
    ("bg_image", re.compile(r'url\(\s*["\']?(?:data:|javascript:)', re.IGNORECASE), "background-image"),
    ("bg_ext", re.compile(r'url\(\s*["\']?https?://[^\)]+\)', re.IGNORECASE), "background-image"),
    ("content_after", re.compile(r':after\s*\{[^\}]*content\s*:\s*["\'](?:javascript:|data:)', re.IGNORECASE), "content"),
    ("content_before", re.compile(r':before\s*\{[^\}]*content\s*:\s*["\'](?:javascript:|data:)', re.IGNORECASE), "content"),
]

_COMMENT_WORDS = {
    "hidden", "stealth", "cloaking", "obfuscate", "invisible",
    "seo", "spam", "backlink", "redirect", "hack", "exploit", "malware", "phish",
}


class CSSDetector(BaseDetector):
    def detect(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_hidden(content, source))
        findings.extend(self._detect_selectors(content, source))
        findings.extend(self._detect_properties(content, source))
        findings.extend(self._detect_urls(content, source))
        findings.extend(self._detect_imports(content, source))
        findings.extend(self._detect_comments(content, source))
        findings.extend(self._detect_obfuscation(content, source))
        return findings

    def _detect_hidden(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        hiding = self.rules.get("css_hiding_values", {})

        for prop, values in hiding.items():
            if prop in ("position",):
                continue
            if isinstance(values, list):
                for val in values:
                    pat = re.compile(rf"{prop}\s*:\s*{re.escape(val)}", re.IGNORECASE)
                    for m in pat.finditer(content):
                        findings.append(Finding(
                            rule_id=f"css:hiding:{prop}",
                            severity=3,
                            category="hidden_element",
                            source_type="css",
                            location=source,
                            evidence=m.group(0),
                            context=self._ctx(content, m.start(), m.end()),
                            position=(m.start(), m.end()),
                            metadata={"property": prop, "value": val},
                        ))

        for m in re.finditer(
            r'\.?[#\w][^{]+\{[^}]*(?:left|top|right|bottom)\s*:\s*-(\d{3,})(?:px|em|%)',
            content, re.IGNORECASE | re.DOTALL,
        ):
            findings.append(Finding(
                rule_id="css:hiding:absolute_pos",
                severity=4 if int(m.group(1)) > 9999 else 3,
                category="hidden_element",
                source_type="css",
                location=source,
                evidence=m.group(0),
                context=self._ctx(content, m.start(), m.end()),
                position=(m.start(), m.end()),
            ))

        return findings

    def _detect_selectors(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pat, sev, desc in _SEL_PATTERNS:
            for m in pat.finditer(content):
                findings.append(Finding(
                    rule_id=f"css:selector:{name}",
                    severity=sev,
                    category="css_issue",
                    source_type="css",
                    location=source,
                    evidence=m.group(0),
                    context=self._ctx(content, m.start(), m.end()),
                    position=(m.start(), m.end()),
                    metadata={"description": desc},
                ))
        return findings

    def _detect_properties(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pat, prop in _PROP_PATTERNS:
            for m in pat.finditer(content):
                findings.append(Finding(
                    rule_id=f"css:property:{name}",
                    severity=3,
                    category="css_issue",
                    source_type="css",
                    location=source,
                    evidence=m.group(0),
                    context=self._ctx(content, m.start(), m.end()),
                    position=(m.start(), m.end()),
                    metadata={"property": prop},
                ))
        return findings

    def _detect_urls(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for item in extract_urls(content, source_type="css"):
            url = item["url"]
            if url.startswith("javascript:"):
                findings.append(Finding(rule_id="css:url:javascript", severity=5, category="suspicious_url",
                                        source_type="css", location=source, evidence=url,
                                        context=item["context"], position=item["position"],
                                        metadata={"reasons": ["JavaScript 协议"]}))
            elif url.startswith("data:"):
                sev = 5 if len(url) > 500 else 4
                findings.append(Finding(rule_id="css:url:data", severity=sev, category="suspicious_url",
                                        source_type="css", location=source, evidence=url[:200],
                                        context=item["context"], position=item["position"],
                                        metadata={"reasons": ["Data URI"]}))
            elif is_external_link(url) and not is_trusted_cdn(url):
                findings.append(Finding(rule_id="css:url:external", severity=2, category="suspicious_url",
                                        source_type="css", location=source, evidence=url,
                                        context=item["context"], position=item["position"],
                                        metadata={"reasons": ["外部 CSS 资源"]}))
        return findings

    def _detect_imports(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r'@import\s+(?:url\(\s*["\']?([^"\')\s]+)["\']?\s*\)|["\']([^"\']+)["\'])', content, re.IGNORECASE):
            url = m.group(1) or m.group(2)
            if is_external_link(url):
                findings.append(Finding(
                    rule_id="css:import:external", severity=3, category="css_issue",
                    source_type="css", location=source, evidence=url,
                    context=self._ctx(content, m.start(), m.end(), 40),
                    position=(m.start(), m.end()),
                    metadata={"reasons": ["外部 CSS 导入"]},
                ))
        cnt = content.lower().count("@import")
        if cnt > 10:
            findings.append(Finding(
                rule_id="css:import:excessive", severity=3, category="css_issue",
                source_type="css", location=source, evidence=f"{cnt} 个 @import",
                metadata={"count": cnt},
            ))
        return findings

    def _detect_comments(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"/\*(.+?)\*/", content, re.DOTALL):
            text = m.group(1).lower()
            for kw in _COMMENT_WORDS:
                if kw in text:
                    findings.append(Finding(
                        rule_id="css:comment:suspicious", severity=3, category="css_issue",
                        source_type="comments", location=source, evidence=kw,
                        context=m.group(1)[:200], metadata={"keyword": kw},
                    ))
                    break
        return findings

    def _detect_obfuscation(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        long_matches = list(re.finditer(r'(?:\.|#)([a-zA-Z0-9_]{20,})', content))
        if len(long_matches) >= 5:
            findings.append(Finding(
                rule_id="css:obfuscation:long_names",
                severity=4 if len(long_matches) >= 10 else 3,
                category="css_issue", source_type="css", location=source,
                evidence=f"{len(long_matches)} 个超长选择器",
                metadata={"count": len(long_matches)},
            ))
        ctrl = list(re.finditer(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', content))
        if len(ctrl) > 10:
            findings.append(Finding(
                rule_id="css:obfuscation:control_chars",
                severity=3, category="css_issue", source_type="css", location=source,
                evidence=f"{len(ctrl)} 个控制字符",
                metadata={"count": len(ctrl)},
            ))
        return findings

    @staticmethod
    def _ctx(text: str, start: int, end: int, margin: int = 50) -> str:
        cs = max(0, start - margin)
        ce = min(len(text), end + margin)
        return text[cs:ce].replace("\n", " ").replace("\r", " ")
