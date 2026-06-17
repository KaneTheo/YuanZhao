"""特殊隐藏技术检测器."""

from __future__ import annotations

import logging
import re

from yuanzhao.detectors.base import BaseDetector, Finding

logger = logging.getLogger("yuanzhao.detectors.hiding")


class SpecialHidingDetector(BaseDetector):
    def detect(self, content: str, source: str) -> list[Finding]:
        # 从规则读取零宽字符
        zw_chars = self.rules.get("zero_width_chars", [
            "​", "‌", "‍", "⁠", "﻿",
        ])
        findings: list[Finding] = []
        findings.extend(_detect_zero_width(content, source, zw_chars))
        findings.extend(_detect_whitespace_stack(content, source))
        findings.extend(_detect_color_hiding(content, source))
        findings.extend(_detect_position_hiding(content, source))
        findings.extend(_detect_font_size_hiding(content, source))
        findings.extend(_detect_text_indent_hiding(content, source))
        findings.extend(_detect_opacity_hiding(content, source))
        findings.extend(_detect_nested(content, source))
        findings.extend(_detect_entities(content, source))
        return findings


def _detect_zero_width(content: str, source: str, chars: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile("|".join(re.escape(c) for c in chars))
    matches = list(pattern.finditer(content))
    if matches:
        ctx = _ctx(content, matches[0].start(), matches[-1].end())
        findings.append(Finding(
            rule_id="hiding:zero_width", severity=7, category="hidden_element",
            source_type="text", location=source,
            evidence=f"{len(matches)} 个零宽字符", context=ctx,
            metadata={"count": len(matches), "technique": "零宽字符隐藏"},
        ))
    return findings


def _detect_whitespace_stack(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(r"(\s|\t|\r|\n){10,}", content):
        ctx = _ctx(content, m.start(), m.end())
        if "<" not in ctx and ">" not in ctx:
            findings.append(Finding(
                rule_id="hiding:whitespace", severity=4, category="hidden_element",
                source_type="text", location=source,
                evidence=f"空白堆积 ({len(m.group(0))} 个)", context=ctx,
                metadata={"count": len(m.group(0)), "technique": "空白字符堆积"},
            ))
    return findings


def _detect_color_hiding(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    color_pat = re.compile(r"(?<!background-)color\s*:\s*(#\w{3,6}|rgba?\([^)]+\))", re.IGNORECASE)
    bg_pat = re.compile(r"background-color\s*:\s*(#\w{3,6}|rgba?\([^)]+\)|\w+)", re.IGNORECASE)
    for m in color_pat.finditer(content):
        color = m.group(1).lower()
        segment = content[max(0, m.start() - 200):m.end() + 200]
        bg_m = bg_pat.search(segment)
        if bg_m and _colors_similar(color, bg_m.group(1).lower()):
            findings.append(Finding(
                rule_id="hiding:color_match", severity=7, category="hidden_element",
                source_type="css", location=source,
                evidence=f"文字 {color} ≈ 背景 {bg_m.group(1)}",
                context=_ctx(content, m.start(), m.end()),
                metadata={"technique": "颜色隐藏", "text_color": color, "bg_color": bg_m.group(1)},
            ))
    return findings


def _detect_position_hiding(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(
        r"position\s*:\s*absolute.*?(left|top|bottom|right)\s*:\s*(-?\d+(?:\.\d+)?(?:px|em|%)?)",
        content, re.IGNORECASE | re.DOTALL,
    ):
        direction = m.group(1)
        value = m.group(2)
        num_match = re.search(r"([-\d.]+)", value)
        if num_match and abs(float(num_match.group(1))) > 1000:
            findings.append(Finding(
                rule_id="hiding:absolute_pos", severity=7, category="hidden_element",
                source_type="css", location=source, evidence=f"{direction}:{value}",
                context=_ctx(content, m.start(), m.end()),
                metadata={"technique": "绝对定位隐藏", "direction": direction, "value": value},
            ))
    return findings


def _detect_font_size_hiding(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(r"font-size\s*:\s*(0|0\.\d+)", content, re.IGNORECASE):
        findings.append(Finding(
            rule_id="hiding:font_size", severity=7, category="hidden_element",
            source_type="css", location=source, evidence=m.group(0),
            context=_ctx(content, m.start(), m.end()),
            metadata={"technique": "字体大小隐藏", "size": m.group(1)},
        ))
    return findings


def _detect_text_indent_hiding(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(r"text-indent\s*:\s*(-\d+(?:\.\d+)?(?:px|em|%))", content, re.IGNORECASE):
        indent = m.group(1)
        num_match = re.search(r"([-\d.]+)", indent)
        if num_match and abs(float(num_match.group(1))) > 50:
            findings.append(Finding(
                rule_id="hiding:text_indent", severity=7, category="hidden_element",
                source_type="css", location=source, evidence=indent,
                context=_ctx(content, m.start(), m.end()),
                metadata={"technique": "文本缩进隐藏", "indent": indent},
            ))
    return findings


def _detect_opacity_hiding(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(r"opacity\s*:\s*(0|0\.0+)(?![.\d])", content, re.IGNORECASE):
        findings.append(Finding(
            rule_id="hiding:opacity", severity=7, category="hidden_element",
            source_type="css", location=source, evidence=m.group(0),
            context=_ctx(content, m.start(), m.end()),
            metadata={"technique": "透明度隐藏"},
        ))
    for m in re.finditer(r"visibility\s*:\s*hidden", content, re.IGNORECASE):
        findings.append(Finding(
            rule_id="hiding:visibility", severity=7, category="hidden_element",
            source_type="css", location=source, evidence="visibility: hidden",
            context=_ctx(content, m.start(), m.end()),
            metadata={"technique": "可见性隐藏"},
        ))
    for m in re.finditer(r"display\s*:\s*none", content, re.IGNORECASE):
        findings.append(Finding(
            rule_id="hiding:display_none", severity=7, category="hidden_element",
            source_type="css", location=source, evidence="display: none",
            context=_ctx(content, m.start(), m.end()),
            metadata={"technique": "显示隐藏"},
        ))
    return findings


def _detect_nested(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in re.finditer(
        r"<(div|span|p|a)[^>]*>\s*<(div|span|p|a)[^>]*>\s*<(div|span|p|a)[^>]*>",
        content, re.IGNORECASE,
    ):
        findings.append(Finding(
            rule_id="hiding:nested", severity=4, category="hidden_element",
            source_type="html", location=source, evidence="多层嵌套",
            context=_ctx(content, m.start(), m.end(), 30),
            metadata={"technique": "多层嵌套隐藏"},
        ))
    return findings


def _detect_entities(content: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    matches = list(re.finditer(r"&#(\d+);|&#x([0-9a-f]+);", content, re.IGNORECASE))
    if len(matches) > 10:
        findings.append(Finding(
            rule_id="hiding:entities", severity=4, category="hidden_element",
            source_type="html", location=source,
            evidence=f"{len(matches)} 个 HTML 实体",
            context=_ctx(content, matches[0].start(), matches[min(5, len(matches) - 1)].end(), 20),
            metadata={"count": len(matches), "technique": "HTML 实体编码隐藏"},
        ))
    return findings


def _colors_similar(c1: str, c2: str) -> bool:
    c1, c2 = c1.lower(), c2.lower()
    if c1 == c2:
        return True
    dark = {"#000", "#000000", "black", "rgb(0,0,0)", "rgba(0,0,0,1)"}
    white = {"#fff", "#ffffff", "white", "rgb(255,255,255)", "rgba(255,255,255,1)"}
    return (c1 in dark and c2 in dark) or (c1 in white and c2 in white)


def _ctx(text: str, start: int, end: int, margin: int = 50) -> str:
    cs = max(0, start - margin)
    ce = min(len(text), end + margin)
    return text[cs:ce].replace("\n", " ").replace("\r", " ")
