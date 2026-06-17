"""JavaScript 检测器."""

from __future__ import annotations

import logging
import re

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.network.utils import extract_domain, extract_urls, is_external_link

logger = logging.getLogger("yuanzhao.detectors.js")

# 混淆模式
_OBFUSCATION = [
    ("hex_encoding", re.compile(r'\\x[0-9a-fA-F]{2}'), "十六进制编码"),
    ("unicode_encoding", re.compile(r'\\u[0-9a-fA-F]{4}'), "Unicode 编码"),
    ("string_concat", re.compile(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'), "字符串拼接"),
    ("array_join", re.compile(r'\[.*\]\.join\s*\(\s*["\']'), "数组操作混淆"),
    ("reversed_string", re.compile(r'\.split\(\s*["\']\s*\)\s*\.reverse\(\)\s*\.join'), "反转字符串"),
    ("eval_concat", re.compile(r'eval\s*\(\s*[a-zA-Z0-9_$\[\]]+\s*\+'), "带参数拼接的 eval"),
]

# 可疑代码模式
_SUSPICIOUS = [
    ("self_executing", re.compile(r'(function\s*\(\s*\)\s*\{[^\}]*\}\s*\(\s*\))|\(([^\)]+)\)\(\)'), 3, "自执行函数"),
    ("conditional_eval", re.compile(r'if\s*\([^\)]*\)\s*\{[^\}]*eval\s*\('), 4, "条件 eval 调用"),
    ("try_catch_eval", re.compile(r'try\s*\{[^\}]*eval\s*\([^\)]*\)[^\}]*\}\s*catch'), 4, "try-catch 中的 eval"),
    ("hidden_eval", re.compile(r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*["\']eval["\'].*;.*\[.*\]\s*\('), 5, "隐藏的 eval 调用"),
    ("cookie", re.compile(r'document\.cookie'), 3, "Cookie 操作"),
    ("referrer", re.compile(r'document\.referrer'), 1, "Referrer 检查"),
    ("user_agent", re.compile(r'navigator\.userAgent'), 1, "User-Agent 检查"),
]

_COMMENT_WORDS = {
    "hack", "exploit", "backdoor", "trojan", "malware", "keylogger",
    "cracker", "steal", "inject", "redirect", "obfuscate", "phish",
}


def _entropy(text: str) -> float:
    import math
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


class JSDetector(BaseDetector):
    def detect(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_high_risk_functions(content, source))
        findings.extend(self._detect_obfuscation(content, source))
        findings.extend(self._detect_suspicious_patterns(content, source))
        findings.extend(self._detect_dynamic_urls(content, source))
        findings.extend(self._detect_dom_manipulations(content, source))
        findings.extend(self._detect_comments(content, source))
        findings.extend(self._analyze_entropy(content, source))
        return findings

    def _detect_high_risk_functions(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        func_weights = self.rules.get("js_high_risk_functions", {})
        for name, severity in func_weights.items():
            for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", content):
                findings.append(Finding(
                    rule_id=f"js:high_risk:{name}",
                    severity=severity,
                    category="js_issue",
                    source_type="js",
                    location=source,
                    evidence=m.group(0),
                    context=self._ctx(content, m.start(), m.end()),
                    position=(m.start(), m.end()),
                    metadata={"function": name},
                ))
        return findings

    def _detect_obfuscation(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pat, desc in _OBFUSCATION:
            matches = list(pat.finditer(content))
            count = len(matches)
            if count >= 5:
                severity = 4 if count >= 10 else 3
                findings.append(Finding(
                    rule_id=f"js:obfuscation:{name}",
                    severity=severity,
                    category="js_issue",
                    source_type="js",
                    location=source,
                    evidence=f"{count} 处匹配",
                    context=self._ctx(content, matches[0].start(), matches[0].end()),
                    metadata={"pattern": name, "count": count, "description": desc},
                ))
        return findings

    def _detect_suspicious_patterns(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pat, sev, desc in _SUSPICIOUS:
            for m in pat.finditer(content):
                findings.append(Finding(
                    rule_id=f"js:pattern:{name}",
                    severity=sev,
                    category="js_issue",
                    source_type="js",
                    location=source,
                    evidence=m.group(0)[:200],
                    context=self._ctx(content, m.start(), m.end()),
                    position=(m.start(), m.end()),
                    metadata={"pattern": name, "description": desc},
                ))
        return findings

    def _detect_dynamic_urls(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        source_domain = extract_domain(source) if source.startswith(("http://", "https://")) else None
        tld_weights = self.rules.get("suspicious_tlds", {})
        for item in extract_urls(content, source_type="js"):
            url = item["url"]
            if not is_external_link(url, source_domain):
                continue
            risk = 3
            reasons = ["外部 JS URL"]
            link_domain = extract_domain(url)
            for tld, sev in tld_weights.items():
                if link_domain.endswith(f".{tld}"):
                    risk = min(5, risk + sev)
                    reasons.append(f"可疑 TLD .{tld}")
                    break
            if re.search(r"/[a-zA-Z0-9]{8,}\.js$", url):
                risk = min(5, risk + 1)
                reasons.append("长随机文件名")
            if risk >= 3:
                findings.append(Finding(
                    rule_id="js:dynamic_url",
                    severity=risk,
                    category="suspicious_url",
                    source_type="js",
                    location=source,
                    evidence=url,
                    context=item["context"],
                    position=item["position"],
                    metadata={"reasons": reasons},
                ))
        return findings

    def _detect_dom_manipulations(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        dom_ops = {"innerHTML": 4, "outerHTML": 4, "appendChild": 3, "insertBefore": 3, "replaceChild": 3}
        for op, sev in dom_ops.items():
            for m in re.finditer(r"\b" + re.escape(op) + r"\s*\(", content):
                findings.append(Finding(
                    rule_id=f"js:dom:{op}",
                    severity=sev,
                    category="js_issue",
                    source_type="js",
                    location=source,
                    evidence=m.group(0),
                    context=self._ctx(content, m.start(), m.end()),
                    position=(m.start(), m.end()),
                    metadata={"operation": op},
                ))
        return findings

    def _detect_comments(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"//(.+)", content):
            text = m.group(1).lower()
            for word in _COMMENT_WORDS:
                if word in text:
                    findings.append(Finding(
                        rule_id="js:comment:suspicious",
                        severity=3,
                        category="js_issue",
                        source_type="comments",
                        location=source,
                        evidence=word,
                        context=m.group(1)[:200],
                        metadata={"keyword": word},
                    ))
                    break
        for m in re.finditer(r"/\*(.+?)\*/", content, re.DOTALL):
            text = m.group(1)
            for word in _COMMENT_WORDS:
                if word in text.lower():
                    findings.append(Finding(
                        rule_id="js:comment:suspicious",
                        severity=3,
                        category="js_issue",
                        source_type="comments",
                        location=source,
                        evidence=word,
                        context=text[:200],
                        metadata={"keyword": word},
                    ))
                    break
            if re.search(r"[A-Za-z0-9+/=]{32,}", text) and len(text) > 50:
                findings.append(Finding(
                    rule_id="js:comment:base64",
                    severity=4,
                    category="js_issue",
                    source_type="comments",
                    location=source,
                    evidence="Base64-like 字符串",
                    context=text[:200],
                ))
        return findings

    def _analyze_entropy(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        code = re.sub(r"//[^\n]*|/\*.*?\*/", "", content, flags=re.DOTALL)
        e = _entropy(code)
        if e > 4.5:
            findings.append(Finding(rule_id="js:entropy:high", severity=4, category="js_issue",
                                    source_type="js", location=source, evidence=f"熵值 {e:.2f}",
                                    metadata={"entropy": round(e, 2)}))
        elif e > 3.8:
            findings.append(Finding(rule_id="js:entropy:medium", severity=2, category="js_issue",
                                    source_type="js", location=source, evidence=f"熵值 {e:.2f}",
                                    metadata={"entropy": round(e, 2)}))
        return findings

    @staticmethod
    def _ctx(text: str, start: int, end: int, margin: int = 80) -> str:
        cs = max(0, start - margin)
        ce = min(len(text), end + margin)
        return text[cs:ce].replace("\n", " ").replace("\r", " ")
