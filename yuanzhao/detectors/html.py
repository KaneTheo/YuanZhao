"""HTML 检测器 — 正则匹配 + BeautifulSoup 结构化 DOM 分析."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.network.utils import extract_domain, extract_urls, is_external_link, is_trusted_cdn

logger = logging.getLogger("yuanzhao.detectors.html")

# 内置正则模式
_RE_PATTERNS = [
    ("suspicious_attributes", re.compile(r'\bon\w+\s*=\s*["\']?javascript:', re.IGNORECASE), 3, "可疑的事件属性"),
    ("eval_inline", re.compile(r'\beval\s*\(', re.IGNORECASE), 4, "内联 eval 函数"),
    ("document_write", re.compile(r'\bdocument\.write\s*\(', re.IGNORECASE), 3, "document.write 调用"),
    ("base64_decode", re.compile(r'\batob\s*\(|\bfromCharCode\s*\(', re.IGNORECASE), 2, "Base64 解码操作"),
    ("data_uri", re.compile(r'data:[^;]+;base64,', re.IGNORECASE), 2, "Data URI"),
    ("remote_iframe", re.compile(r'<iframe[^>]+src=["\']?https?://', re.IGNORECASE), 3, "远程 iframe"),
    ("obfuscated_attributes", re.compile(r'\b(data-|on)[a-z0-9_-]+\s*=\s*["\']?[^"\']*(\\\\x[0-9a-f]{2}|\\\\u[0-9a-f]{4})', re.IGNORECASE), 3, "混淆的属性"),
]

_RE_HIDDEN = re.compile(
    r'<(div|span|p|section|article)[^>]+style=["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden)',
    re.IGNORECASE,
)

_COMMENT_RULES = [
    ("hidden_content", re.compile(r'(?:password|secret|hidden|private|admin)', re.IGNORECASE), 3, "包含敏感信息的注释"),
    ("encoded_content", re.compile(r'(?:base64|hex|escape|decodeURI)', re.IGNORECASE), 3, "包含编码内容的注释"),
    ("conditional_comments", re.compile(r'<!--\[(?:(?!\]-->)[\s\S])*\]>'), 1, "条件注释"),
    ("large_comment", re.compile(r'<!--(?:(?!-->)[\s\S]){500,}-->'), 2, "大型注释"),
]

_META_REDIRECT = re.compile(
    r'<meta[^>]+http-equiv=["\']?(refresh|redirect)["\']?[^>]+content=["\']?[^"\']*url=(\S+)["\']?',
    re.IGNORECASE,
)


class HTMLDetector(BaseDetector):
    def detect(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_suspicious_urls(content, source))
        findings.extend(self._detect_patterns(content, source))
        findings.extend(self._detect_hidden_elements(content, source))
        findings.extend(self._detect_comments(content, source))
        findings.extend(self._detect_meta(content, source))
        findings.extend(self._detect_dom(content, source))
        return findings

    def _detect_suspicious_urls(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        source_domain = extract_domain(source) if source.startswith(("http://", "https://")) else None
        tld_weights = self.rules.get("suspicious_tlds", {})
        short_links = self.rules.get("short_link_domains", [])

        for item in extract_urls(content, source_type="html"):
            url = item["url"]
            risk, reasons = self._assess_url(url, source_domain, tld_weights, short_links)
            if risk > 0:
                findings.append(Finding(
                    rule_id="html:suspicious_url",
                    severity=min(risk, 10),
                    category="suspicious_url",
                    source_type="html",
                    location=source,
                    evidence=url,
                    context=item["context"],
                    position=item["position"],
                    metadata={"reasons": reasons},
                ))
        return findings

    def _assess_url(self, url: str, source_domain: str | None,
                    tld_weights: dict, short_links: list) -> tuple[int, list[str]]:
        risk = 0
        reasons: list[str] = []

        if url.lower().startswith("javascript:"):
            return 8, ["JavaScript 伪协议"]
        if url.lower().startswith("data:"):
            return (5 if len(url) > 500 else 4), ["Data URI"]
        if not url.lower().startswith(("http://", "https://")):
            return 0, []
        if is_trusted_cdn(url):
            return 0, []

        link_domain = extract_domain(url)

        if source_domain and is_external_link(url, source_domain):
            risk += 2
            reasons.append("外部链接")

        for tld, severity in tld_weights.items():
            if link_domain.endswith(f".{tld}"):
                risk += severity
                reasons.append(f"高风险域名后缀 .{tld}")
                break

        parts = link_domain.split(".")
        if len(parts) >= 2 and len(parts[-2]) >= 8 and not any(c.isdigit() for c in parts[-2]):
            risk += 2
            reasons.append("可能为随机生成域名")

        if link_domain in short_links:
            risk += 3
            reasons.append("短链接服务")

        parsed = urlparse(url)
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            risk += 2
            reasons.append("非标准端口")

        if parsed.query:
            for p in ("redirect", "proxy", "referer", "origin", "callback"):
                if p in parsed.query.lower():
                    risk += 1
                    reasons.append(f"可疑查询参数: {p}")
                    break

        return risk, reasons

    def _detect_patterns(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pat, sev, desc in _RE_PATTERNS:
            for m in pat.finditer(content):
                ctx = self._ctx(content, m.start(), m.end())
                findings.append(Finding(
                    rule_id=f"html:pattern:{name}",
                    severity=sev,
                    category="suspicious_pattern",
                    source_type="html",
                    location=source,
                    evidence=m.group(0),
                    context=ctx,
                    position=(m.start(), m.end()),
                    metadata={"pattern": name, "description": desc},
                ))
        return findings

    def _detect_hidden_elements(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _RE_HIDDEN.finditer(content):
            ctx = self._ctx(content, m.start(), m.end())
            findings.append(Finding(
                rule_id="html:hidden_element",
                severity=2,
                category="hidden_element",
                source_type="html",
                location=source,
                evidence=m.group(0),
                context=ctx,
                position=(m.start(), m.end()),
                metadata={"description": "CSS 隐藏的块元素"},
            ))
        return findings

    def _detect_comments(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"<!--(.*?)-->", content, re.DOTALL):
            text = m.group(1)
            for name, pat, sev, desc in _COMMENT_RULES:
                if pat.search(text):
                    findings.append(Finding(
                        rule_id=f"html:comment:{name}",
                        severity=sev,
                        category="suspicious_pattern",
                        source_type="comments",
                        location=source,
                        evidence=text[:200],
                        context=text[:200],
                        metadata={"description": desc},
                    ))
                    break

            for url_m in re.finditer(r"""href=["'](https?://[^"']+)""", text):
                url = url_m.group(1)
                findings.append(Finding(
                    rule_id="html:comment:link",
                    severity=3,
                    category="suspicious_url",
                    source_type="comments",
                    location=source,
                    evidence=url,
                    context=text[:200],
                    metadata={"reasons": ["链接位于 HTML 注释中"]},
                ))

        return findings

    def _detect_meta(self, content: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _META_REDIRECT.finditer(content):
            url = m.group(2).rstrip("\"'")
            findings.append(Finding(
                rule_id="html:meta:refresh",
                severity=3,
                category="suspicious_url",
                source_type="meta",
                location=source,
                evidence=url,
                context=m.group(0),
                metadata={"reasons": ["通过 Meta 标签重定向"]},
            ))
        return findings

    # ==================== BeautifulSoup 结构化 DOM 分析 ====================

    def _detect_dom(self, content: str, source: str) -> list[Finding]:
        """使用 BeautifulSoup 进行结构化 DOM 分析."""
        findings: list[Finding] = []
        try:
            soup = BeautifulSoup(content, "lxml")
        except Exception:
            return findings
        source_domain = extract_domain(source) if source.startswith(("http://", "https://")) else None
        tld_weights = self.rules.get("suspicious_tlds", {})
        findings.extend(self._analyze_script_tags(soup, source))
        findings.extend(self._analyze_iframes(soup, source, source_domain, tld_weights))
        findings.extend(self._analyze_links(soup, source, source_domain, tld_weights))
        findings.extend(self._analyze_forms(soup, source, source_domain))
        findings.extend(self._analyze_hidden_dom(soup, source))
        return findings

    def _analyze_script_tags(self, soup: BeautifulSoup, source: str) -> list[Finding]:
        """检测 script 标签: 外部可疑域名、缺少完整性校验、内联高危函数."""
        findings: list[Finding] = []
        for tag in soup.find_all("script"):
            src = tag.get("src", "")
            if src:
                domain = extract_domain(src) if src.startswith(("http://", "https://")) else None
                if domain and not is_trusted_cdn(src):
                    findings.append(Finding(
                        rule_id="html:dom:external_script",
                        severity=4,
                        category="suspicious_url",
                        source_type="html",
                        location=source,
                        evidence=src,
                        context=str(tag)[:300],
                        metadata={"description": "外部脚本来源", "script_src": src},
                    ))
                if src.startswith(("http://", "https://")) and not tag.get("integrity"):
                    findings.append(Finding(
                        rule_id="html:dom:no_sri",
                        severity=2,
                        category="suspicious_pattern",
                        source_type="html",
                        location=source,
                        evidence=src,
                        context=str(tag)[:300],
                        metadata={"description": "外部脚本缺少 SRI 完整性校验"},
                    ))
            else:
                text = tag.string or ""
                if re.search(r'\beval\s*\(', text, re.IGNORECASE) or \
                   re.search(r'\bdocument\.write\s*\(', text, re.IGNORECASE) or \
                   re.search(r'\bfromCharCode\s*\(', text, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="html:dom:suspicious_inline_script",
                        severity=5,
                        category="js_issue",
                        source_type="html",
                        location=source,
                        evidence=text[:200],
                        context=text[:300],
                        metadata={"description": "内联脚本包含高危函数"},
                    ))
        return findings

    def _analyze_iframes(self, soup: BeautifulSoup, source: str,
                         source_domain: str | None, tld_weights: dict) -> list[Finding]:
        """检测 iframe: 外部来源、隐藏尺寸、缺少沙箱."""
        findings: list[Finding] = []
        for tag in soup.find_all("iframe"):
            src = tag.get("src", "")
            style = (tag.get("style") or "").lower()
            width = tag.get("width", "")
            height = tag.get("height", "")

            if src and src.startswith(("http://", "https://")):
                domain = extract_domain(src)
                risk = 3
                reasons = ["外部 iframe"]

                if source_domain and is_external_link(src, source_domain):
                    risk += 2
                    reasons.append("外部域名")
                for tld, sev in tld_weights.items():
                    if domain and domain.endswith(f".{tld}"):
                        risk += sev
                        reasons.append(f"高风险域名后缀 .{tld}")
                        break

                findings.append(Finding(
                    rule_id="html:dom:iframe",
                    severity=min(risk, 10),
                    category="suspicious_url",
                    source_type="html",
                    location=source,
                    evidence=src,
                    context=str(tag)[:300],
                    metadata={"description": "iframe 元素", "reasons": reasons},
                ))

            # 隐藏 iframe
            if ("display:none" in style or "visibility:hidden" in style or
                    ("width" in style and "0" in style and "height" in style and "0" in style) or
                    width in ("0", "1") or height in ("0", "1")):
                findings.append(Finding(
                    rule_id="html:dom:hidden_iframe",
                    severity=7,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=str(tag)[:200],
                    context=str(tag)[:300],
                    metadata={"description": "隐藏的 iframe", "style": style},
                ))

            if src.startswith(("http://", "https://")) and not tag.get("sandbox"):
                findings.append(Finding(
                    rule_id="html:dom:no_sandbox",
                    severity=2,
                    category="suspicious_pattern",
                    source_type="html",
                    location=source,
                    evidence=src,
                    context=str(tag)[:300],
                    metadata={"description": "iframe 缺少 sandbox 属性"},
                ))
        return findings

    def _analyze_links(self, soup: BeautifulSoup, source: str,
                       source_domain: str | None, tld_weights: dict) -> list[Finding]:
        """检测链接: 外部可疑域名、隐藏链接."""
        findings: list[Finding] = []
        short_links = self.rules.get("short_link_domains", [])
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if not href.startswith(("http://", "https://")):
                continue
            if is_trusted_cdn(href):
                continue

            link_domain = extract_domain(href)
            style = (tag.get("style") or "").lower()
            text = (tag.get_text() or "").strip()

            # 隐藏链接检测
            hidden = False
            hidden_reasons = []
            if "display:none" in style or "visibility:hidden" in style:
                hidden = True
                hidden_reasons.append("CSS 隐藏")
            if "opacity:0" in style or "opacity: 0" in style:
                hidden = True
                hidden_reasons.append("透明链接")
            if re.search(r'font-size\s*:\s*0', style):
                hidden = True
                hidden_reasons.append("零字号")
            if re.search(r'(?:left|top)\s*:\s*-\d{3,}px', style):
                hidden = True
                hidden_reasons.append("定位到屏幕外")
            if tag.get("aria-hidden") == "true":
                hidden = True
                hidden_reasons.append("aria-hidden 属性")

            if hidden:
                findings.append(Finding(
                    rule_id="html:dom:hidden_link",
                    severity=6,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=href,
                    context=str(tag)[:300],
                    metadata={"description": f"隐藏链接 ({', '.join(hidden_reasons)})"},
                ))

            # 可疑外部链接
            risk = 0
            reasons = []
            if source_domain and is_external_link(href, source_domain):
                risk += 2
                reasons.append("外部链接")
            for tld, sev in tld_weights.items():
                if link_domain and link_domain.endswith(f".{tld}"):
                    risk += sev
                    reasons.append(f"高风险域名后缀 .{tld}")
                    break
            if link_domain and link_domain in short_links:
                risk += 3
                reasons.append("短链接服务")
            # 链接文字与目标不匹配
            if text and link_domain:
                text_lower = text.lower()
                if any(shop_word in text_lower for shop_word in
                       ("login", "signin", "account", "verify", "secure", "update", "confirm")):
                    unknown_words = ("sample", "example", "test", "demo")
                    if not any(w in link_domain for w in unknown_words):
                        risk += 2
                        reasons.append("链接文字具有诱导性（登录/验证/账户）")

            if risk >= 4:
                findings.append(Finding(
                    rule_id="html:dom:suspicious_link",
                    severity=min(risk, 10),
                    category="suspicious_url",
                    source_type="html",
                    location=source,
                    evidence=href,
                    context=str(tag)[:300],
                    metadata={"description": "可疑链接", "reasons": reasons, "link_text": text[:100]},
                ))
        return findings

    def _analyze_forms(self, soup: BeautifulSoup, source: str,
                       source_domain: str | None) -> list[Finding]:
        """检测表单: 外部提交 action、隐藏字段、可疑登录表单."""
        findings: list[Finding] = []
        for form in soup.find_all("form"):
            action = form.get("action", "")

            # 检查外部 action
            if action and action.startswith(("http://", "https://")):
                action_domain = extract_domain(action)
                is_external = source_domain and action_domain and action_domain != source_domain
                findings.append(Finding(
                    rule_id="html:dom:external_form",
                    severity=7 if is_external else 4,
                    category="suspicious_pattern",
                    source_type="html",
                    location=source,
                    evidence=action,
                    context=str(form)[:500],
                    metadata={"description": "表单提交到外部 URL" if is_external else "表单提交到绝对 URL"},
                ))

            # 检查隐藏的敏感字段
            hidden_inputs = form.find_all("input", type="hidden")
            sensitive_names = {"token", "csrf", "auth", "password", "secret", "key", "credential"}
            for inp in hidden_inputs:
                name = (inp.get("name") or "").lower()
                value = (inp.get("value") or "").lower()
                if any(s in name for s in sensitive_names):
                    findings.append(Finding(
                        rule_id="html:dom:sensitive_hidden_field",
                        severity=3,
                        category="suspicious_pattern",
                        source_type="html",
                        location=source,
                        evidence=str(inp)[:200],
                        context=name,
                        metadata={"description": f"隐藏字段包含敏感名称: {name}"},
                    ))
                if "http" in value or "script" in value:
                    findings.append(Finding(
                        rule_id="html:dom:suspicious_hidden_value",
                        severity=5,
                        category="suspicious_pattern",
                        source_type="html",
                        location=source,
                        evidence=str(inp)[:200],
                        context=value,
                        metadata={"description": "隐藏字段值包含可疑内容"},
                    ))

            # 检测登录表单通过 HTTP 明文提交
            if source and source.startswith("http://"):
                password_fields = form.find_all("input", type="password")
                if password_fields:
                    findings.append(Finding(
                        rule_id="html:dom:insecure_login",
                        severity=6,
                        category="suspicious_pattern",
                        source_type="html",
                        location=source,
                        evidence=f"Password field on HTTP page, action={action or '(none)'}",
                        context=str(form)[:400],
                        metadata={"description": "HTTP 明文页面包含密码输入框"},
                    ))
        return findings

    def _analyze_hidden_dom(self, soup: BeautifulSoup, source: str) -> list[Finding]:
        """使用 BS4 检测 DOM 中的隐藏元素."""
        findings: list[Finding] = []
        hiding_keywords = ["hidden", "hide", "invisible", "visually-hidden", "sr-only", "d-none"]

        for tag in soup.find_all(style=True):
            style = tag["style"].lower().replace(" ", "")

            # display:none / visibility:hidden
            if "display:none" in style or "visibility:hidden" in style:
                findings.append(Finding(
                    rule_id="html:dom:styled_hidden",
                    severity=3,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=str(tag)[:200],
                    context=str(tag)[:300],
                    metadata={"description": f"通过 {tag.name} 元素的 inline style 隐藏"},
                ))

            # opacity:0
            if "opacity:0" in style and "display:none" not in style:
                findings.append(Finding(
                    rule_id="html:dom:zero_opacity",
                    severity=4,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=str(tag)[:200],
                    context=str(tag)[:300],
                    metadata={"description": f"{tag.name} 元素 opacity 为 0"},
                ))

            # 定位到屏幕外
            if re.search(r'(?:left|top)\s*:\s*-\d{3,}px', style) or \
               re.search(r'position\s*:\s*absolute.*?(?:left|top)\s*:\s*-\d{3,}px', style):
                findings.append(Finding(
                    rule_id="html:dom:offscreen_positioned",
                    severity=5,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=str(tag)[:200],
                    context=str(tag)[:300],
                    metadata={"description": f"{tag.name} 元素被定位到屏幕外"},
                ))

        # hidden 属性和 aria-hidden
        for tag in soup.find_all(attrs={"hidden": True}):
            findings.append(Finding(
                rule_id="html:dom:hidden_attribute",
                severity=2,
                category="hidden_element",
                source_type="html",
                location=source,
                evidence=str(tag)[:200],
                context=str(tag)[:300],
                metadata={"description": f"{tag.name} 元素使用了 hidden 属性"},
            ))

        # 通过 class 名称隐藏
        for tag in soup.find_all(class_=True):
            classes = " ".join(tag.get("class", [])).lower()
            if any(hk in classes for hk in hiding_keywords):
                findings.append(Finding(
                    rule_id="html:dom:hiding_class",
                    severity=3,
                    category="hidden_element",
                    source_type="html",
                    location=source,
                    evidence=f"class=\"{' '.join(tag.get('class', []))}\"",
                    context=str(tag)[:300],
                    metadata={"description": f"{tag.name} 使用隐藏类名: {classes}"},
                ))

        return findings

    @staticmethod
    def _ctx(text: str, start: int, end: int, margin: int = 50) -> str:
        cs = max(0, start - margin)
        ce = min(len(text), end + margin)
        return text[cs:ce].replace("\n", " ").replace("\r", " ")
