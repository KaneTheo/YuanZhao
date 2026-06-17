"""URL 解析、域名提取、风险分析."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    return urlparse(url).netloc.lower() or ""


def is_external_link(url: str, base_domain: str | None = None) -> bool:
    url_domain = extract_domain(url)
    if not url_domain:
        return False
    if not base_domain:
        return url.startswith(("http://", "https://"))
    return not (url_domain == base_domain or url_domain.endswith(f".{base_domain}"))


def analyze_url_risk(url: str) -> dict[str, Any]:
    """评估 URL 风险等级，返回 {risk_level: int, reasons: list[str]}."""
    risk = 0
    reasons: list[str] = []
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    domain = parsed.netloc.lower()

    if scheme == "javascript":
        risk += 5
        reasons.append("JavaScript 伪协议")
    elif scheme == "data":
        risk += 4
        reasons.append("Data URI")
    elif scheme in ("http", "https"):
        risk += 1

    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        risk += 2
        reasons.append("非标准端口")

    suspicious_tlds = {"pro", "xyz", "pw", "top", "loan", "win", "bid", "online", "tk", "ga", "gq", "ml", "cf"}
    for tld in suspicious_tlds:
        if domain.endswith(f".{tld}"):
            risk += 2
            reasons.append(f"高风险域名后缀 .{tld}")
            break

    short_link_domains = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "adf.ly"}
    if any(domain == sl or domain.endswith(f".{sl}") for sl in short_link_domains):
        risk += 3
        reasons.append("短链接服务")

    if re.search(r"/[a-zA-Z0-9]{8,}\.(?:js|php)$", parsed.path):
        risk += 1
        reasons.append("可疑随机路径")

    return {"risk_level": min(risk, 10), "reasons": reasons}


def extract_urls(text: str, source_type: str = "unknown") -> list[dict[str, Any]]:
    """从文本中提取所有 URL，返回 {url, context, position, source_type} 列表."""
    patterns = [
        re.compile(r'(https?://[^\s<>"\']+)', re.IGNORECASE),
        re.compile(r'(/(?!/)[-\w./?%&=#]+)', re.IGNORECASE),
        re.compile(r'(javascript:[^\s<>"\']+)', re.IGNORECASE),
        re.compile(r'(data:[^;]+;base64,[^\s<>"\']+)', re.IGNORECASE),
    ]
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern in patterns:
        for m in pattern.finditer(text):
            url = m.group(1).strip("'\"")
            if not url or len(url) < 3 or url in seen:
                continue
            # Skip relative paths that are substrings of already-extracted full URLs
            if url.startswith("/") and any(url in u for u in seen if u.startswith("http")):
                continue
            seen.add(url)
            ctx_start = max(0, m.start() - 50)
            ctx_end = min(len(text), m.end() + 50)
            results.append({
                "url": url,
                "context": text[ctx_start:ctx_end],
                "position": (m.start(), m.end()),
                "source_type": source_type,
            })

    return results


_TRUSTED_CDN = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "unpkg.com", "cdn.staticfile.org", "stackpath.bootstrapcdn.com",
    "cdn.bootcdn.net", "hm.baidu.com", "www.googletagmanager.com",
}


def is_trusted_cdn(url: str) -> bool:
    domain = extract_domain(url)
    if not domain:
        return False
    return any(domain == td or domain.endswith(f".{td}") for td in _TRUSTED_CDN)
