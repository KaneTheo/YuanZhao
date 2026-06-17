"""HTTP 客户端 — session 管理、重试、代理、浏览器级请求头."""

from __future__ import annotations

import contextlib
import logging
import ssl

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("yuanzhao.network")


class TLSAdapter(HTTPAdapter):
    """支持旧版 TLS 重协商的适配器."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        with contextlib.suppress(Exception):
            ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.5",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def create_session(
    proxy: str | None = None,
    timeout: float = 30.0,
    max_retries: int = 3,
) -> requests.Session:
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    session.timeout = timeout  # type: ignore[attr-defined]

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )

    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    try:
        session.mount("https://", TLSAdapter(max_retries=retry_strategy))
    except Exception:
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    return session


def fetch_url(
    url: str,
    session: requests.Session | None = None,
    timeout: float = 30.0,
    proxy: str | None = None,
) -> tuple[str, dict] | None:
    """获取 URL 内容，返回 (text, headers_dict) 或 None."""
    if session is None:
        session = create_session(proxy=proxy, timeout=timeout)

    try:
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=timeout)
        if resp.status_code == 404:
            logger.warning("URL 不存在 (404): %s", url)
        elif resp.status_code >= 400:
            logger.warning("URL 返回状态码 %d: %s", resp.status_code, url)

        resp.encoding = resp.apparent_encoding or resp.encoding or "utf-8"
        return resp.text, dict(resp.headers)

    except requests.exceptions.Timeout:
        logger.error("请求超时 (%ds): %s", timeout, url)
    except requests.exceptions.RequestException as e:
        logger.error("请求失败: %s — %s", url, e)
    return None
