"""无头浏览器检测器 — 动态内容、DOM 操作、iframe 内容、隐藏元素（计算样式）."""

from __future__ import annotations

import logging

from yuanzhao.detectors.base import BaseDetector, Finding
from yuanzhao.network.utils import analyze_url_risk

logger = logging.getLogger("yuanzhao.detectors.headless")


class HeadlessDetector(BaseDetector):
    """使用 Selenium Chrome 无头浏览器进行动态内容检测."""

    def __init__(self, rules=None, *,
                 headless_binary: str | None = None,
                 headless_driver: str | None = None,
                 headless_timeout: float = 60.0,
                 js_wait: float = 3.0,
                 user_agent: str = "chrome"):
        super().__init__(rules)
        self._driver = None
        self._binary = headless_binary
        self._driver_path = headless_driver
        self._timeout = headless_timeout
        self._js_wait = js_wait
        self._user_agent = user_agent

    def enabled(self, config) -> bool:
        return getattr(config, "headless", False)

    @property
    def driver(self):
        if self._driver is None:
            self._init_driver()
        return self._driver

    def _init_driver(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service

            from yuanzhao.network.client import _resolve_ua

            opts = Options()
            if self._binary:
                opts.binary_location = self._binary
            opts.add_argument("--headless")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--window-size=1920,1080")
            opts.add_argument("--log-level=3")
            ua = _resolve_ua(self._user_agent)
            opts.add_argument(f"--user-agent={ua}")

            if self._driver_path:
                service = Service(self._driver_path)
            else:
                from webdriver_manager.chrome import ChromeDriverManager
                service = Service(ChromeDriverManager().install())

            self._driver = webdriver.Chrome(service=service, options=opts)
            self._driver.set_page_load_timeout(self._timeout)
            self._driver.set_script_timeout(self._timeout)
            logger.info("Chrome 无头浏览器初始化成功")

        except ImportError:
            logger.error("缺少无头浏览器依赖: pip install yuanzhao[headless]")
        except Exception as e:
            logger.error("无头浏览器初始化失败: %s", e)

    def detect(self, content: str, source: str) -> list[Finding]:
        if not self._driver and not self._init_driver():
            return []

        findings: list[Finding] = []
        url = source  # 对于无头浏览器，source 应为 URL

        try:
            self._driver.get(url)
            from selenium.webdriver.support.ui import WebDriverWait
            try:
                WebDriverWait(self._driver, self._js_wait).until(
                    lambda d: d.execute_script("return document.readyState") in ("complete", "interactive")
                )
            except Exception as e:
                logger.warning("等待页面加载超时，继续执行检测: %s", e)

            findings.extend(self._detect_dynamic_links(url))
            findings.extend(self._detect_hidden_elements(url))
            findings.extend(self._detect_iframe_content(url))

        except Exception as e:
            logger.error("无头浏览器检测出错: %s", e)

        return findings

    def _detect_dynamic_links(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            from selenium.webdriver.common.by import By
            links = self._driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href:
                        risk_info = analyze_url_risk(href)
                        if risk_info["risk_level"] > 0:
                            text = link.text.strip()[:100]
                            findings.append(Finding(
                                rule_id="headless:dynamic_link",
                                severity=risk_info["risk_level"],
                                category="suspicious_url",
                                source_type="dynamic",
                                location=source,
                                evidence=href,
                                context=f"动态链接: {text}",
                                metadata={"element": "a", "reasons": risk_info["reasons"]},
                            ))
                except Exception as e:
                    logger.debug("跳过异常链接元素: %s", e)
        except Exception as e:
            logger.error("检测动态链接出错: %s", e)
        return findings

    def _detect_hidden_elements(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        script = """
        (function() {
            var results = [];
            var all = document.querySelectorAll('*');
            all.forEach(function(el) {
                var style = window.getComputedStyle(el);
                var rect = el.getBoundingClientRect();
                var isHidden = style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    style.opacity === '0' ||
                    rect.width <= 1 || rect.height <= 1 ||
                    parseInt(style.fontSize) <= 0;
                var isOffScreen = style.position === 'absolute' &&
                    (parseInt(style.left) < -1000 || parseInt(style.top) < -1000);
                var hasLinks = el.querySelector('a') !== null;
                var hasText = el.textContent.trim().length > 0;
                if ((isHidden || isOffScreen) && (hasLinks || hasText)) {
                    var links = [];
                    el.querySelectorAll('a').forEach(function(a) {
                        var h = a.getAttribute('href');
                        if (h) links.push(h);
                    });
                    results.push({
                        tag: el.tagName,
                        text: el.textContent.trim().substring(0, 200),
                        links: links,
                        technique: isOffScreen ? 'off_screen' : 'visibility'
                    });
                }
            });
            return results;
        })();
        """
        try:
            elements = self._driver.execute_script(script)
            for elem in elements or []:
                sev = 8 if elem.get("links") else 6
                findings.append(Finding(
                    rule_id="headless:hidden_element",
                    severity=sev,
                    category="hidden_element",
                    source_type="dynamic",
                    location=source,
                    evidence=f"<{elem['tag']}>: {elem.get('text', '')}",
                    context=elem.get("text", ""),
                    metadata={
                        "technique": elem.get("technique", ""),
                        "tag": elem.get("tag", ""),
                        "links": elem.get("links", []),
                    },
                ))
                for link in elem.get("links", []) or []:
                    risk_info = analyze_url_risk(link)
                    findings.append(Finding(
                        rule_id="headless:hidden_link",
                        severity=max(sev, risk_info["risk_level"]),
                        category="suspicious_url",
                        source_type="dynamic",
                        location=source,
                        evidence=link,
                        context=f"隐藏元素中的链接: {link}",
                        metadata={"reasons": ["隐藏在 " + elem.get("technique", "") + " 元素中"]},
                    ))
        except Exception as e:
            logger.error("检测隐藏元素出错: %s", e)
        return findings

    def _detect_iframe_content(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            from selenium.webdriver.common.by import By
            iframes = self._driver.find_elements(By.TAG_NAME, "iframe")
            for iframe in iframes:
                try:
                    src = iframe.get_attribute("src")
                    if src:
                        risk_info = analyze_url_risk(src)
                        if risk_info["risk_level"] > 0:
                            findings.append(Finding(
                                rule_id="headless:iframe",
                                severity=risk_info["risk_level"],
                                category="suspicious_url",
                                source_type="dynamic",
                                location=source,
                                evidence=src,
                                context=f"iframe src: {src}",
                                metadata={"reasons": risk_info["reasons"]},
                            ))
                except Exception as e:
                    logger.debug("跳过异常 iframe 元素: %s", e)
        except Exception as e:
            logger.error("检测 iframe 出错: %s", e)
        return findings

    def close(self):
        if self._driver:
            try:
                self._driver.quit()
            except Exception as e:
                logger.warning("关闭浏览器驱动时出错: %s", e)
            self._driver = None
