"""扫描引擎 — 调度检测器、线程池并发、结果聚合."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time

from yuanzhao.config import ScanConfig, TargetType
from yuanzhao.detectors.base import Finding
from yuanzhao.detectors.css import CSSDetector
from yuanzhao.detectors.custom_rules import CustomRulesDetector
from yuanzhao.detectors.hiding import SpecialHidingDetector
from yuanzhao.detectors.html import HTMLDetector
from yuanzhao.detectors.javascript import JSDetector
from yuanzhao.detectors.keyword import KeywordDetector
from yuanzhao.files.utils import collect_files, is_binary_file, read_file
from yuanzhao.network.client import create_session, fetch_url
from yuanzhao.rules.loader import load_yaml_rules

logger = logging.getLogger("yuanzhao.scanner")


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.rules = load_yaml_rules()
        self._lock = threading.Lock()
        self._scanned: set[str] = set()

        # 初始化检测器
        self._detectors: list = []
        self._init_detectors()

    def _init_detectors(self):
        cfg = self.config
        self._detectors.append(KeywordDetector(keyword_file=cfg.keyword_file, rules=self.rules))

        if cfg.scan_html:
            self._detectors.append(HTMLDetector(rules=self.rules))
        if cfg.scan_js:
            self._detectors.append(JSDetector(rules=self.rules))
        if cfg.scan_css:
            self._detectors.append(CSSDetector(rules=self.rules))
        if cfg.scan_special_hiding:
            self._detectors.append(SpecialHidingDetector(rules=self.rules))
        if cfg.rules_file:
            self._detectors.append(CustomRulesDetector(rules=self.rules, rules_file=cfg.rules_file))

        # 无头浏览器按需加载
        if cfg.headless:
            try:
                from yuanzhao.detectors.headless import HeadlessDetector
                hd = HeadlessDetector(
                    rules=self.rules,
                    headless_binary=cfg.headless_binary,
                    headless_driver=cfg.headless_driver,
                    headless_timeout=cfg.headless_timeout,
                    js_wait=cfg.js_wait,
                    user_agent=cfg.user_agent,
                )
                self._detectors.append(hd)
                self._headless = hd
            except ImportError:
                logger.warning("无头浏览器依赖未安装，跳过")
                self._headless = None
        else:
            self._headless = None

    def scan(self, targets: list[tuple[str, TargetType]]) -> dict:
        """执行扫描，返回聚合结果字典."""
        start = time.time()
        aggregated: dict[str, list] = {
            "findings": [],
            "scanned_files": [],
            "scanned_urls": [],
            "errors": [],
        }
        total = len(targets)

        logger.info("开始扫描 %d 个目标", total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {
                pool.submit(self._scan_single, target, ttype): target
                for target, ttype in targets
            }
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    with self._lock:
                        if result:
                            aggregated["findings"].extend(result.get("findings", []))
                            aggregated["scanned_files"].extend(result.get("scanned_files", []))
                            aggregated["scanned_urls"].extend(result.get("scanned_urls", []))
                            aggregated["errors"].extend(result.get("errors", []))
                except Exception as e:
                    logger.error("扫描目标失败 %s: %s", target, e)

        elapsed = time.time() - start
        aggregated["scan_time"] = elapsed
        aggregated["total_scanned"] = len(aggregated["scanned_files"]) + len(aggregated["scanned_urls"])

        summary = {
            "suspicious_links": [f for f in aggregated["findings"] if f.category == "suspicious_url"],
            "hidden_elements": [f for f in aggregated["findings"] if f.category == "hidden_element"],
            "keyword_matches": [f for f in aggregated["findings"] if f.category == "keyword_match"],
            "js_issues": [f for f in aggregated["findings"] if f.category == "js_issue"],
            "css_issues": [f for f in aggregated["findings"] if f.category == "css_issue"],
        }
        aggregated["summary"] = summary
        return aggregated

    def _scan_single(self, target: str, ttype: TargetType) -> dict | None:
        if ttype in (TargetType.INTERNAL_URL, TargetType.EXTERNAL_URL):
            return self._scan_url(target, ttype)
        elif ttype == TargetType.LOCAL_FILE:
            return self._scan_file(target)
        elif ttype == TargetType.LOCAL_DIRECTORY:
            return self._scan_directory(target)
        return None

    def _scan_url(self, url: str, ttype: TargetType) -> dict:
        with self._lock:
            if url in self._scanned:
                return {}
            self._scanned.add(url)

        timeout = self.config.internal_timeout if ttype == TargetType.INTERNAL_URL else self.config.external_timeout
        session = create_session(proxy=self.config.proxy, timeout=timeout, user_agent=self.config.user_agent)
        result = fetch_url(url, session=session, timeout=timeout, user_agent=self.config.user_agent)

        if result is None:
            return {"errors": [f"获取失败: {url}"], "findings": [], "scanned_files": [], "scanned_urls": [url]}

        content, _headers = result
        findings: list[Finding] = []

        for detector in self._detectors:
            if detector.enabled(self.config):
                try:
                    findings.extend(detector.detect(content, url))
                except Exception as e:
                    logger.error("检测器 %s 出错 (%s): %s", type(detector).__name__, url, e)

        return {
            "findings": findings,
            "scanned_urls": [url],
            "scanned_files": [],
            "errors": [],
        }

    def _scan_file(self, path: str) -> dict:
        with self._lock:
            if path in self._scanned:
                return {}
            self._scanned.add(path)

        if is_binary_file(path):
            return {"errors": [], "findings": [], "scanned_files": [], "scanned_urls": []}

        content = read_file(path)
        if not content:
            return {"errors": [f"无法读取: {path}"], "findings": [], "scanned_files": [], "scanned_urls": []}

        findings: list[Finding] = []
        for detector in self._detectors:
            if detector.enabled(self.config):
                try:
                    findings.extend(detector.detect(content, path))
                except Exception as e:
                    logger.error("检测器 %s 出错 (%s): %s", type(detector).__name__, path, e)

        return {
            "findings": findings,
            "scanned_files": [path],
            "scanned_urls": [],
            "errors": [],
        }

    def _scan_directory(self, directory: str) -> dict:
        files = collect_files(
            directory,
            extensions=self.config.file_extensions,
            depth=self.config.depth,
            exclude=self.config.exclude,
        )
        if not files:
            return {"errors": [], "findings": [], "scanned_files": [], "scanned_urls": []}

        all_findings: list[Finding] = []
        scanned: list[str] = []
        errors: list[str] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(self._scan_file, f): f for f in files}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_findings.extend(result.get("findings", []))
                        scanned.extend(result.get("scanned_files", []))
                        errors.extend(result.get("errors", []))
                except Exception as e:
                    logger.error("扫描文件失败: %s", e)

        return {
            "findings": all_findings,
            "scanned_files": scanned,
            "scanned_urls": [],
            "errors": errors,
        }

    def cleanup(self):
        if self._headless:
            self._headless.close()
