"""配置管理 — CLI 参数 > 环境变量 > 配置文件 > 内置默认值."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class ScanMode(Enum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class TargetType(Enum):
    LOCAL_FILE = "local_file"
    LOCAL_DIRECTORY = "local_directory"
    INTERNAL_URL = "internal_url"
    EXTERNAL_URL = "external_url"


class ReportFormat(Enum):
    TXT = "txt"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


@dataclass
class ScanConfig:
    """单次扫描的不可变配置."""

    target: str
    target_type: TargetType

    # 扫描控制
    mode: ScanMode = ScanMode.DEEP
    depth: int = 3
    threads: int = 8

    # 超时与网络
    timeout: float = 30.0
    internal_timeout: float = 60.0
    external_timeout: float = 30.0
    proxy: str | None = None

    # 文件过滤
    exclude: list[str] = field(default_factory=list)
    html_extensions: tuple[str, ...] = (
        ".html", ".htm", ".shtml", ".xhtml", ".php", ".asp", ".aspx", ".jsp",
    )
    css_extensions: tuple[str, ...] = (".css", ".less", ".scss", ".sass")
    js_extensions: tuple[str, ...] = (".js", ".jsx", ".ts", ".tsx")

    # 关键字与自定义规则
    keyword_file: str | None = None
    rules_file: str | None = None

    # 报告
    report_format: ReportFormat = ReportFormat.TXT
    report_dir: str = field(default_factory=lambda: os.path.join(os.getcwd(), "reports"))

    # 调试
    verbose: bool = False
    no_color: bool = False

    # 无头浏览器
    headless: bool = False
    headless_browser: str = "chrome"
    headless_binary: str | None = None
    headless_driver: str | None = None
    headless_timeout: float = 60.0
    js_wait: float = 3.0

    @property
    def file_extensions(self) -> list[str]:
        exts: set[str] = set()
        if self.mode in (ScanMode.FAST, ScanMode.STANDARD, ScanMode.DEEP):
            exts.update(self.html_extensions)
        if self.mode in (ScanMode.STANDARD, ScanMode.DEEP):
            exts.update(self.js_extensions)
            exts.update(self.css_extensions)
        return sorted(exts)

    @property
    def scan_html(self) -> bool:
        return True

    @property
    def scan_js(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_css(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_iframe(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_dom(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_encoding(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_special_hiding(self) -> bool:
        return self.mode in (ScanMode.STANDARD, ScanMode.DEEP)

    @property
    def scan_steganography(self) -> bool:
        return self.mode == ScanMode.DEEP

    def get_proxy_dict(self) -> dict[str, str] | None:
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}
