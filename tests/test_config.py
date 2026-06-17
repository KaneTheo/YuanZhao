"""ScanConfig 测试."""

import os

from yuanzhao.config import ReportFormat, ScanConfig, ScanMode, TargetType


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE)
        assert cfg.mode == ScanMode.DEEP
        assert cfg.depth == 3
        assert cfg.threads == 8
        assert cfg.timeout == 30.0
        assert cfg.report_format == ReportFormat.TXT
        assert cfg.report_dir == os.path.join(os.getcwd(), "reports")

    def test_fast_mode_properties(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE, mode=ScanMode.FAST)
        assert cfg.scan_html is True
        assert cfg.scan_js is False
        assert cfg.scan_css is False
        assert cfg.scan_special_hiding is False
        assert cfg.scan_steganography is False
        assert ".html" in cfg.file_extensions
        assert ".js" not in cfg.file_extensions
        assert ".css" not in cfg.file_extensions

    def test_standard_mode_properties(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE, mode=ScanMode.STANDARD)
        assert cfg.scan_html is True
        assert cfg.scan_js is True
        assert cfg.scan_css is True
        assert cfg.scan_special_hiding is True
        assert cfg.scan_steganography is False
        for ext in (".html", ".js", ".css"):
            assert ext in cfg.file_extensions

    def test_deep_mode_properties(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE, mode=ScanMode.DEEP)
        assert cfg.scan_html is True
        assert cfg.scan_js is True
        assert cfg.scan_css is True
        assert cfg.scan_special_hiding is True
        assert cfg.scan_steganography is True

    def test_proxy_dict(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE, proxy="http://127.0.0.1:8080")
        assert cfg.get_proxy_dict() == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

    def test_no_proxy(self):
        cfg = ScanConfig(target="test.html", target_type=TargetType.LOCAL_FILE)
        assert cfg.get_proxy_dict() is None

    def test_custom_values(self):
        cfg = ScanConfig(
            target="https://example.com",
            target_type=TargetType.EXTERNAL_URL,
            mode=ScanMode.FAST,
            depth=1,
            threads=4,
            timeout=10.0,
            headless=True,
            js_wait=5.0,
        )
        assert cfg.depth == 1
        assert cfg.threads == 4
        assert cfg.timeout == 10.0
        assert cfg.headless is True
        assert cfg.js_wait == 5.0


class TestScanMode:
    def test_values(self):
        assert ScanMode.FAST.value == "fast"
        assert ScanMode.STANDARD.value == "standard"
        assert ScanMode.DEEP.value == "deep"

    def test_from_string(self):
        assert ScanMode("fast") == ScanMode.FAST
        assert ScanMode("deep") == ScanMode.DEEP


class TestReportFormat:
    def test_values(self):
        assert ReportFormat.TXT.value == "txt"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.CSV.value == "csv"
