"""集成测试 — 端到端扫描."""

import json
import os
import tempfile
from pathlib import Path

from yuanzhao.config import ScanConfig, ScanMode, TargetType
from yuanzhao.scanner.engine import ScanEngine
from yuanzhao.scanner.targets import resolve_targets

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _read_fixture(name):
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class TestScanEngine:
    def test_scan_html_file_fast_mode(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.FAST,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])
            assert "findings" in results
            assert results["total_scanned"] >= 1
        finally:
            engine.cleanup()

    def test_scan_html_file_standard_mode(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.STANDARD,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])
            findings = results["findings"]
            assert len(findings) > 0
            # Standard mode should find more than just keywords
            categories = {f.category for f in findings}
            assert len(categories) >= 1
        finally:
            engine.cleanup()

    def test_scan_html_file_deep_mode(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.DEEP,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])
            findings = results["findings"]
            assert len(findings) > 0
            assert "summary" in results
        finally:
            engine.cleanup()

    def test_scan_js_file(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.js"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.STANDARD,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.js"), TargetType.LOCAL_FILE)])
            findings = results["findings"]
            assert len(findings) > 0
            # Should detect JS-specific issues
            js_findings = [f for f in findings if f.category == "js_issue"]
            assert len(js_findings) > 0
        finally:
            engine.cleanup()

    def test_scan_css_file(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.css"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.STANDARD,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.css"), TargetType.LOCAL_FILE)])
            findings = results["findings"]
            assert len(findings) > 0
        finally:
            engine.cleanup()

    def test_scan_directory_standard(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR),
            target_type=TargetType.LOCAL_DIRECTORY,
            mode=ScanMode.STANDARD,
            depth=1,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR), TargetType.LOCAL_DIRECTORY)])
            findings = results["findings"]
            assert len(findings) > 0
            assert results["total_scanned"] >= 2  # at least .html and .css
        finally:
            engine.cleanup()

    def test_summary_categories(self):
        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.DEEP,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])
            summary = results["summary"]
            assert "suspicious_links" in summary
            assert "hidden_elements" in summary
            assert "keyword_matches" in summary
            assert "js_issues" in summary
        finally:
            engine.cleanup()

    def test_clean_html_minimal_findings(self, tmp_path):
        clean = tmp_path / "clean.html"
        clean.write_text("<html><body><p>Hello World</p></body></html>", encoding="utf-8")

        config = ScanConfig(
            target=str(clean),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.FAST,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(clean), TargetType.LOCAL_FILE)])
            findings = results["findings"]
            # Clean page should have very few findings (only keyword matches if patterns match)
            high_severity = [f for f in findings if f.severity >= 4]
            assert len(high_severity) == 0
        finally:
            engine.cleanup()


class TestTargetResolution:
    def test_local_file(self):
        targets = resolve_targets(
            ScanConfig(target=str(FIXTURE_DIR / "sample.html"), target_type=TargetType.LOCAL_FILE)
        )
        assert len(targets) == 1
        assert targets[0][1] == TargetType.LOCAL_FILE

    def test_local_directory(self):
        targets = resolve_targets(
            ScanConfig(target=str(FIXTURE_DIR), target_type=TargetType.LOCAL_DIRECTORY)
        )
        assert len(targets) == 1
        assert targets[0][1] == TargetType.LOCAL_DIRECTORY

    def test_external_url(self):
        config = ScanConfig(
            target="https://example.com",
            target_type=TargetType.EXTERNAL_URL,
        )
        targets = resolve_targets(config)
        assert len(targets) == 1
        assert targets[0][1] == TargetType.EXTERNAL_URL

    def test_target_file_list(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, f"{FIXTURE_DIR / 'sample.html'}\n{FIXTURE_DIR / 'sample.js'}\n".encode())
            os.close(fd)
            config = ScanConfig(
                target="dummy",
                target_type=TargetType.LOCAL_FILE,
            )
            targets = resolve_targets(config, target_file=path)
            assert len(targets) >= 2
        finally:
            os.unlink(path)


class TestEndToEnd:
    def test_full_workflow_html_report(self, tmp_path):
        """End-to-end: scan fixture with all detectors and generate HTML report."""
        from yuanzhao.reporters.html import HTMLReporter

        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.DEEP,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])
            findings = results["findings"]

            assert len(findings) > 0
            assert results["total_scanned"] >= 1
            assert results["scan_time"] >= 0

            report_path = tmp_path / "report.html"
            reporter = HTMLReporter(report_path)
            out = reporter.generate(findings, {
                "target": "sample.html",
                "mode": "deep",
                "duration": f"{results['scan_time']:.2f}s",
                "scanned_files": len(results.get("scanned_files", [])),
                "scanned_urls": len(results.get("scanned_urls", [])),
            })
            assert out == str(report_path)
            assert report_path.exists()
        finally:
            engine.cleanup()

    def test_full_workflow_json_report(self, tmp_path):
        """End-to-end: scan and generate JSON report."""
        from yuanzhao.reporters.json_reporter import JSONReporter

        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.STANDARD,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])

            report_path = tmp_path / "report.json"
            reporter = JSONReporter(report_path)
            reporter.generate(results["findings"], {
                "target": "sample.html",
                "mode": "standard",
                "duration": "0.5s",
                "scanned_files": 1,
                "scanned_urls": 0,
            })

            data = json.loads(report_path.read_text(encoding="utf-8"))
            assert data["report"]["tool"] == "渊照 YuanZhao"
            assert data["statistics"]["total_findings"] > 0
        finally:
            engine.cleanup()

    def test_full_workflow_csv_report(self, tmp_path):
        """End-to-end: scan and generate CSV report."""
        from yuanzhao.reporters.csv_reporter import CSVReporter

        config = ScanConfig(
            target=str(FIXTURE_DIR / "sample.html"),
            target_type=TargetType.LOCAL_FILE,
            mode=ScanMode.STANDARD,
        )
        engine = ScanEngine(config)
        try:
            results = engine.scan([(str(FIXTURE_DIR / "sample.html"), TargetType.LOCAL_FILE)])

            report_path = tmp_path / "report.csv"
            reporter = CSVReporter(report_path)
            reporter.generate(results["findings"], {
                "target": "sample.html",
                "mode": "standard",
                "duration": "0.5s",
                "scanned_files": 1,
                "scanned_urls": 0,
            })
            assert report_path.exists()
        finally:
            engine.cleanup()
