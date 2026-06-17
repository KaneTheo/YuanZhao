"""报告生成器测试."""

import json

import pytest

from yuanzhao.detectors.base import Finding
from yuanzhao.reporters.csv_reporter import CSVReporter
from yuanzhao.reporters.html import HTMLReporter
from yuanzhao.reporters.json_reporter import JSONReporter
from yuanzhao.reporters.text import TextReporter


@pytest.fixture
def sample_findings():
    return [
        Finding(
            rule_id="html:suspicious_url", severity=5, category="suspicious_url",
            source_type="html", location="index.html",
            evidence="https://evil.xyz/malware",
            context='<a href="https://evil.xyz/malware">',
            position=(100, 130),
            metadata={"reasons": ["外部链接", "高风险域名后缀 .xyz"]},
        ),
        Finding(
            rule_id="keyword:赌博", severity=8, category="keyword_match",
            source_type="text", location="index.html",
            evidence="赌博", context="包含 赌博 的句子",
            position=(200, 202),
            metadata={"keyword": "赌博", "category": "博彩", "weight": 8},
        ),
        Finding(
            rule_id="hiding:display_none", severity=7, category="hidden_element",
            source_type="css", location="style.css",
            evidence="display: none",
            context=".hidden { display: none; }",
            position=(10, 15),
            metadata={"technique": "显示隐藏"},
        ),
    ]


class TestTextReporter:
    def test_generate(self, tmp_path, sample_findings):
        path = tmp_path / "report.txt"
        reporter = TextReporter(path)
        out = reporter.generate(sample_findings, {"target": "test.html", "mode": "deep", "duration": "1.23s",
                                                    "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)
        content = path.read_text(encoding="utf-8")
        assert "渊照" in content
        assert "evil.xyz" in content
        assert "赌博" in content


class TestHTMLReporter:
    def test_generate(self, tmp_path, sample_findings):
        path = tmp_path / "report.html"
        reporter = HTMLReporter(path)
        out = reporter.generate(sample_findings, {"target": "test.html", "mode": "deep", "duration": "1.23s",
                                                    "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)
        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content.lower() or "<html" in content.lower()
        assert "evil.xyz" in content
        assert "赌博" in content

    def test_empty_findings(self, tmp_path):
        path = tmp_path / "empty.html"
        reporter = HTMLReporter(path)
        out = reporter.generate([], {"target": "clean.html", "mode": "deep", "duration": "0.01s",
                                      "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)
        assert path.exists()


class TestJSONReporter:
    def test_generate(self, tmp_path, sample_findings):
        path = tmp_path / "report.json"
        reporter = JSONReporter(path)
        out = reporter.generate(sample_findings, {"target": "test.html", "mode": "deep", "duration": "1.23s",
                                                    "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["report"]["tool"] == "渊照 YuanZhao"
        assert len(data["findings"]) == 3
        assert data["statistics"]["suspicious_urls"] == 1
        assert data["statistics"]["keyword_matches"] == 1
        assert data["statistics"]["hidden_elements"] == 1

    def test_empty_findings(self, tmp_path):
        path = tmp_path / "empty.json"
        reporter = JSONReporter(path)
        out = reporter.generate([], {"target": "clean.html", "mode": "fast", "duration": "0.01s",
                                      "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["statistics"]["total_findings"] == 0


class TestCSVReporter:
    def test_generate(self, tmp_path, sample_findings):
        path = tmp_path / "report.csv"
        reporter = CSVReporter(path)
        out = reporter.generate(sample_findings, {"target": "test.html", "mode": "deep", "duration": "1.23s",
                                                    "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)
        content = path.read_text(encoding="utf-8-sig")
        assert "evil.xyz" in content
        assert "赌博" in content

    def test_empty_findings(self, tmp_path):
        path = tmp_path / "empty.csv"
        reporter = CSVReporter(path)
        out = reporter.generate([], {"target": "clean.html", "mode": "fast", "duration": "0.01s",
                                      "scanned_files": 1, "scanned_urls": 0})
        assert out == str(path)

    def test_formula_injection_prevention(self, tmp_path):
        findings = [Finding(
            rule_id="test", severity=1, category="test", source_type="text",
            location="test.txt", evidence="=cmd|' /C calc'!A0",
            context="=cmd|' /C calc'!A0",
        )]
        path = tmp_path / "safe.csv"
        reporter = CSVReporter(path)
        reporter.generate(findings, {"target": "test", "mode": "fast", "duration": "1s",
                                      "scanned_files": 1, "scanned_urls": 0})
        content = path.read_text(encoding="utf-8-sig")
        # The = sign should be prefixed with a single quote
        assert "'=cmd" in content or "=cmd" not in content


class TestReporterBase:
    def test_ensure_dir(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "report.txt"
        reporter = TextReporter(nested)
        reporter._ensure_dir()
        assert nested.parent.exists()
