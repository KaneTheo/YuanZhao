"""关键字检测器测试."""

import pytest

from yuanzhao.detectors.keyword import KeywordDetector


@pytest.fixture
def detector():
    return KeywordDetector()


class TestKeywordDetector:
    def test_init_loads_keywords(self, detector):
        assert len(detector._patterns) > 0

    def test_detect_basic(self, detector):
        findings = detector.detect("This page contains 赌博 content", "test.html")
        assert len(findings) >= 1
        assert any("赌博" in str(f.metadata) for f in findings)

    def test_no_match(self, detector):
        findings = detector.detect("Hello world, this is a normal page", "test.html")
        assert len(findings) == 0

    def test_severity_descending(self, detector):
        content = "赌博 博彩 casino bet"
        findings = detector.detect(content, "test.html")
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, reverse=True)

    def test_finding_structure(self, detector):
        findings = detector.detect("This page has 赌博 content", "test.html")
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id.startswith("keyword:")
        assert f.category == "keyword_match"
        assert f.source_type == "text"
        assert f.location == "test.html"
        assert f.context != ""

    def test_duplicate_prevention(self, detector):
        # Same keyword appearing twice — second should be tracked
        findings = detector.detect("赌博 and 赌博 again", "test.html")
        gambling_findings = [f for f in findings if "赌博" in f.evidence]
        assert len(gambling_findings) == 2  # two distinct positions

    def test_word_boundary_for_short_ascii(self, tmp_path):
        # Short (<=2) ASCII keywords use word boundaries via custom keyword file
        csv_path = tmp_path / "short.csv"
        csv_path.write_text("AV,malware,8\n", encoding="utf-8")
        d = KeywordDetector(keyword_file=str(csv_path))
        findings = d.detect("JAVASCRIPT AV", "test.html")
        av_findings = [f for f in findings if f.evidence == "AV"]
        assert len(av_findings) == 1  # only standalone AV, not inside JAVASCRIPT

    def test_custom_keyword_file(self, tmp_path):
        csv_path = tmp_path / "custom.csv"
        csv_path.write_text("testkeyword,gambling,8\n", encoding="utf-8")
        d = KeywordDetector(keyword_file=str(csv_path))
        findings = d.detect("testkeyword here", "test.html")
        assert len(findings) == 1
        assert findings[0].evidence == "testkeyword"
        assert findings[0].severity == 8
