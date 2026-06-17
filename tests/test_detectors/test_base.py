"""Finding 数据类和 BaseDetector 测试."""

import pytest

from yuanzhao.detectors.base import BaseDetector, Finding


class TestFinding:
    def test_create_minimal(self):
        f = Finding(rule_id="test:rule", severity=5, category="test", source_type="text", location="test.txt", evidence="test")
        assert f.rule_id == "test:rule"
        assert f.severity == 5
        assert f.category == "test"
        assert f.context == ""
        assert f.position == (0, 0)
        assert f.metadata == {}

    def test_create_full(self):
        f = Finding(
            rule_id="html:test", severity=7, category="suspicious_url",
            source_type="html", location="index.html",
            evidence="https://evil.com", context="<a href=\"https://evil.com\">",
            position=(10, 40), metadata={"reason": "bad"},
        )
        assert f.evidence == "https://evil.com"
        assert f.context == "<a href=\"https://evil.com\">"
        assert f.position == (10, 40)
        assert f.metadata["reason"] == "bad"

    def test_equality(self):
        f1 = Finding(rule_id="x", severity=5, category="c", source_type="t", location="l", evidence="e")
        f2 = Finding(rule_id="x", severity=5, category="c", source_type="t", location="l", evidence="e")
        assert f1 == f2

    def test_not_equal(self):
        f1 = Finding(rule_id="x", severity=5, category="c", source_type="t", location="l", evidence="e")
        f2 = Finding(rule_id="y", severity=5, category="c", source_type="t", location="l", evidence="e")
        assert f1 != f2


class TestBaseDetector:
    def test_abstract_class(self):
        with pytest.raises(TypeError):
            BaseDetector()  # type: ignore

    def test_concrete_subclass(self):
        class SimpleDetector(BaseDetector):
            def detect(self, content, source):
                return [Finding(rule_id="simple:test", severity=1, category="test", source_type="text", location=source, evidence=content)]

        d = SimpleDetector()
        findings = d.detect("hello", "test.txt")
        assert len(findings) == 1
        assert findings[0].evidence == "hello"

    def test_rules_passed(self):
        class RuleDetector(BaseDetector):
            def detect(self, content, source):
                threshold = self.rules.get("threshold", 5)
                return [Finding(rule_id="test", severity=threshold, category="test", source_type="text", location=source, evidence=content)]

        d = RuleDetector(rules={"threshold": 9})
        findings = d.detect("data", "file.txt")
        assert findings[0].severity == 9

    def test_enabled_default(self):
        class MyDetector(BaseDetector):
            def detect(self, content, source):
                return []

        d = MyDetector()
        assert d.enabled(None) is True
