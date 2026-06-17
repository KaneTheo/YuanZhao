"""CSS 检测器测试."""

import pytest

from yuanzhao.detectors.css import CSSDetector
from yuanzhao.rules.loader import load_yaml_rules


@pytest.fixture
def detector():
    rules = load_yaml_rules()
    return CSSDetector(rules=rules)


class TestCSSDetector:
    def test_display_none(self, detector):
        findings = detector.detect(".hidden { display: none; }", "test.css")
        hidden = [f for f in findings if "display" in f.rule_id]
        assert len(hidden) >= 1

    def test_visibility_hidden(self, detector):
        findings = detector.detect(".invisible { visibility: hidden; }", "test.css")
        hidden = [f for f in findings if "visibility" in f.rule_id]
        assert len(hidden) >= 1

    def test_opacity_zero(self, detector):
        findings = detector.detect(".zero { opacity: 0; }", "test.css")
        hidden = [f for f in findings if "opacity" in f.rule_id]
        assert len(hidden) >= 1

    def test_absolute_position_off_screen(self, detector):
        findings = detector.detect(".off { position: absolute; left: -9999px; }", "test.css")
        pos_findings = [f for f in findings if f.rule_id == "css:hiding:absolute_pos"]
        assert len(pos_findings) >= 1

    def test_background_image_url(self, detector):
        findings = detector.detect(
            "body { background-image: url(https://external.example.com/bg.jpg); }",
            "test.css",
        )
        bg_findings = [f for f in findings if f.rule_id == "css:property:bg_ext"]
        assert len(bg_findings) >= 1

    def test_long_class_name(self, detector):
        findings = detector.detect(".this_is_a_very_long_class_name_that_looks_suspicious { color: red; }", "test.css")
        long_findings = [f for f in findings if f.rule_id == "css:selector:long_class"]
        assert len(long_findings) >= 1

    def test_long_id_name(self, detector):
        findings = detector.detect("#this_is_a_very_long_id { color: blue; }", "test.css")
        long_findings = [f for f in findings if f.rule_id == "css:selector:long_id"]
        assert len(long_findings) >= 1

    def test_external_import(self, detector):
        findings = detector.detect(
            '@import url("https://suspicious.xyz/theme.css");',
            "test.css",
        )
        import_findings = [f for f in findings if f.rule_id == "css:import:external"]
        assert len(import_findings) >= 1

    def test_suspicious_comment_keywords(self, detector):
        findings = detector.detect(
            "/* hidden stealth cloaking obfuscate invisible */\n.selector { color: red; }",
            "test.css",
        )
        comment_findings = [f for f in findings if f.rule_id == "css:comment:suspicious"]
        assert len(comment_findings) >= 1

    def test_obfuscation_long_names(self, detector):
        rules = ".long_name_abcdefghijklm {}\n" * 10
        findings = detector.detect(rules, "test.css")
        obfuscation = [f for f in findings if f.rule_id == "css:obfuscation:long_names"]
        assert len(obfuscation) >= 1

    def test_control_characters(self, detector):
        content = "body { color: red; } " + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c" * 3
        findings = detector.detect(content, "test.css")
        ctrl = [f for f in findings if f.rule_id == "css:obfuscation:control_chars"]
        assert len(ctrl) >= 1

    def test_normal_css(self, detector):
        findings = detector.detect("body{color:#333;font-size:16px;}", "test.css")
        # No hiding, no suspicious URLs
        hiding = [f for f in findings if f.category == "hidden_element"]
        assert len(hiding) == 0

    def test_empty_content(self, detector):
        findings = detector.detect("", "empty.css")
        assert len(findings) == 0
