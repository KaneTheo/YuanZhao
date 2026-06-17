"""JavaScript 检测器测试."""

import pytest

from yuanzhao.detectors.javascript import JSDetector, _entropy
from yuanzhao.rules.loader import load_yaml_rules


@pytest.fixture
def detector():
    rules = load_yaml_rules()
    return JSDetector(rules=rules)


class TestEntropy:
    def test_low_entropy(self):
        assert _entropy("aaaaaaaaaa") < 1.0

    def test_high_entropy(self):
        # Random-like string should have high entropy
        text = "k7jF9xL3mN8qR2wP5yV6" * 5
        assert _entropy(text) > 3.0

    def test_empty_string(self):
        assert _entropy("") == 0.0


class TestJSDetector:
    def test_detect_eval(self, detector):
        findings = detector.detect("eval('alert(1)')", "test.js")
        eval_findings = [f for f in findings if f.rule_id == "js:high_risk:eval"]
        assert len(eval_findings) >= 1

    def test_detect_document_cookie(self, detector):
        findings = detector.detect("document.cookie = 'x=1'", "test.js")
        cookie_findings = [f for f in findings if f.rule_id == "js:pattern:cookie"]
        assert len(cookie_findings) >= 1

    def test_detect_navigator_useragent(self, detector):
        findings = detector.detect("var ua = navigator.userAgent", "test.js")
        ua_findings = [f for f in findings if f.rule_id == "js:pattern:user_agent"]
        assert len(ua_findings) >= 1

    def test_detect_self_executing(self, detector):
        findings = detector.detect("function(){}(); (x)();", "test.js")
        self_exec = [f for f in findings if f.rule_id == "js:pattern:self_executing"]
        assert len(self_exec) >= 1

    def test_obfuscation_hex_encoding(self, detector):
        content = r"\x41\x42\x43\x44\x45" * 3
        findings = detector.detect(content, "test.js")
        hex_findings = [f for f in findings if f.rule_id == "js:obfuscation:hex_encoding"]
        assert len(hex_findings) >= 1

    def test_obfuscation_unicode_encoding(self, detector):
        content = "\\u0041\\u0042\\u0043\\u0044\\u0045" * 3
        findings = detector.detect(content, "test.js")
        uni_findings = [f for f in findings if f.rule_id == "js:obfuscation:unicode_encoding"]
        assert len(uni_findings) >= 1

    def test_suspicious_comments(self, detector):
        content = "// backdoor trojan malware exploit hack"
        findings = detector.detect(content, "test.js")
        comment_findings = [f for f in findings if f.rule_id == "js:comment:suspicious"]
        assert len(comment_findings) > 0

    def test_comment_base64_detection(self, detector):
        content = "/* dGhpcyBpc250IHJlYWxseSBiYXNlNjQgZGF0YSwganVzdCBsb29rcyBsaWtlIGl0IHRob3VnaA== some padding to make this over 50 chars */"
        findings = detector.detect(content, "test.js")
        b64_findings = [f for f in findings if f.rule_id == "js:comment:base64"]
        assert len(b64_findings) >= 1

    def test_external_url_detection(self, detector):
        content = 'var url = "https://external.xyz/malware.js"'
        findings = detector.detect(content, "https://example.com/page")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) > 0

    def test_dom_manipulation(self, detector):
        findings = detector.detect("element.appendChild(evil); element.innerHTML = x", "test.js")
        dom_findings = [f for f in findings if f.rule_id in ("js:dom:appendChild", "js:high_risk:appendChild", "js:dom:innerHTML", "js:high_risk:innerHTML")]
        assert len(dom_findings) > 0

    def test_high_entropy(self, detector):
        # Generate high-entropy content
        import random
        random.seed(42)
        content = "".join(chr(random.randint(32, 126)) for _ in range(500))
        findings = detector.detect(content, "test.js")
        entropy_findings = [f for f in findings if "entropy" in f.rule_id]
        assert len(entropy_findings) >= 1

    def test_low_entropy(self, detector):
        content = "function add(a, b) { return a + b; } " * 20
        findings = detector.detect(content, "test.js")
        entropy_findings = [f for f in findings if "entropy" in f.rule_id]
        # Normal code should not have entropy warnings
        high_entropy = [f for f in entropy_findings if f.rule_id == "js:entropy:high"]
        assert len(high_entropy) == 0

    def test_clean_js(self, detector):
        content = "function hello() { console.log('world'); }"
        findings = detector.detect(content, "test.js")
        assert isinstance(findings, list)
        # Only pattern matches like function calls — no high-risk ones
        high_risk = [f for f in findings if f.severity >= 4]
        assert len(high_risk) == 0
