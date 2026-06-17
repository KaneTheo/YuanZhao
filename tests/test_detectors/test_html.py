"""HTML 检测器测试."""

import pytest

from yuanzhao.detectors.html import HTMLDetector
from yuanzhao.rules.loader import load_yaml_rules


@pytest.fixture
def detector():
    rules = load_yaml_rules()
    return HTMLDetector(rules=rules)


@pytest.fixture
def sample_html():
    from pathlib import Path
    fixture = Path(__file__).parent.parent / "fixtures" / "sample.html"
    return fixture.read_text(encoding="utf-8")


class TestHTMLDetector:
    def test_detect_suspicious_urls(self, detector, sample_html):
        findings = detector.detect(sample_html, "sample.html")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) > 0

    def test_javascript_pseudo_protocol(self, detector):
        content = '<a href="javascript:eval(\'bad\')">click</a>'
        findings = detector.detect(content, "test.html")
        js_findings = [f for f in findings if "javascript" in str(f.evidence).lower()]
        assert len(js_findings) > 0

    def test_suspicious_tld_url(self, detector):
        content = '<a href="https://evil.xyz/malware">link</a>'
        findings = detector.detect(content, "test.html")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) > 0

    def test_short_link_url(self, detector):
        content = '<a href="https://bit.ly/abc">short</a>'
        findings = detector.detect(content, "test.html")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) > 0

    def test_trusted_cdn_not_flagged(self, detector):
        content = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
        findings = detector.detect(content, "test.html")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) == 0

    def test_hidden_element_detection(self, detector):
        content = '<div style="display:none">hidden</div>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.category == "hidden_element"]
        assert len(hidden) > 0

    def test_visibility_hidden(self, detector):
        content = '<span style="visibility:hidden">hidden</span>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.category == "hidden_element"]
        assert len(hidden) >= 1

    def test_meta_refresh_redirect(self, detector):
        content = '<meta http-equiv="refresh" content="0;url=https://evil.com/phish">'
        findings = detector.detect(content, "test.html")
        meta_findings = [f for f in findings if f.rule_id == "html:meta:refresh"]
        assert len(meta_findings) >= 1
        assert "evil.com" in meta_findings[0].evidence

    def test_comment_with_sensitive_words(self, detector):
        content = '<!-- password: admin123 -->'
        findings = detector.detect(content, "test.html")
        comment_findings = [f for f in findings if f.source_type == "comments"]
        assert len(comment_findings) > 0

    def test_comment_with_link(self, detector):
        content = '<!-- <a href="https://evil.com">hidden link</a> -->'
        findings = detector.detect(content, "test.html")
        link_findings = [f for f in findings if f.rule_id == "html:comment:link"]
        assert len(link_findings) >= 1

    def test_suspicious_patterns(self, detector):
        content = '<div onclick="javascript:alert(1)">click</div>'
        findings = detector.detect(content, "test.html")
        pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
        assert len(pattern_findings) > 0

    def test_empty_content(self, detector):
        findings = detector.detect("", "empty.html")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_clean_html(self, detector):
        findings = detector.detect("<html><body><p>Hello World</p></body></html>", "clean.html")
        url_findings = [f for f in findings if f.category == "suspicious_url"]
        assert len(url_findings) == 0

    # ==================== BS4 DOM 结构化分析测试 ====================

    def test_dom_external_script(self, detector):
        content = '<script src="https://evil.com/malware.js"></script>'
        findings = detector.detect(content, "test.html")
        dom = [f for f in findings if f.rule_id == "html:dom:external_script"]
        assert len(dom) >= 1
        assert "evil.com" in dom[0].evidence

    def test_dom_script_no_sri(self, detector):
        content = '<script src="https://example.com/lib.js"></script>'
        findings = detector.detect(content, "test.html")
        sri = [f for f in findings if f.rule_id == "html:dom:no_sri"]
        assert len(sri) >= 1

    def test_dom_inline_script_eval(self, detector):
        content = '<script>eval("alert(1)")</script>'
        findings = detector.detect(content, "test.html")
        suspicious = [f for f in findings if f.rule_id == "html:dom:suspicious_inline_script"]
        assert len(suspicious) >= 1

    def test_dom_hidden_iframe(self, detector):
        content = '<iframe src="https://bad.com" style="display:none"></iframe>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_iframe"]
        assert len(hidden) >= 1

    def test_dom_zero_size_iframe(self, detector):
        content = '<iframe src="https://bad.com" width="0" height="0"></iframe>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_iframe"]
        assert len(hidden) >= 1

    def test_dom_iframe_no_sandbox(self, detector):
        content = '<iframe src="https://example.com/widget"></iframe>'
        findings = detector.detect(content, "test.html")
        no_sandbox = [f for f in findings if f.rule_id == "html:dom:no_sandbox"]
        assert len(no_sandbox) >= 1

    def test_dom_hidden_link_display_none(self, detector):
        content = '<a href="https://evil.com" style="display:none">hidden</a>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_link"]
        assert len(hidden) >= 1

    def test_dom_hidden_link_opacity_zero(self, detector):
        content = '<a href="https://evil.com" style="opacity:0">hidden</a>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_link"]
        assert len(hidden) >= 1

    def test_dom_hidden_link_font_size_zero(self, detector):
        content = '<a href="https://evil.com" style="font-size:0">hidden</a>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_link"]
        assert len(hidden) >= 1

    def test_dom_hidden_link_offscreen(self, detector):
        content = '<a href="https://evil.com" style="position:absolute;left:-9999px">hidden</a>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_link"]
        assert len(hidden) >= 1

    def test_dom_hidden_link_aria(self, detector):
        content = '<a href="https://evil.com" aria-hidden="true">hidden</a>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_link"]
        assert len(hidden) >= 1

    def test_dom_external_form_action(self, detector):
        content = '<form action="https://evil.com/steal"></form>'
        findings = detector.detect(content, "test.html")
        forms = [f for f in findings if f.rule_id == "html:dom:external_form"]
        assert len(forms) >= 1

    def test_dom_hidden_field_sensitive(self, detector):
        content = '<form><input type="hidden" name="auth_token" value="secret"></form>'
        findings = detector.detect(content, "test.html")
        fields = [f for f in findings if f.rule_id == "html:dom:sensitive_hidden_field"]
        assert len(fields) >= 1

    def test_dom_hidden_field_suspicious_value(self, detector):
        content = '<form><input type="hidden" name="redirect" value="http://evil.com"></form>'
        findings = detector.detect(content, "test.html")
        fields = [f for f in findings if f.rule_id == "html:dom:suspicious_hidden_value"]
        assert len(fields) >= 1

    def test_dom_hidden_attribute(self, detector):
        content = '<div hidden>secret content</div>'
        findings = detector.detect(content, "test.html")
        hidden = [f for f in findings if f.rule_id == "html:dom:hidden_attribute"]
        assert len(hidden) >= 1

    def test_dom_hiding_class(self, detector):
        content = '<div class="visually-hidden">hidden content</div>'
        findings = detector.detect(content, "test.html")
        class_hidden = [f for f in findings if f.rule_id == "html:dom:hiding_class"]
        assert len(class_hidden) >= 1

    def test_dom_styled_hidden(self, detector):
        content = '<span style="display:none">hidden</span>'
        findings = detector.detect(content, "test.html")
        styled = [f for f in findings if f.rule_id == "html:dom:styled_hidden"]
        assert len(styled) >= 1

    def test_dom_zero_opacity(self, detector):
        content = '<p style="opacity:0">invisible</p>'
        findings = detector.detect(content, "test.html")
        opacity = [f for f in findings if f.rule_id == "html:dom:zero_opacity"]
        assert len(opacity) >= 1

    def test_dom_offscreen_positioned(self, detector):
        content = '<div style="position:absolute;left:-9999px;top:-9999px">offscreen</div>'
        findings = detector.detect(content, "test.html")
        offscreen = [f for f in findings if f.rule_id == "html:dom:offscreen_positioned"]
        assert len(offscreen) >= 1

    def test_dom_trusted_cdn_script_not_flagged(self, detector):
        content = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
        findings = detector.detect(content, "test.html")
        ext = [f for f in findings if f.rule_id == "html:dom:external_script"]
        assert len(ext) == 0

    def test_dom_sandboxed_iframe_not_flagged(self, detector):
        content = '<iframe src="https://example.com/widget" sandbox="allow-scripts"></iframe>'
        findings = detector.detect(content, "test.html")
        no_sandbox = [f for f in findings if f.rule_id == "html:dom:no_sandbox"]
        assert len(no_sandbox) == 0
