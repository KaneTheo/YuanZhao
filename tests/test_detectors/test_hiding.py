"""特殊隐藏技术检测器测试."""

from yuanzhao.detectors.hiding import (
    SpecialHidingDetector,
    _colors_similar,
    _detect_color_hiding,
    _detect_entities,
    _detect_font_size_hiding,
    _detect_nested,
    _detect_opacity_hiding,
    _detect_position_hiding,
    _detect_text_indent_hiding,
    _detect_whitespace_stack,
    _detect_zero_width,
)


class TestZeroWidthDetection:
    def test_detects_zero_width_chars(self):
        # Zero-width space U+200B
        content = "hello​world"
        findings = _detect_zero_width(content, "test.html", ["​", "‌", "‍"])
        assert len(findings) == 1
        assert findings[0].rule_id == "hiding:zero_width"

    def test_multiple_zw_chars(self):
        content = "​​​​​"
        findings = _detect_zero_width(content, "test.html", ["​", "‌"])
        assert len(findings) == 1
        assert findings[0].metadata["count"] == 5

    def test_no_zw_chars(self):
        content = "normal text"
        findings = _detect_zero_width(content, "test.html", ["​"])
        assert len(findings) == 0


class TestWhitespaceStack:
    def test_detects_whitespace_stack(self):
        content = "before" + " " * 50 + "after"
        findings = _detect_whitespace_stack(content, "test.html")
        assert len(findings) >= 1

    def test_skips_html_tags(self):
        content = "<div>" + " " * 50 + "</div>"
        findings = _detect_whitespace_stack(content, "test.html")
        # Should skip because context contains < and >
        assert all("<" not in f.context or ">" not in f.context for f in findings)

    def test_no_stack(self):
        content = "normal     spacing"
        findings = _detect_whitespace_stack(content, "test.html")
        assert len(findings) == 0


class TestColorHiding:
    def test_same_color_text_and_bg(self):
        content = "color: #ffffff; background-color: #fff;"
        findings = _detect_color_hiding(content, "test.css")
        assert len(findings) >= 1
        assert findings[0].rule_id == "hiding:color_match"

    def test_different_colors(self):
        content = "color: #ff0000;\nbackground-color: #0000ff;\n"
        findings = _detect_color_hiding(content, "test.css")
        assert len(findings) == 0

    def test_dark_on_dark(self):
        content = "color: #000000;\nbackground-color: #000;\n"
        findings = _detect_color_hiding(content, "test.css")
        assert len(findings) >= 1

    def test_no_bg_in_context(self):
        findings = _detect_color_hiding("color: #ffffff;", "test.css")
        assert len(findings) == 0


class TestPositionHiding:
    def test_far_left(self):
        content = "position: absolute; left: -9999px;"
        findings = _detect_position_hiding(content, "test.css")
        assert len(findings) >= 1

    def test_far_top(self):
        content = "position:absolute;top:-2000em;"
        findings = _detect_position_hiding(content, "test.css")
        assert len(findings) >= 1

    def test_normal_position(self):
        content = "position: absolute; left: 10px;"
        findings = _detect_position_hiding(content, "test.css")
        assert len(findings) == 0

    def test_boundary_value(self):
        # Values <= 1000 should NOT be flagged
        content = "position: absolute; left: -999px;"
        findings = _detect_position_hiding(content, "test.css")
        assert len(findings) == 0


class TestFontSizeHiding:
    def test_zero_font_size(self):
        findings = _detect_font_size_hiding("font-size: 0;", "test.css")
        assert len(findings) == 1

    def test_zero_point_something(self):
        findings = _detect_font_size_hiding("font-size: 0.0;", "test.css")
        assert len(findings) >= 1

    def test_normal_font_size(self):
        findings = _detect_font_size_hiding("font-size: 14px;", "test.css")
        assert len(findings) == 0


class TestTextIndentHiding:
    def test_large_negative_indent(self):
        findings = _detect_text_indent_hiding("text-indent: -9999px;", "test.css")
        assert len(findings) >= 1

    def test_small_indent(self):
        findings = _detect_text_indent_hiding("text-indent: -20px;", "test.css")
        assert len(findings) == 0

    def test_em_value(self):
        findings = _detect_text_indent_hiding("text-indent: -999em;", "test.css")
        assert len(findings) >= 1


class TestOpacityHiding:
    def test_zero_opacity(self):
        findings = _detect_opacity_hiding("opacity: 0;", "test.css")
        assert len(findings) >= 1
        assert any(f.rule_id == "hiding:opacity" for f in findings)

    def test_visibility_hidden(self):
        findings = _detect_opacity_hiding("visibility: hidden;", "test.css")
        assert any(f.rule_id == "hiding:visibility" for f in findings)

    def test_display_none(self):
        findings = _detect_opacity_hiding("display: none;", "test.css")
        assert any(f.rule_id == "hiding:display_none" for f in findings)

    def test_normal_opacity(self):
        findings = _detect_opacity_hiding("opacity: 0.5;", "test.css")
        # Normal opacity should not trigger "opacity: 0" or "visibility: hidden" or "display: none"
        suspicious = [f for f in findings if f.rule_id in ("hiding:opacity", "hiding:visibility", "hiding:display_none")]
        assert len(suspicious) == 0


class TestNested:
    def test_triple_nested(self):
        content = "<div><span><p>deeply nested</p></span></div>"
        findings = _detect_nested(content, "test.html")
        assert len(findings) >= 1

    def test_no_nesting(self):
        findings = _detect_nested("<div>plain div</div>", "test.html")
        assert len(findings) == 0


class TestEntities:
    def test_many_entities(self):
        entities = "".join(f"&#{i};" for i in range(65, 80))
        findings = _detect_entities(entities, "test.html")
        assert len(findings) >= 1

    def test_few_entities(self):
        findings = _detect_entities("hello &#65; world", "test.html")
        assert len(findings) == 0

    def test_hex_entities(self):
        entities = "".join(f"&#x{i:x};" for i in range(0x41, 0x50))
        findings = _detect_entities(entities, "test.html")
        assert len(findings) >= 1


class TestColorsSimilar:
    def test_exact_match(self):
        assert _colors_similar("#ffffff", "#ffffff") is True

    def test_white_variants(self):
        assert _colors_similar("#fff", "white") is True
        assert _colors_similar("white", "rgb(255,255,255)") is True

    def test_black_variants(self):
        assert _colors_similar("#000", "#000000") is True
        assert _colors_similar("black", "rgb(0,0,0)") is True

    def test_different_colors(self):
        assert _colors_similar("#ff0000", "#0000ff") is False
        assert _colors_similar("black", "white") is False


class TestSpecialHidingDetector:
    def test_integration(self):
        detector = SpecialHidingDetector()
        content = """
        <div style="display:none">hidden</div>
        <span style="opacity:0">zero</span>
        <p style="font-size:0">small</p>
        零宽:​字符
        """
        findings = detector.detect(content, "test.html")
        assert len(findings) >= 3  # display:none, opacity:0, font-size:0, zero-width
