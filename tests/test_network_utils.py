"""URL 解析工具测试."""

from yuanzhao.network.utils import (
    analyze_url_risk,
    extract_domain,
    extract_urls,
    is_external_link,
    is_trusted_cdn,
)


class TestExtractDomain:
    def test_standard_url(self):
        assert extract_domain("https://www.example.com/path") == "www.example.com"

    def test_url_with_port(self):
        assert extract_domain("http://example.com:8080/path") == "example.com:8080"

    def test_javascript_protocol(self):
        assert extract_domain("javascript:alert(1)") == ""

    def test_no_scheme(self):
        result = extract_domain("//example.com/path")
        assert "example.com" in result


class TestIsExternalLink:
    def test_same_domain(self):
        assert is_external_link("https://example.com/page", "example.com") is False

    def test_subdomain(self):
        assert is_external_link("https://sub.example.com/page", "example.com") is False

    def test_different_domain(self):
        assert is_external_link("https://evil.com/page", "example.com") is True

    def test_no_base_domain(self):
        assert is_external_link("https://evil.com/page") is True
        assert is_external_link("javascript:void(0)") is False


class TestAnalyzeUrlRisk:
    def test_normal_url(self):
        r = analyze_url_risk("https://www.example.com/page")
        assert r["risk_level"] >= 1  # http scheme adds 1

    def test_javascript_url(self):
        r = analyze_url_risk("javascript:eval('x')")
        assert r["risk_level"] >= 5
        assert any("JavaScript" in reason for reason in r["reasons"])

    def test_data_uri(self):
        r = analyze_url_risk("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        assert r["risk_level"] >= 4
        assert any("Data URI" in reason for reason in r["reasons"])

    def test_suspicious_tld(self):
        r = analyze_url_risk("https://evil.xyz/page")
        assert r["risk_level"] >= 3
        assert any(".xyz" in reason for reason in r["reasons"])

    def test_short_link(self):
        r = analyze_url_risk("https://bit.ly/abc123")
        assert r["risk_level"] >= 4
        assert any("短链接" in reason for reason in r["reasons"])

    def test_non_standard_port(self):
        r = analyze_url_risk("https://example.com:9999/page")
        assert any("非标准端口" in reason for reason in r["reasons"])

    def test_random_path(self):
        r = analyze_url_risk("https://example.com/abcdefghij.js")
        assert any("可疑随机路径" in reason for reason in r["reasons"])


class TestExtractUrls:
    def test_http_urls(self):
        content = 'Visit <a href="https://example.com">here</a> or https://test.com'
        urls = extract_urls(content)
        url_values = [u["url"] for u in urls]
        assert "https://example.com" in url_values
        assert "https://test.com" in url_values

    def test_javascript_url(self):
        content = '<a href="javascript:void(0)">click</a>'
        urls = extract_urls(content)
        assert any("javascript:" in u["url"] for u in urls)

    def test_data_uri(self):
        content = '<img src="data:image/png;base64,iVBORw0KGgo=">'
        urls = extract_urls(content)
        assert any(u["url"].startswith("data:") for u in urls)

    def test_duplicate_removal(self):
        content = "https://example.com https://example.com https://example.com"
        urls = extract_urls(content)
        assert len(urls) == 1

    def test_has_context(self):
        content = "before https://example.com after"
        urls = extract_urls(content)
        assert len(urls) == 1
        assert "context" in urls[0]
        assert "position" in urls[0]

    def test_no_urls(self):
        urls = extract_urls("plain text without any urls")
        assert urls == []


class TestIsTrustedCDN:
    def test_trusted_cdn(self):
        assert is_trusted_cdn("https://cdn.jsdelivr.net/npm/jquery") is True
        assert is_trusted_cdn("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js") is True
        assert is_trusted_cdn("https://code.jquery.com/jquery-3.6.0.min.js") is True

    def test_untrusted_url(self):
        assert is_trusted_cdn("https://evil.com/jquery.js") is False
        assert is_trusted_cdn("https://cdn.example.com/lib.js") is False

    def test_subdomain_trusted(self):
        assert is_trusted_cdn("https://fonts.googleapis.com/css?family=Roboto") is True
