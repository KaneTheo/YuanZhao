"""规则加载器测试."""

from yuanzhao.rules.loader import load_keywords_csv, load_yaml_rules


class TestLoadYamlRules:
    def test_load_builtin(self):
        rules = load_yaml_rules()
        assert isinstance(rules, dict)
        assert "trusted_cdn" in rules
        assert "suspicious_tlds" in rules
        assert "short_link_domains" in rules
        assert "js_high_risk_functions" in rules
        assert "css_hiding_values" in rules
        assert "zero_width_chars" in rules

    def test_trusted_cdn_list(self):
        rules = load_yaml_rules()
        cdns = rules["trusted_cdn"]
        assert isinstance(cdns, list)
        assert "cdn.jsdelivr.net" in cdns
        assert "cdnjs.cloudflare.com" in cdns

    def test_suspicious_tlds_dict(self):
        rules = load_yaml_rules()
        tlds = rules["suspicious_tlds"]
        assert isinstance(tlds, dict)
        assert "xyz" in tlds
        assert tlds["tk"] >= 3  # high risk

    def test_js_high_risk_functions(self):
        rules = load_yaml_rules()
        funcs = rules["js_high_risk_functions"]
        assert "eval" in funcs
        assert funcs["eval"] == 5

    def test_css_hiding_values(self):
        rules = load_yaml_rules()
        hiding = rules["css_hiding_values"]
        assert "display" in hiding
        assert "none" in hiding["display"]

    def test_nonexistent_file(self):
        rules = load_yaml_rules("nonexistent.yaml")
        assert rules == {}


class TestLoadKeywordsCSV:
    def test_load_builtin(self):
        keywords = load_keywords_csv()
        assert len(keywords) > 0
        for kw, cat, weight in keywords:
            assert isinstance(kw, str)
            assert cat in ("gambling", "porn", "malware", "phishing", "other")
            assert 1 <= weight <= 10

    def test_nonexistent_file(self):
        keywords = load_keywords_csv("nonexistent.csv")
        assert keywords == []
