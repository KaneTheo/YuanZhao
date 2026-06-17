"""自定义规则检测器测试."""

from yuanzhao.detectors.custom_rules import CustomRulesDetector


class TestCustomRulesDetector:
    def test_load_from_yaml(self, tmp_path):
        yaml_path = tmp_path / "test_rules.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:hello"
    pattern: 'hello\\s+world'
    flags: "i"
    severity: 7
    category: "suspicious_pattern"
    source_type: "text"
    description: "测试规则"
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        assert len(d._compiled_rules) == 1
        assert d._compiled_rules[0]["rule_id"] == "test:hello"

    def test_detect_pattern_match(self, tmp_path):
        yaml_path = tmp_path / "test_rules.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:hello"
    pattern: 'hello\\s+world'
    flags: "i"
    severity: 7
    category: "suspicious_pattern"
    source_type: "text"
    description: "测试规则"
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        findings = d.detect("HELLO   WORLD is here", "test.html")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "test:hello"
        assert f.severity == 7
        assert f.category == "suspicious_pattern"
        assert f.source_type == "text"

    def test_multiple_matches(self, tmp_path):
        yaml_path = tmp_path / "multi.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:digit"
    pattern: '\\d{4,}'
    flags: ""
    severity: 5
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        findings = d.detect("code: 1234 and 56789", "test.html")
        assert len(findings) == 2

    def test_no_match(self, tmp_path):
        yaml_path = tmp_path / "no_match.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:specific"
    pattern: 'SPECIFIC_PATTERN'
    flags: ""
    severity: 5
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        findings = d.detect("nothing to see here", "test.html")
        assert len(findings) == 0

    def test_regex_flags_ignore_case(self, tmp_path):
        yaml_path = tmp_path / "flags.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:case"
    pattern: 'case_sensitive'
    flags: "i"
    severity: 3
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        findings = d.detect("CASE_SENSITIVE match", "test.html")
        assert len(findings) == 1

    def test_regex_flags_dotall(self, tmp_path):
        yaml_path = tmp_path / "dotall.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:multiline"
    pattern: 'start(.+?)end'
    flags: "s"
    severity: 4
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        findings = d.detect("start\nmiddle\nend", "test.html")
        assert len(findings) == 1

    def test_missing_file_returns_empty(self):
        d = CustomRulesDetector(rules_file="nonexistent.yaml")
        assert d._compiled_rules == []

    def test_no_rules_file_returns_empty(self):
        d = CustomRulesDetector()
        assert d._compiled_rules == []

    def test_invalid_yaml_handled(self, tmp_path):
        yaml_path = tmp_path / "invalid.yaml"
        yaml_path.write_text("not: valid: yaml: [", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        assert d._compiled_rules == []

    def test_invalid_regex_skipped(self, tmp_path):
        yaml_path = tmp_path / "bad_regex.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:bad"
    pattern: '[unclosed'
    flags: ""
    severity: 5
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
  - rule_id: "test:good"
    pattern: 'valid'
    flags: "i"
    severity: 3
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        # Only the valid rule is compiled
        assert len(d._compiled_rules) == 1
        assert d._compiled_rules[0]["rule_id"] == "test:good"

    def test_severity_clamped(self, tmp_path):
        yaml_path = tmp_path / "severity.yaml"
        yaml_path.write_text("""
rules:
  - rule_id: "test:high"
    pattern: 'high'
    flags: ""
    severity: 99
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
  - rule_id: "test:low"
    pattern: 'low'
    flags: ""
    severity: 0
    category: "suspicious_pattern"
    source_type: "text"
    description: ""
""", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        assert d._compiled_rules[0]["severity"] == 10
        assert d._compiled_rules[1]["severity"] == 1

    def test_empty_rules_list(self, tmp_path):
        yaml_path = tmp_path / "empty.yaml"
        yaml_path.write_text("rules: []", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        assert d._compiled_rules == []

    def test_missing_rules_key(self, tmp_path):
        yaml_path = tmp_path / "no_rules_key.yaml"
        yaml_path.write_text("other: data", encoding="utf-8")
        d = CustomRulesDetector(rules_file=str(yaml_path))
        assert d._compiled_rules == []
