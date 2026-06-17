"""HTML 报告（Jinja2 模板渲染）."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from yuanzhao.detectors.base import Finding
from yuanzhao.reporters.base import BaseReporter

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class HTMLReporter(BaseReporter):
    def generate(self, findings: list[Finding], metadata: dict) -> str:
        self._ensure_dir()
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
        template = env.get_template("report.html")

        suspicious = sorted(
            [f for f in findings if f.category == "suspicious_url"],
            key=lambda f: f.severity, reverse=True,
        )
        keywords = sorted(
            [f for f in findings if f.category == "keyword_match"],
            key=lambda f: f.severity, reverse=True,
        )
        hidden = sorted(
            [f for f in findings if f.category == "hidden_element"],
            key=lambda f: f.severity, reverse=True,
        )
        js_issues = sorted(
            [f for f in findings if f.category == "js_issue"],
            key=lambda f: f.severity, reverse=True,
        )
        css_issues = sorted(
            [f for f in findings if f.category == "css_issue"],
            key=lambda f: f.severity, reverse=True,
        )
        other = sorted(
            [f for f in findings if f.category not in (
                "suspicious_url", "keyword_match", "hidden_element", "js_issue", "css_issue",
            )],
            key=lambda f: f.severity, reverse=True,
        )

        critical = sum(1 for f in findings if f.severity >= 8)
        high = sum(1 for f in findings if 5 <= f.severity <= 7)
        medium = sum(1 for f in findings if 3 <= f.severity <= 4)
        low = sum(1 for f in findings if f.severity <= 2)

        html = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=metadata.get("target", ""),
            mode=metadata.get("mode", ""),
            duration=str(metadata.get("duration", "")),
            scanned_files=metadata.get("scanned_files", 0),
            scanned_urls=metadata.get("scanned_urls", 0),
            total_findings=len(findings),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            suspicious_links=suspicious,
            keyword_matches=keywords,
            hidden_elements=hidden,
            js_issues=js_issues,
            css_issues=css_issues,
            other_findings=other,
            categories=[
                ("可疑链接", len(suspicious), "danger", suspicious),
                ("关键字匹配", len(keywords), "warning", keywords),
                ("隐藏元素", len(hidden), "warning", hidden),
                ("JS 问题", len(js_issues), "info", js_issues),
                ("CSS 问题", len(css_issues), "info", css_issues),
                ("其他发现", len(other), "info", other),
            ],
        )

        path = str(self.output_path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
