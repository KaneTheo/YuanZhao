"""JSON 报告."""

from __future__ import annotations

import json
from datetime import datetime

from yuanzhao.detectors.base import Finding
from yuanzhao.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    def generate(self, findings: list[Finding], metadata: dict) -> str:
        self._ensure_dir()
        path = str(self.output_path)

        data = {
            "report": {
                "tool": "渊照 YuanZhao",
                "version": "2.0.0",
                "generated_at": datetime.now().isoformat(),
                "target": metadata.get("target", ""),
                "mode": metadata.get("mode", ""),
                "duration": str(metadata.get("duration", "")),
                "scanned_files": metadata.get("scanned_files", 0),
                "scanned_urls": metadata.get("scanned_urls", 0),
            },
            "statistics": {
                "total_findings": len(findings),
                "suspicious_urls": sum(1 for f in findings if f.category == "suspicious_url"),
                "keyword_matches": sum(1 for f in findings if f.category == "keyword_match"),
                "hidden_elements": sum(1 for f in findings if f.category == "hidden_element"),
                "js_issues": sum(1 for f in findings if f.category == "js_issue"),
                "css_issues": sum(1 for f in findings if f.category == "css_issue"),
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "source_type": f.source_type,
                    "location": f.location,
                    "evidence": f.evidence,
                    "context": f.context,
                    "metadata": f.metadata,
                }
                for f in findings
            ],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path
