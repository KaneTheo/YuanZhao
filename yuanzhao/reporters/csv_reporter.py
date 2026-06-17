"""CSV 报告."""

from __future__ import annotations

import csv
from datetime import datetime

from yuanzhao.detectors.base import Finding
from yuanzhao.reporters.base import BaseReporter


class CSVReporter(BaseReporter):
    def generate(self, findings: list[Finding], metadata: dict) -> str:
        self._ensure_dir()
        path = str(self.output_path)

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["渊照暗链扫描报告"])
            writer.writerow(["扫描时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["扫描目标", metadata.get("target", "")])
            writer.writerow(["扫描模式", metadata.get("mode", "")])
            writer.writerow(["扫描耗时", str(metadata.get("duration", ""))])
            writer.writerow([])

            if findings:
                writer.writerow([
                    "序号", "规则ID", "类别", "严重程度", "来源类型",
                    "来源", "证据", "上下文",
                ])
                for i, fl in enumerate(findings, 1):
                    writer.writerow([
                        i, fl.rule_id, fl.category, fl.severity,
                        fl.source_type, fl.location,
                        _safe(fl.evidence)[:200],
                        _safe(fl.context)[:200],
                    ])
        return path


def _safe(v: str | None) -> str:
    if v is None:
        return ""
    s = str(v)
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s
