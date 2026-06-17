"""纯文本报告."""

from __future__ import annotations

from datetime import datetime

from yuanzhao.detectors.base import Finding
from yuanzhao.reporters.base import BaseReporter


class TextReporter(BaseReporter):
    def generate(self, findings: list[Finding], metadata: dict) -> str:
        self._ensure_dir()
        path = str(self.output_path)

        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 50 + "\n")
            f.write("        渊照 — 暗链扫描报告\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描目标: {metadata.get('target', 'N/A')}\n")
            f.write(f"扫描模式: {metadata.get('mode', 'N/A')}\n")
            f.write(f"扫描耗时: {metadata.get('duration', 'N/A')}\n")
            f.write(f"扫描文件数: {metadata.get('scanned_files', 0)}\n")
            f.write(f"扫描 URL 数: {metadata.get('scanned_urls', 0)}\n\n")

            suspicious = [f for f in findings if f.category == "suspicious_url"]
            keywords = [f for f in findings if f.category == "keyword_match"]
            hidden = [f for f in findings if f.category == "hidden_element"]

            f.write("-" * 50 + "\n")
            f.write("扫描概览\n")
            f.write("-" * 50 + "\n")
            f.write(f"可疑链接: {len(suspicious)}\n")
            f.write(f"关键字匹配: {len(keywords)}\n")
            f.write(f"隐藏元素: {len(hidden)}\n")
            f.write(f"总问题数: {len(findings)}\n\n")

            if suspicious:
                f.write("-" * 50 + "\n")
                f.write("可疑链接详情\n")
                f.write("-" * 50 + "\n\n")
                for i, fl in enumerate(suspicious, 1):
                    f.write(f"[{i}] {fl.evidence}\n")
                    f.write(f"    来源: {fl.location}\n")
                    f.write(f"    严重程度: {fl.severity}/10\n")
                    if fl.metadata.get("reasons"):
                        f.write(f"    原因: {', '.join(fl.metadata['reasons'])}\n")
                    if fl.context:
                        f.write(f"    上下文: {fl.context[:150]}\n")
                    f.write("\n")

            if keywords:
                f.write("-" * 50 + "\n")
                f.write("关键字匹配\n")
                f.write("-" * 50 + "\n\n")
                for i, fl in enumerate(keywords, 1):
                    meta = fl.metadata
                    f.write(f"[{i}] {meta.get('keyword', 'N/A')}\n")
                    f.write(f"    类别: {meta.get('category', 'N/A')}\n")
                    f.write(f"    权重: {meta.get('weight', 'N/A')}\n")
                    f.write(f"    来源: {fl.location}\n")
                    if fl.context:
                        f.write(f"    上下文: {fl.context[:150]}\n")
                    f.write("\n")

            f.write("=" * 50 + "\n")
            f.write("渊照暗链扫描工具 — https://github.com/KaneTheo/YuanZhao\n")
        return path
