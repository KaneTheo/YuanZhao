"""应用编排器 — 连接 CLI → 扫描 → 报告."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yuanzhao.config import ReportFormat, ScanConfig
from yuanzhao.logging import setup_logging
from yuanzhao.reporters.csv_reporter import CSVReporter
from yuanzhao.reporters.html import HTMLReporter
from yuanzhao.reporters.json_reporter import JSONReporter
from yuanzhao.reporters.text import TextReporter
from yuanzhao.scanner.engine import ScanEngine
from yuanzhao.scanner.targets import resolve_targets

console = Console()


def _build_summary_table(findings, results, duration: str, config: ScanConfig) -> Table:
    summary = results.get("summary", {})
    suspicious = len(summary.get("suspicious_links", []))
    keywords = len(summary.get("keyword_matches", []))
    hidden = len(summary.get("hidden_elements", []))
    js_count = len(summary.get("js_issues", []))
    css_count = len(summary.get("css_issues", []))
    total = len(findings)
    scanned_files = len(results.get("scanned_files", []))
    scanned_urls = len(results.get("scanned_urls", []))

    # 风险等级
    critical = sum(1 for f in findings if f.severity >= 8)
    high = sum(1 for f in findings if 5 <= f.severity <= 7)

    if critical > 0:
        risk_style = "bold red"
        risk_text = "!! 高风险"
    elif high > 0:
        risk_style = "bold yellow"
        risk_text = "! 中高风险"
    elif total > 0:
        risk_style = "bold blue"
        risk_text = "~ 低风险"
    else:
        risk_style = "bold green"
        risk_text = "OK 未发现问题"

    table = Table(title="渊照 YuanZhao v2.0.0 — 扫描报告", box=None, padding=(0, 2))
    table.add_column("", style="dim", width=2)
    table.add_column("项目", style="bold")
    table.add_column("结果")

    table.add_row("", "扫描目标", str(config.target))
    table.add_row("", "扫描模式", config.mode.value)
    table.add_row("", "扫描耗时", duration)
    table.add_row("", "扫描文件数", str(scanned_files))
    table.add_row("", "扫描 URL 数", str(scanned_urls))
    table.add_row("", "发现问题总数", f"[{risk_style}]{total}[/{risk_style}]  [{risk_style}]{risk_text}[/{risk_style}]")
    if total > 0:
        table.add_row("", "├ 可疑链接", f"[red]{suspicious}[/red]" if suspicious else str(suspicious))
        table.add_row("", "├ 关键字匹配", f"[yellow]{keywords}[/yellow]" if keywords else str(keywords))
        table.add_row("", "├ 隐藏元素", f"[yellow]{hidden}[/yellow]" if hidden else str(hidden))
        table.add_row("", "├ JS 问题", f"[dim]{js_count}[/dim]" if js_count > 0 else str(js_count))
        table.add_row("", "└ CSS 问题", f"[dim]{css_count}[/dim]" if css_count > 0 else str(css_count))
    table.add_section()
    table.add_row("", "严重程度分布", f"[red]严重(8-10): {critical}[/red]  [yellow]高危(5-7): {high}[/yellow]")
    return table


def run(config: ScanConfig, target_file: str | None = None) -> int:
    logger = setup_logging(str(config.report_dir), verbose=config.verbose)
    logger.info("渊照 YuanZhao v2.0.0 启动")
    logger.info("目标: %s  模式: %s  线程: %d  深度: %d",
                config.target, config.mode.value, config.threads, config.depth)

    # 解析目标
    targets = resolve_targets(config, target_file)
    if not targets:
        logger.error("没有有效的扫描目标")
        return 1

    logger.info("共 %d 个扫描目标", len(targets))

    # 执行扫描
    engine = ScanEngine(config)
    start = time.time()
    try:
        results = engine.scan(targets)
    finally:
        engine.cleanup()

    elapsed = time.time() - start
    duration = f"{elapsed:.2f}s"
    findings = results.get("findings", [])

    # Rich 摘要输出
    table = _build_summary_table(findings, results, duration, config)
    console.print()
    console.print(table)
    console.print()

    # 生成报告
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = config.report_format.value
    report_path = Path(config.report_dir) / f"scan_report_{ts}.{ext}"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = {
        "target": config.target,
        "mode": config.mode.value,
        "duration": duration,
        "scanned_files": len(results.get("scanned_files", [])),
        "scanned_urls": len(results.get("scanned_urls", [])),
    }

    reporter_map = {
        ReportFormat.TXT: TextReporter,
        ReportFormat.HTML: HTMLReporter,
        ReportFormat.JSON: JSONReporter,
        ReportFormat.CSV: CSVReporter,
    }

    reporter_cls = reporter_map.get(config.report_format)
    if reporter_cls is None:
        logger.error("不支持的报告格式: %s", config.report_format.value)
        return 1

    reporter = reporter_cls(report_path)
    output = reporter.generate(findings, metadata)

    logger.info("报告已保存: %s", output)

    # 最终提示
    console.print(
        Panel.fit(
            f"[bold green]报告已保存至:[/bold green] {output}\n"
            "[dim]建议将 HTML 报告发送给 AI 工具进行二次分析，以排除误报和噪音[/dim]",
            border_style="green",
        )
    )
    return 0
