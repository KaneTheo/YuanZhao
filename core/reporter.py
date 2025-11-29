# -*- coding: utf-8 -*-

"""
报告生成器模块
"""

import os
import json
import csv
import logging
from datetime import datetime

def _escape_html(s: str) -> str:
    if s is None:
        return ''
    return (
        str(s)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
    )
from typing import Dict, List

logger = logging.getLogger('YuanZhao.reporter')

class Reporter:
    """报告生成器类"""
    
    def __init__(self, config):
        self.config = config
    
    def generate_report(self, results: Dict, duration):
        """生成报告"""
        try:
            report_dir = os.path.dirname(self.config.report_file)
            if report_dir and not os.path.exists(report_dir):
                os.makedirs(report_dir)
            
            if self.config.report_type == 'txt':
                self._generate_text_report(results, duration)
            elif self.config.report_type == 'html':
                self._generate_html_report(results, duration)
            elif self.config.report_type == 'json':
                self._generate_json_report(results, duration)
            elif self.config.report_type == 'csv':
                self._generate_csv_report(results, duration)
            else:
                raise ValueError(f"不支持的报告类型: {self.config.report_type}")
                
            logger.info(f"报告已成功生成: {self.config.report_file}")
            return self.config.report_file  # 返回报告文件路径
            
        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}", exc_info=True)
            raise
    
    def _generate_text_report(self, results: Dict, duration):
        """生成文本报告"""
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            f.write("========================================\n")
            f.write("         渊照 - 暗链扫描报告\n")
            f.write("========================================\n\n")
            
            # 基本信息
            f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描目标: {self.config.target}\n")
            f.write(f"扫描模式: {self.config.scan_mode}\n")
            f.write(f"扫描耗时: {duration}\n")
            f.write(f"扫描文件数: {results.get('scanned_files', 0)}\n")
            f.write(f"扫描URL数: {results.get('scanned_urls', 0)}\n\n")
            
            # 扫描结果概览
            f.write("----------------------------------------\n")
            f.write("扫描结果概览\n")
            f.write("----------------------------------------\n")
            f.write(f"发现可疑链接: {len(results.get('suspicious_links', []))}\n")
            f.write(f"发现关键字匹配: {len(results.get('keyword_matches', []))}\n\n")
            
            # 可疑链接详情
            if results.get('suspicious_links', []):
                f.write("----------------------------------------\n")
                f.write("可疑链接详情\n")
                f.write("----------------------------------------\n\n")
                
                for i, link in enumerate(results['suspicious_links'], 1):
                    link_val = link.get('link') or link.get('url', 'N/A')
                    source_val = link.get('source') or link.get('file_path', 'N/A')
                    f.write(f"[{i}] 链接: {link_val}\n")
                    f.write(f"    来源: {source_val}\n")
                    f.write(f"    类型: {link.get('type', 'N/A')}\n")
                    f.write(f"    检测方式: {link.get('detection_method', 'N/A')}\n")
                    f.write(f"    风险等级: {link.get('risk_level', 'N/A')}\n")
                    if 'context' in link:
                        f.write(f"    上下文: {link['context'][:100]}...\n")
                    f.write("\n")
            
            # 关键字匹配详情
            if results.get('keyword_matches', []):
                f.write("----------------------------------------\n")
                f.write("关键字匹配详情\n")
                f.write("----------------------------------------\n\n")
                
                for i, match in enumerate(results['keyword_matches'], 1):
                    f.write(f"[{i}] 关键字: {match.get('keyword', 'N/A')}\n")
                    f.write(f"    类别: {match.get('category', 'N/A')}\n")
                    f.write(f"    风险权重: {match.get('weight', 'N/A')}\n")
                    f.write(f"    来源: {match.get('source', 'N/A')}\n")
                    if 'context' in match:
                        f.write(f"    上下文: {match['context'][:100]}...\n")
                    f.write("\n")
            
            # 总结和建议
            f.write("========================================\n")
            f.write("总结与建议\n")
            f.write("========================================\n\n")
            
            if results.get('suspicious_links', []) or results.get('keyword_matches', []):
                f.write("发现潜在的安全问题，请进行以下操作：\n\n")
                f.write("1. 审查所有可疑链接，确认其合法性\n")
                f.write("2. 分析关键字匹配结果，检查相关内容\n")
                f.write("3. 移除或修复发现的暗链\n")
                f.write("4. 加强网站安全措施，防止再次被植入暗链\n")
                f.write("5. 定期使用渊照工具进行扫描\n")
            else:
                f.write("未发现明显的暗链问题。建议继续保持警惕，定期进行扫描。\n")
    
    def _generate_html_report(self, results: Dict, duration):
        """生成HTML报告"""
        # 读取对应的log文件内容
        log_content = self._read_log_file()
        
        
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渊照 - 暗链扫描报告</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .header {{
            background-color: #3498db;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .section {{
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .table-container {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .risk-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .risk-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .risk-low {{
            color: #3498db;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .context {{
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .log-container {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 400px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>渊照 - 暗链扫描报告</h1>
    </div>
    
    <div class="summary">
        <h2>扫描概览</h2>
        <p><strong>扫描时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>扫描目标:</strong> {_escape_html(self.config.target)}</p>
        <p><strong>扫描模式:</strong> {_escape_html(self.config.scan_mode)}</p>
        <p><strong>扫描耗时:</strong> {duration}</p>
        <p><strong>扫描文件数:</strong> {results.get('scanned_files', 0)}</p>
        <p><strong>扫描URL数:</strong> {results.get('scanned_urls', 0)}</p>
        
        <h3>结果统计</h3>
        <p><strong>发现可疑链接:</strong> <span class="risk-high">{len(results.get('suspicious_links', []))}</span></p>
        <p><strong>发现关键字匹配:</strong> <span class="risk-high">{len(results.get('keyword_matches', []))}</span></p>
    </div>
"""
        
        # 添加可疑链接表格
        if results.get('suspicious_links', []):
            html_content += """
    <div class="section">
        <h2>可疑链接详情</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>序号</th>
                        <th>链接</th>
                        <th>来源</th>
                        <th>来源类型</th>
                        <th>类型</th>
                        <th>检测方式</th>
                        <th>风险等级</th>
                        <th>位置</th>
                        <th>上下文</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            # 读取日志内容以提取问题详情
            log_content = self._read_log_file()
            suspicious_link_details = []
            if log_content:
                # 从日志中提取可疑链接信息
                import re
                for line in log_content.split('\n'):
                    if '找到可疑链接:' in line:
                        # 使用正则表达式提取完整的URL
                        url_pattern = r'https?://[^\s]+'
                        matches = re.findall(url_pattern, line)
                        if matches:
                            suspicious_link_details.append(matches[0])
            
            for i, link in enumerate(results['suspicious_links'], 1):
                risk_class = self._get_risk_class(link.get('risk_level', ''))
                # 获取问题详情，如果有日志中的信息就使用
                context_info = (link.get('context', '')[:100] + '...') if link.get('context') else ''
                # 优先显示规范URL；无URL时展示动态表达式短摘
                display_value = link.get('link') or link.get('url')
                if not display_value and link.get('expression'):
                    display_value = (link['expression'][:100] + '...')
                link_val = _escape_html(display_value or 'N/A')
                source_val = _escape_html(link.get('source') or link.get('file_path', 'N/A'))
                source_type_val = _escape_html(link.get('context_type', 'N/A'))
                if suspicious_link_details:
                    # 仅在日志中有完全匹配的链接时使用日志上下文
                    for detail in suspicious_link_details:
                        if link_val and detail and link_val in detail:
                            context_info = f"从日志中检测到: {_escape_html(detail)}"
                            break
                
                pos = link.get('position')
                pos_display = _escape_html(f"{pos[0]}-{pos[1]}" if isinstance(pos, (list, tuple)) and len(pos) == 2 else 'N/A')
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{link_val}</td>
                        <td>{source_val}</td>
                        <td>{source_type_val}</td>
                        <td>{_escape_html(link.get('type', 'N/A'))}</td>
                        <td>{_escape_html(link.get('detection_method', 'N/A'))}</td>
                        <td class="{risk_class}">{link.get('risk_level', 'N/A')}</td>
                        <td>{pos_display}</td>
                        <td><div class="context">{_escape_html(context_info)}</div></td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
"""
        
        # 添加关键字匹配表格
        if results.get('keyword_matches', []):
            html_content += """
    <div class="section">
        <h2>关键字匹配详情</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>序号</th>
                        <th>关键字</th>
                        <th>类别</th>
                        <th>风险权重</th>
                        <th>来源</th>
                        <th>上下文</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for i, match in enumerate(results['keyword_matches'], 1):
                risk_class = self._get_keyword_risk_class(match.get('weight', 0))
                html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{_escape_html(match.get('keyword', 'N/A'))}</td>
                        <td>{_escape_html(match.get('category', 'N/A'))}</td>
                        <td class="{risk_class}">{match.get('weight', 'N/A')}</td>
                        <td>{_escape_html(match.get('source', 'N/A'))}</td>
                        <td><div class="context">{_escape_html((match.get('context', '') or '')[:100])}...</div></td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
"""
        
        # 添加总结和建议
        html_content += """
    <div class="section">
        <h2>总结与建议</h2>
        <p>感谢使用渊照暗链扫描工具。根据扫描结果，我们提供以下分析和建议：</p>
"""
        
        if results.get('suspicious_links', []) or results.get('keyword_matches', []):
            html_content += """
        <p style="color: #e74c3c;">发现潜在的安全问题，请进行以下操作：</p>
        <ol>
            <li>审查所有可疑链接，确认其合法性</li>
            <li>分析关键字匹配结果，检查相关内容</li>
            <li>移除或修复发现的暗链</li>
            <li>加强网站安全措施，防止再次被植入暗链</li>
            <li>定期使用渊照工具进行扫描</li>
        </ol>
"""
        else:
            html_content += """
        <p style="color: #27ae60;">未发现明显的暗链问题。建议继续保持警惕，定期进行扫描。</p>
"""
        
        html_content += """
    </div>
    
    <div class="footer">
        <p>本报告由渊照暗链扫描工具自动生成</p>
        <p>© 2024 YuanZhao</p>
    </div>
</body>
</html>
"""
        
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_json_report(self, results: Dict, duration):
        """生成JSON报告"""
        # 丰富context_type字段，保持结构化输出一致性
        enriched_links = []
        for link in results.get('suspicious_links', []):
            item = dict(link)
            if 'context_type' not in item:
                item['context_type'] = 'N/A'
            if 'source_tag' not in item:
                item['source_tag'] = item.get('source_tag', 'N/A')
            enriched_links.append(item)
        report_data = {
            'report_info': {
                'tool': '渊照暗链扫描工具',
                'version': '1.0',
                'scan_time': datetime.now().isoformat(),
                'target': self.config.target,
                'target_type': self.config.target_type,
                'scan_mode': self.config.scan_mode,
                'duration': str(duration),
                'scanned_files': results.get('scanned_files', 0),
                'scanned_urls': results.get('scanned_urls', 0)
            },
            'statistics': {
                'suspicious_links_count': len(results.get('suspicious_links', [])),
                'keyword_matches_count': len(results.get('keyword_matches', [])),
                'total_issues': results.get('total_issues', 0)
            },
            'suspicious_links': enriched_links,
            'keyword_matches': results.get('keyword_matches', [])
        }
        
        with open(self.config.report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    def _generate_csv_report(self, results: Dict, duration):
        """生成CSV报告"""
        # 先写入可疑链接
        def _sanitize_csv_cell(val: str) -> str:
            if val is None:
                return ''
            s = str(val)
            return ("'" + s) if s and s[0] in ('=', '+', '-', '@') else s
        with open(self.config.report_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            
            # 写入报告信息
            writer.writerow(['渊照暗链扫描报告'])
            writer.writerow(['扫描时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['扫描目标', _sanitize_csv_cell(self.config.target)])
            writer.writerow(['扫描模式', _sanitize_csv_cell(self.config.scan_mode)])
            writer.writerow(['扫描耗时', str(duration)])
            writer.writerow([])
            
            # 写入可疑链接
            if results.get('suspicious_links', []):
                writer.writerow(['可疑链接'])
                writer.writerow(['序号', '链接', '来源', '来源类型', '来源标签', '类型', '检测方式', '风险等级', '位置', '上下文'])
                
                for i, link in enumerate(results['suspicious_links'], 1):
                    link_display = link.get('link', '') or link.get('url', '') or (link.get('expression', '')[:100] + '...' if link.get('expression') else '')
                    pos = link.get('position')
                    pos_display = f"{pos[0]}-{pos[1]}" if isinstance(pos, (list, tuple)) and len(pos) == 2 else ''
                    writer.writerow([
                        i,
                        _sanitize_csv_cell(link_display),
                        _sanitize_csv_cell(link.get('source', '')),
                        _sanitize_csv_cell(link.get('context_type', 'N/A')),
                        _sanitize_csv_cell(link.get('source_tag', 'N/A')),
                        _sanitize_csv_cell(link.get('type', '')),
                        _sanitize_csv_cell(link.get('detection_method', '')),
                        link.get('risk_level', ''),
                        _sanitize_csv_cell(pos_display),
                        _sanitize_csv_cell((link.get('context', '') or '')[:200])
                    ])
                writer.writerow([])
            
            # 写入关键字匹配
            if results.get('keyword_matches', []):
                writer.writerow(['关键字匹配'])
                writer.writerow(['序号', '关键字', '类别', '风险权重', '来源', '上下文'])
                
                for i, match in enumerate(results['keyword_matches'], 1):
                    writer.writerow([
                        i,
                        _sanitize_csv_cell(match.get('keyword', '')),
                        _sanitize_csv_cell(match.get('category', '')),
                        match.get('weight', ''),
                        _sanitize_csv_cell(match.get('source', '')),
                        _sanitize_csv_cell((match.get('context', '') or '')[:200])
                    ])
    
    def _get_risk_class(self, risk_level):
        """根据风险等级返回CSS类名"""
        if risk_level in ['高', 'high', 'HIGH']:
            return 'risk-high'
        elif risk_level in ['中', 'medium', 'MEDIUM']:
            return 'risk-medium'
        else:
            return 'risk-low'
    
    def _get_keyword_risk_class(self, weight):
        """根据关键字风险权重返回CSS类名"""
        try:
            weight = int(weight)
            if weight >= 8:
                return 'risk-high'
            elif weight >= 5:
                return 'risk-medium'
            else:
                return 'risk-low'
        except:
            return 'risk-low'
    
    def _read_log_file(self):
        """读取对应的log文件内容，确保完整读取所有日志"""
        try:
            if not getattr(self.config, 'debug', False):
                return "日志读取未启用（非调试模式）"
            # 添加导入
            import time
            
            # 直接使用固定路径方法，先检查reports目录下是否存在最新的日志文件
            # 优先使用报告所在目录作为日志目录
            reports_dir = os.path.dirname(self.config.report_file) or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
            
            # 查找reports目录下所有日志文件
            if os.path.exists(reports_dir):
                all_log_files = [f for f in os.listdir(reports_dir) if f.startswith('YuanZhao_') and f.endswith('.log')]
                
                if all_log_files:
                    # 按修改时间排序，获取最新的日志文件
                    log_files_with_time = [(f, os.path.getmtime(os.path.join(reports_dir, f))) for f in all_log_files]
                    log_files_with_time.sort(key=lambda x: x[1], reverse=True)
                    latest_log_file = os.path.join(reports_dir, log_files_with_time[0][0])
                    
                    # 为了避免读取日志时写入的调试信息污染结果，先获取文件内容并缓存
                    # 初始化变量存储最佳的读取结果
                    best_content = None
                    best_encoding = None
                    best_lines_count = 0
                    best_has_summary = False
                    
                    # 初始等待时间（参数化）
                    time.sleep((getattr(self.config, 'debug_log_wait_ms', 3000))/1000.0)
                    
                    # 检查文件大小是否稳定，表示写入完成
                    size_stable_count = 0
                    last_size = 0
                    max_size_checks = int(getattr(self.config, 'debug_log_checks', 5))
                    
                    for _ in range(max_size_checks):
                        try:
                            current_size = os.path.getsize(latest_log_file)
                            
                            if current_size == last_size:
                                size_stable_count += 1
                            else:
                                size_stable_count = 0
                                last_size = current_size
                                
                            if size_stable_count >= 3:  # 文件大小连续三次稳定
                                break
                            
                            time.sleep((getattr(self.config, 'debug_log_interval_ms', 800))/1000.0)
                        except Exception:
                            break
                    
                    # 一次性读取文件内容并缓存，避免多次打开文件时内容变化
                    try:
                        with open(latest_log_file, 'rb') as f:
                            binary_content = f.read()
                    except Exception as e:
                        logger.error(f"读取日志文件时出错: {str(e)}")
                        return "无法读取日志文件"
                    
                    # 尝试多次读取，确保获取完整内容
                    max_attempts = 3  # 减少尝试次数，因为已经缓存了文件内容
                    for attempt in range(max_attempts):
                        # 等待一小段时间
                        if attempt > 0:
                            time.sleep(1.0)
                        
                        # 优先使用UTF-8编码，因为日志文件通常使用UTF-8
                        encodings = ['utf-8', 'cp936', 'gbk']
                        for encoding in encodings:
                            try:
                                # 尝试解码
                                try:
                                    content = binary_content.decode(encoding, errors='replace')
                                except:
                                    content = binary_content.decode(encoding, errors='ignore')
                                
                                # 预处理内容，规范化行尾
                                content = content.replace('\r\n', '\n').replace('\r', '\n')
                                
                                # 验证内容完整性
                                if content:
                                    lines = content.split('\n')
                                    # 过滤掉空行，获取有效行数
                                    non_empty_lines = [line for line in lines if line.strip()]
                                    lines_count = len(non_empty_lines)
                                    
                                    # 大幅扩展扫描总结关键词
                                    summary_keywords = [
                                        '扫描总结', '扫描完成', '扫描耗时', '总文件数', '发现问题', 
                                        '已扫描', '扫描结束', '平均速度', '扫描结果', '扫描报告',
                                        '扫描结束时间', '总共扫描', '完成扫描', '结果统计', '耗时统计'
                                    ]
                                    has_summary = any(any(keyword in line for keyword in summary_keywords) for line in non_empty_lines)
                                    
                                    # 更新最佳结果
                                    # 首先处理best_encoding为None的情况
                                    update_best = False
                                    
                                    # 如果当前内容有总结，而最佳结果没有总结，则更新
                                    if has_summary and not best_has_summary:
                                        update_best = True
                                    # 如果两者都有总结或都没有总结
                                    elif has_summary == best_has_summary:
                                        # 如果还没有最佳编码，直接更新
                                        if best_encoding is None:
                                            update_best = True
                                        # 否则按编码优先级和行数比较
                                        else:
                                            # 编码优先级比较（索引越小优先级越高）
                                            current_index = encodings.index(encoding)
                                            best_index = encodings.index(best_encoding)
                                            
                                            if current_index < best_index or (current_index == best_index and lines_count > best_lines_count):
                                                update_best = True
                                    
                                    if update_best:
                                        best_content = content
                                        best_encoding = encoding
                                        best_lines_count = lines_count
                                        best_has_summary = has_summary
                                    
                                    # 如果找到扫描总结，直接返回内容
                                    if has_summary:
                                        return content
                            except Exception:
                                continue
                    
                    # 如果尝试了所有次数后仍然没有找到扫描总结，返回行数最多的内容
                    if best_content:
                        return best_content
                    
                    # 最后的备用方案：使用UTF-8解码
                    try:
                        content = binary_content.decode('utf-8', errors='replace')
                        content = content.replace('\r\n', '\n').replace('\r', '\n')
                        return content
                    except Exception:
                        return "无法获取完整的日志内容"
                else:
                    return "未找到任何日志文件"
            else:
                return f"报告目录不存在: {reports_dir}"
        except Exception as e:
            logger.error(f"读取日志文件异常: {str(e)}", exc_info=True)
            return f"读取日志文件时发生错误: {str(e)}\n详细信息: {repr(e)}"
            
        # 局部_escape_html移除，统一使用文件顶部的全局_escape_html
            
