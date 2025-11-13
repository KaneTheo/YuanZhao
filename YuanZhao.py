#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
渊照 - 暗链扫描工具
"""

import os
import sys
import argparse
import logging
import re
from datetime import datetime
from urllib.parse import urlparse

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.logging_utils import setup_logging, log_config, log_summary
from core.config import Config
from core.scanner import Scanner
from core.reporter import Reporter

def parse_arguments():
    """
    解析命令行参数
    """
    description = '''渊照 - 专业暗链扫描工具
    
    用于智能检测网站、HTML文件或目录中的可疑暗链、隐藏元素和恶意代码。
    支持自动识别扫描目标类型（本地文件/目录、内网URL、公网URL），并应用最优扫描策略。
    提供多种扫描模式和报告格式，具备强大的检测能力和灵活的配置选项。
    
    主要功能：
    - 基础扫描：HTML代码、JavaScript代码、CSS代码、元标签、注释扫描
    - 高级扫描：加密/编码链接检测、隐写术检测、DOM操作检测、iframe检测
    - 特殊隐藏手法检测：颜色隐藏、绝对定位隐藏、零宽字符隐藏、字体大小隐藏等
    - 关键字匹配：支持自定义关键字文件，按类别组织关键字，进行多语言匹配
    - 优化的HTML报告：清晰展示可疑链接信息，上下文列直接显示从日志中检测到的完整问题
    '''
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # 扫描目标
    parser.add_argument('target', help='扫描目标：文件路径、目录路径或URL（支持http/https协议）')
    
    # 扫描配置
    parser.add_argument('-d', '--depth', type=int, default=3, 
                        help='递归扫描深度（默认：3，0表示仅扫描当前文件/目录）')
    parser.add_argument('-m', '--mode', choices=['fast', 'standard', 'deep'], default='deep', 
                        help='''扫描模式：
                        fast（基础）：仅检测基本的暗链与明显可疑元素，快速
                        standard（高级）：增加JS/HTML/CSS分析与隐藏元素检测
                        deep（完整）：执行全部检测模块，适合深度审计''')
    parser.add_argument('-t', '--threads', type=int, default=8, 
                        help='并发线程数（默认：8，范围1-100）')
    parser.add_argument('-o', '--output', help='报告输出目录（默认：./reports）')
    parser.add_argument('-f', '--format', choices=['txt', 'html', 'json', 'csv'], default='txt', 
                        help='''报告格式（默认：txt）：
                        txt：简洁的文本报告，适合快速查看和日志记录
                        html：详细的网页报告，包含样式和表格，上下文列直接显示问题链接
                        json：结构化数据，适合程序处理和自动化集成
                        csv：表格数据，适合导入电子表格软件进行进一步分析''')
    
    # 高级配置
    parser.add_argument('--timeout', type=int, default=30, 
                        help='请求超时时间（秒，默认：30）。注意：工具会根据目标类型（内网/公网）自动优化超时设置')
    parser.add_argument('--proxy', help='''代理设置，格式：
                        http://username:password@host:port（有认证）或
                        http://host:port（无认证）''')
    parser.add_argument('--keyword-file', help='''自定义关键字文件路径（CSV格式）
                        格式示例：关键字,类别,风险权重
                        类别可选：gambling(博彩), porn(色情), malware(恶意软件), phishing(钓鱼), other(其他)
                        风险权重范围：1-10，10为最高风险''')
    parser.add_argument('--exclude', nargs='+', help='排除的文件或目录（支持通配符，如 "*.log" "node_modules/"）')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--verbose', action='store_true', default=False, help='显示详细日志信息，包括检测过程和调试内容')
    
    # 无头浏览器选项
    parser.add_argument('--headless', action='store_true', help='启用无头浏览器扫描 (增强动态内容检测)')
    parser.add_argument('--browser-type', choices=['chrome'], default='chrome', help='无头浏览器类型 (默认: chrome)')
    parser.add_argument('--js-wait', type=int, default=3, help='JavaScript执行等待时间 (秒, 默认: 3)')
    parser.add_argument('--headless-timeout', type=int, default=60, help='无头浏览器超时时间 (秒, 默认: 60)')
    parser.add_argument('--headless-binary', help='Chrome二进制路径 (例如: C\\Program Files\\Google\\Chrome\\Application\\chrome.exe)')
    
    # 添加使用示例
    parser.epilog = '''
使用示例：
  # 扫描单个HTML文件
  python YuanZhao.py test.html
  
  # 扫描目录及其子目录（深度为2）
  python YuanZhao.py ./website -d 2
  
  # 扫描URL，使用高级模式，保存为HTML格式报告
  python YuanZhao.py https://example.com -m standard -f html
  
  # 使用自定义关键字文件，禁用彩色输出
  python YuanZhao.py ./website --keyword-file custom_keywords.txt --no-color
  
  # 完整扫描公网网站并生成HTML报告（优化后格式，在上下文列显示完整问题链接）
  python YuanZhao.py https://example.com -m deep -d 1 -t 8 --timeout 30 -f html --verbose
  
  # 扫描特定新闻页面并在可疑链接详情中显示问题信息
  python YuanZhao.py https://example.com/news.php -m deep -d 1 -t 8 --timeout 30 -f html --verbose
  
  # 对内网网站进行深度扫描，使用较长超时时间
  python YuanZhao.py http://192.168.1.100 -d 4 -m deep --timeout 60 -f html -o intranet_reports
  
  # 扫描并排除特定文件类型
  python YuanZhao.py ./website --exclude "*.log" "temp/*" "node_modules/"
  
  # 使用无头浏览器增强扫描动态内容
  python YuanZhao.py https://example.com --headless --js-wait 5
  '''
    
    return parser.parse_args()

def validate_arguments(args):
    """
    验证命令行参数
    """
    # 验证目标是否存在（如果是文件或目录）
    if not args.target.startswith(('http://', 'https://')):
        if not os.path.exists(args.target):
            print(f"错误：目标 '{args.target}' 不存在")
            return False
    
    # 验证关键字文件
    if args.keyword_file and not os.path.exists(args.keyword_file):
        print(f"错误：关键字文件 '{args.keyword_file}' 不存在")
        return False
    
    # 验证线程数
    if args.threads < 1 or args.threads > 100:
        print("错误：线程数必须在1-100之间")
        return False
    
    # 验证扫描深度
    if args.depth < 0:
        print("错误：扫描深度不能为负数")
        return False
    
    return True

def main():
    """
    主函数
    """
    # 解析参数
    args = parse_arguments()
    
    # 验证参数
    if not validate_arguments(args):
        sys.exit(1)
    
    # 创建报告目录
    report_dir = args.output or os.path.join(os.getcwd(), 'reports')
    os.makedirs(report_dir, exist_ok=True)
    
    # 设置日志
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(log_dir=report_dir, level=log_level)
    
    # 记录开始时间
    start_time = datetime.now()
    logger.info(f"开始扫描：{args.target}")
    logger.info(f"扫描模式：{args.mode}")
    
    # 创建配置
    config = Config()
    
    # 设置配置属性
    # 判断目标类型
    if args.target.startswith(('http://', 'https://')):
        # 检查是否为内网链接
        parsed_url = urlparse(args.target)
        domain = parsed_url.netloc
        # 内网域名/IP特征
        if (re.match(r'^127\.0\.0\.1(:\d+)?$', domain) or 
            re.match(r'^localhost(:\d+)?$', domain) or
            re.match(r'^10\.\d+\.\d+\.\d+(:\d+)?$', domain) or
            re.match(r'^172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+(:\d+)?$', domain) or
            re.match(r'^192\.168\.\d+\.\d+(:\d+)?$', domain)):
            config.target_type = 'internal_url'
        else:
            config.target_type = 'external_url'
    elif os.path.isfile(args.target):
        config.target_type = 'local_file'
    elif os.path.isdir(args.target):
        config.target_type = 'local_directory'
    else:
        config.target_type = 'unknown'
    
    config.target = args.target
    config.crawl_depth = args.depth
    config.depth = args.depth  # 同步更新depth属性
    
    # 映射扫描模式（仅使用新名称）
    mode_mapping = {
        'fast': 'fast',
        'standard': 'standard',
        'deep': 'deep'
    }
    config.scan_mode = mode_mapping.get(args.mode, 'standard')
    config.mode = config.scan_mode  # 同步更新mode属性
    config._set_mode_config()  # 更新模式相关配置
    
    config.threads = args.threads
    config.timeout = args.timeout
    config.proxy = args.proxy
    config.keywords_file = args.keyword_file
    config.report_type = args.format
    config.report_file = os.path.join(report_dir, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}")
    config.debug = args.verbose
    # 排除规则
    config.exclude = args.exclude or []
    
    # 设置无头浏览器配置
    config.use_headless_browser = args.headless
    config.headless_browser = args.browser_type
    config.js_wait_time = args.js_wait
    config.headless_timeout = args.headless_timeout
    config.headless_binary = args.headless_binary
    if args.headless:
        config.headless_auto_download = True
    
    # 记录配置
    log_config(logger, config.get_config_dict())
    
    try:
        # 创建扫描器
        scanner = Scanner(config)
        
        # 开始扫描
        results = scanner.scan()
        
        # 记录结束时间
        end_time = datetime.now()
        duration = str(end_time - start_time)
        
        # 创建报告
        reporter = Reporter(config)
        report_file = reporter.generate_report(results, duration)
        scan_time = (end_time - start_time).total_seconds()
        
        # 记录总结
        log_summary(
            logger,
            total_files=results.get('total_files', 0),
            scanned_files=results.get('scanned_files', 0),
            issues_found=results.get('total_issues', 0),
            scan_time=scan_time
        )
        
        logger.info(f"扫描完成！报告已保存至：{report_file}")
        print(f"\n扫描完成！报告已保存至：{report_file}")
        
    except Exception as e:
        logger.error(f"扫描过程中发生错误：{str(e)}", exc_info=True)
        print(f"错误：扫描过程中发生错误 - {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
    
