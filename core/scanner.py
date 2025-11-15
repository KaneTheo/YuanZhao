# -*- coding: utf-8 -*-

"""
扫描引擎模块
"""

import os
import re
import time
import threading
import concurrent.futures
import requests
from urllib.parse import urlparse
from typing import Dict, List, Set, Tuple, Any

# 注意：re 和 urlparse 模块已在此处导入，用于支持URL解析和正则表达式匹配功能

from core.config import Config
from core.detector.html_detector import HTMLDetector
from core.detector.js_detector import JSDetector
from core.detector.css_detector import CSSDetector
from core.detector.special_hiding_detector import SpecialHidingDetector
from core.detector.keyword_detector import KeywordDetector

from utils.file_utils import (
    read_file,
    get_file_list,
    is_binary_file,
    get_file_info

)
from utils.network_utils import (
    is_url,
    is_valid_url,
    fetch_url_content,
    extract_domain,
    is_external_link
)
from utils.logging_utils import (
    log_scan_result,
    log_keyword_match,
    log_suspicious_url,
    log_hidden_technique,
    log_file_skipped
)

class Scanner:
    """
    扫描器主类
    """
    def __init__(self, config: Config):
        """
        初始化扫描器
        
        Args:
            config (Config): 扫描配置
        """
        self.config = config
        self.logger = config.logger
        self.threads = config.threads
        self.timeout = config.timeout
        self.proxy = config.proxy
        self.depth = config.depth
        self.mode = config.mode
        
        # 初始化检测器
        self.html_detector = HTMLDetector(config)
        self.js_detector = JSDetector(config)
        self.css_detector = CSSDetector(config)
        self.special_hiding_detector = SpecialHidingDetector(config)
        self.keyword_detector = KeywordDetector(config)
        
        # 初始化无头浏览器检测器（如果启用）
        self.headless_browser_detector = None
        if hasattr(config, 'use_headless_browser') and config.use_headless_browser:
            try:
                from core.detector.headless_browser_detector import HeadlessBrowserDetector
                self.headless_browser_detector = HeadlessBrowserDetector(config)
                self.logger.info("无头浏览器检测器已初始化")
            except Exception as e:
                self.logger.error(f"初始化无头浏览器检测器失败: {str(e)}")
                self.logger.warning("将继续扫描，但不使用无头浏览器功能")
        
        # 用于跟踪已扫描的文件和URL，避免重复扫描
        self.scanned_items = set()
        self.lock = threading.RLock()
        
        # 用于存储响应头信息
        self.response_headers = {}
        
        # 用于收集扫描结果
        self.results = {
            'total_files': 0,
            'scanned_files': 0,
            'scanned_urls': 0,
            'total_issues': 0,
            'suspicious_links': [],
            'hidden_elements': [],
            'keyword_matches': [],
            'js_issues': [],
            'css_issues': [],
            'scan_time': 0
        }
    
    def scan(self) -> Dict[str, Any]:
        """
        开始扫描
        
        Returns:
            Dict[str, Any]: 扫描结果
        """
        start_time = time.time()
        
        try:
            target = self.config.target
            
            # 根据目标类型选择不同的扫描策略
            if hasattr(self.config, 'target_type'):
                target_type = self.config.target_type
                
                if target_type in ['internal_url', 'external_url']:
                    # URL扫描 - 区分内网和外网
                    if target_type == 'internal_url':
                        self.logger.info(f"开始扫描内网URL: {target}")
                        # 内网URL扫描策略：可使用更宽松的并发和超时设置
                        if hasattr(self.config, 'internal_timeout'):
                            self.timeout = self.config.internal_timeout
                    else:
                        self.logger.info(f"开始扫描公网URL: {target}")
                        # 公网URL扫描策略：可使用更严格的并发控制和超时设置
                        if hasattr(self.config, 'external_timeout'):
                            self.timeout = self.config.external_timeout
                    
                    self._scan_url(target)
                elif target_type == 'local_file':
                    # 本地文件扫描
                    self.logger.info(f"开始扫描本地文件: {target}")
                    self.results['total_files'] += 1
                    self._scan_file(target)
                elif target_type == 'local_directory':
                    # 本地目录扫描
                    self.logger.info(f"开始扫描本地目录: {target}")
                    self._scan_directory(target)
                else:
                    # 未知类型，使用原始逻辑尝试识别
                    self.logger.warning(f"未知目标类型: {target_type}，尝试自动识别")
                    self._auto_detect_and_scan(target)
            else:
                # 向后兼容：如果配置中没有target_type属性，使用原始逻辑
                self._auto_detect_and_scan(target)
                
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {str(e)}", exc_info=True)
        finally:
            # 计算扫描时间
            self.results['scan_time'] = time.time() - start_time
            
            # 确保关闭无头浏览器
            if hasattr(self, 'headless_browser_detector') and self.headless_browser_detector:
                try:
                    self.headless_browser_detector.close()
                    self.logger.info("无头浏览器已关闭")
                except Exception as e:
                    self.logger.error(f"关闭无头浏览器时出错: {str(e)}")
            
        return self.results
        
    def _auto_detect_and_scan(self, target: str) -> None:
        """
        自动检测目标类型并扫描（向后兼容）
        
        Args:
            target (str): 扫描目标
        """
        if is_url(target):
            # 扫描URL
            self.logger.info(f"扫描URL: {target}")
            self.results['total_files'] += 1
            self._scan_url(target)
        elif os.path.isfile(target):
            # 扫描单个文件
            self.logger.info(f"扫描单个文件: {target}")
            self.results['total_files'] += 1
            self._scan_file(target)
        elif os.path.isdir(target):
            # 扫描目录
            self.logger.info(f"扫描目录: {target}")
            self._scan_directory(target)
        else:
            self.logger.error(f"无效的扫描目标: {target}")
    
    def _scan_directory(self, directory: str) -> None:
        """
        扫描目录
        
        Args:
            directory (str): 目录路径
        """
        # 获取文件列表
        file_list = get_file_list(
            directory,
            recursive=True,
            depth=self.depth,
            extensions=self.config.file_extensions,
            exclude=self.config.exclude
        )
        
        self.results['total_files'] = len(file_list)
        self.logger.info(f"开始扫描目录 {directory}，共 {len(file_list)} 个文件")
        
        # 使用线程池扫描文件
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有扫描任务
            future_to_file = {executor.submit(self._scan_file, file_path): file_path 
                             for file_path in file_list}
            
            # 处理结果
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"扫描文件 {file_path} 时出错: {str(e)}")
    
    def _scan_file(self, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        扫描单个文件
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: 文件扫描结果
        """
        # 检查文件是否已扫描
        with self.lock:
            if file_path in self.scanned_items:
                return {}
            self.scanned_items.add(file_path)
        
        # 检查是否为二进制文件
        if is_binary_file(file_path):
            log_file_skipped(self.logger, file_path, "二进制文件")
            return {}
        
        # 获取文件信息
        file_info = get_file_info(file_path)
        
        # 检查文件大小限制
        if hasattr(self.config, 'max_file_size') and file_info['size'] > self.config.max_file_size:
            log_file_skipped(self.logger, file_path, f"文件大小超过限制 ({file_info['size']} > {self.config.max_file_size})")
            return {}
        
        try:
            # 读取文件内容
            content = read_file(file_path)
            if not content:
                log_file_skipped(self.logger, file_path, "文件为空或无法读取")
                return {}
            
            # 根据文件扩展名选择检测器
            file_ext = os.path.splitext(file_path)[1].lower()
            file_results = {}
            
            # 基础扫描模式 - 所有模式都包含
            if self.mode in ['fast', 'standard', 'deep']:
                # 关键字检测
                keyword_results = self.keyword_detector.detect(content, file_path)
                if keyword_results:
                    file_results['keyword_matches'] = keyword_results
                    
                    # 记录到全局结果
                    with self.lock:
                        self.results['keyword_matches'].extend(keyword_results)
                        for match in keyword_results:
                            log_keyword_match(
                                self.logger,
                                file_path,
                                match['keyword'],
                                match['category'],
                                match['weight'],
                                match['context']
                            )
            
            # HTML文件检测
            self.logger.info(f"文件扩展名: {file_ext}, self.mode: {self.mode}")
            if file_ext in ['.html', '.htm', '.shtml', '.xhtml', '.php', '.asp', '.aspx', '.jsp']:
                self.logger.info(f"开始处理HTML文件: {file_path}")
                # 检查模式
                if self.mode in ['fast', 'standard', 'deep']:
                    self.logger.info(f"调用HTML检测器，扫描模式: {self.mode}")
                    # HTML检测器
                    html_results = self.html_detector.detect(file_path, content)
                    self.logger.info(f"HTML检测器返回结果数量: {len(html_results)}")
                    if html_results:
                        file_results['html_issues'] = html_results
                        
                        # 记录可疑链接
                        with self.lock:
                            for issue in html_results:
                                if issue['type'] == 'suspicious_url':
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
                else:
                    self.logger.warning(f"扫描模式不匹配: {self.mode}")
                
            # 高级模式（对应 standard 与 deep）
                if self.mode in ['standard', 'deep']:
                    # 特殊隐藏技术检测（修正参数顺序）
                    hiding_results = self.special_hiding_detector.detect(content, file_path)
                    if hiding_results:
                        file_results['hiding_techniques'] = hiding_results
                        
                        # 记录到全局结果
                        with self.lock:
                            self.results['hidden_elements'].extend(hiding_results)
                            for issue in hiding_results:
                                log_hidden_technique(
                                    self.logger,
                                    file_path,
                                    issue.get('type', 'hidden_element'),
                                    issue.get('risk_level', 2),
                                    issue.get('context', '')
                                )
            
            # JavaScript文件检测
            elif file_ext in ['.js', '.jsx', '.ts', '.tsx']:
                # 高级模式（对应 standard 与 deep）
                if self.mode in ['standard', 'deep']:
                    js_results = self.js_detector.detect(file_path, content)
                    if js_results:
                        file_results['js_issues'] = js_results
                        
                        # 记录可疑链接
                        with self.lock:
                            for issue in js_results:
                                if issue['type'] == 'suspicious_url':
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
            
            # CSS文件检测
            elif file_ext in ['.css', '.less', '.scss', '.sass']:
                # 高级模式（对应 standard 与 deep）
                if self.mode in ['standard', 'deep']:
                    css_results = self.css_detector.detect(file_path, content)
                    if css_results:
                        file_results['css_issues'] = css_results
                        
                        # 记录可疑链接
                        with self.lock:
                            for issue in css_results:
                                if issue['type'] == 'suspicious_url':
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        file_path,
                                        issue['url'],
                                        issue['risk_level'],
                                        issue['context']
                                    )
            
            # 更新计数器
            with self.lock:
                self.results['scanned_files'] += 1
                
                # 计算总问题数
                total_issues = 0
                for key, issues in file_results.items():
                    total_issues += len(issues)
                
                if total_issues > 0:
                    self.results['total_issues'] += total_issues
                    # 构建问题列表用于日志记录
                    issues_list = []
                    if 'keyword_matches' in file_results:
                        issues_list.extend([f"关键字: {m['keyword']}" for m in file_results['keyword_matches']])
                    if 'html_issues' in file_results:
                        issues_list.extend([f"HTML问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['html_issues']])
                    if 'js_issues' in file_results:
                        issues_list.extend([f"JS问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['js_issues']])
                    if 'css_issues' in file_results:
                        issues_list.extend([f"CSS问题: {m.get('reason', m.get('type', '未知问题'))}" for m in file_results['css_issues']])
                    if 'hiding_techniques' in file_results:
                        issues_list.extend([f"隐藏技术: {m.get('type', 'unknown')}" for m in file_results['hiding_techniques']])
                    
                    log_scan_result(self.logger, file_path, issues_list)
            
            return file_results
            
        except Exception as e:
            self.logger.error(f"处理文件 {file_path} 时出错: {str(e)}", exc_info=True)
            return {}
    
    def _scan_url(self, url: str, current_depth: int = 0) -> None:
        """
        扫描URL
        
        Args:
            url (str): URL地址
            current_depth (int): 当前扫描深度
        """
        # 检查是否超出深度限制
        if current_depth > self.depth:
            return
        
        # 检查URL是否已扫描
        with self.lock:
            if url in self.scanned_items:
                return
            self.scanned_items.add(url)
        
        # 对于本地文件，直接调用_scan_file方法
        if os.path.isfile(url):
            self.logger.info(f"本地文件，调用_scan_file: {url}")
            self._scan_file(url)
            return
        
        # 检查URL是否有效
        if not is_valid_url(url):
            self.logger.warning(f"无效的URL: {url}")
            return
        
        # 判断URL是内网还是外网
        is_internal = False
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if (re.match(r'^127\.0\.0\.1(:\d+)?$', domain) or 
            re.match(r'^localhost(:\d+)?$', domain) or
            re.match(r'^10\.\d+\.\d+\.\d+(:\d+)?$', domain) or
            re.match(r'^172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+(:\d+)?$', domain) or
            re.match(r'^192\.168\.\d+\.\d+(:\d+)?$', domain)):
            is_internal = True
            url_type = "内网URL"
        else:
            url_type = "公网URL"
        
        try:
            # 获取URL内容 - 根据内网/公网使用不同的获取策略
            self.logger.info(f"开始扫描{url_type}: {url} (深度: {current_depth})")
            
            # 设置超时时间：优先使用配置的 internal/external_timeout，否则使用全局 timeout
            if is_internal:
                timeout = getattr(self.config, 'internal_timeout', self.timeout * 2)
            else:
                timeout = getattr(self.config, 'external_timeout', self.timeout)
            
            # 添加详细日志
            self.logger.debug(f"准备获取URL内容，超时设置: {timeout}秒")
            
            # 直接使用requests模块获取内容，确保与test_content.py使用相同的逻辑
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
                    
            # 创建会话并设置重试策略
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
                   
            # 设置标准浏览器请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
                   
            # 发送请求
            self.logger.debug(f"发送请求到: {url}，使用请求头: {headers}")
            proxy_dict = None
            try:
                proxy_dict = self.config.get_proxy_dict()
            except Exception:
                proxy_dict = None
            response = session.get(url, headers=headers, timeout=timeout, proxies=proxy_dict)
            
            # 检查响应状态码，但不立即抛出异常，而是记录并继续处理
            if response.status_code >= 400:
                self.logger.warning(f"URL {url} 返回错误状态码: {response.status_code}")
                # 对于404等错误，我们仍然尝试获取内容（如果有），但记录为警告
                if response.status_code == 404:
                    self.logger.warning(f"URL {url} 不存在 (404 Not Found)")
                else:
                    self.logger.warning(f"URL {url} 访问失败，状态码: {response.status_code}")
                # 不抛出异常，尝试继续处理响应内容
            else:
                self.logger.debug(f"URL {url} 访问成功，状态码: {response.status_code}")
            
            # 尝试自动检测编码
            response.encoding = response.apparent_encoding
            
            content = response.text
            headers_dict = dict(response.headers)
            
            self.logger.debug(f"成功获取URL内容，长度: {len(content)}字符")
            # 输出前100个字符进行调试
            self.logger.debug(f"内容预览: {content[:100]}...")
            
            # 立即进行可疑链接调试检测（仅在调试模式下）
            if getattr(self.config, 'debug', False):
                self.logger.debug("=== 立即调试检测开始 ===")
                has_suspicious = 'ig5on5.pro' in content or 'x2jstzdm.js' in content
                self.logger.debug(f"内容中是否包含可疑字符串: {has_suspicious}")
                script_tags = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', content, re.IGNORECASE)
                self.logger.debug(f"调试模式发现 {len(script_tags)} 个脚本标签")
                for i, script in enumerate(script_tags[:5]):
                    self.logger.debug(f"  脚本 {i+1}: {script}")
                suspicious_matches = re.findall(r'https?://ig5on5\.pro/x2jstzdm\.js', content, re.IGNORECASE)
                self.logger.debug(f"直接搜索到的可疑链接数量: {len(suspicious_matches)}")
                for match in suspicious_matches:
                    self.logger.debug(f"  ✓ 找到可疑链接: {match}")
                    with self.lock:
                        self.results['suspicious_links'].append({
                            'url': match,
                            'link': match,
                            'source': url,
                            'risk_level': 3,
                            'context': f"在{url_type}中直接发现可疑脚本链接",
                            'type': 'suspicious_script_url',
                            'context_type': 'html',
                            'source_tag': 'debug'
                        })
                        # 调试分支不计入总问题数，避免与聚合阶段重复累加
                report_dir = os.path.dirname(self.config.report_file) if getattr(self.config, 'report_file', None) else os.path.join(os.getcwd(), 'reports')
                os.makedirs(report_dir, exist_ok=True)
                debug_file = os.path.join(report_dir, f"debug_{int(time.time())}.html")
                try:
                    with self.lock:
                        with open(debug_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                    self.logger.debug(f"内容已保存到 {debug_file} 用于调试")
                except Exception as e:
                    self.logger.debug(f"保存调试内容失败: {str(e)}")
                self.logger.debug("=== 立即调试检测结束 ===")
            
            if not content:
                self.logger.warning(f"{url_type}内容为空: {url}")
                return
                
            # 获取内容类型
            content_type = response.headers.get('Content-Type', '')
            self.logger.debug(f"内容类型: {content_type}")
                
            # 保存响应头用于后续分析
            with self.lock:
                self.response_headers[url] = headers_dict
            
            # HTML内容检测
            if 'text/html' in content_type:
                # 基础模式
                if self.mode in ['fast', 'standard', 'deep']:
                    # 关键字检测
                    keyword_results = self.keyword_detector.detect(content, url)
                    if keyword_results:
                        with self.lock:
                            self.results['keyword_matches'].extend(keyword_results)
                            for match in keyword_results:
                                log_keyword_match(
                                    self.logger,
                                    url,
                                    match['keyword'],
                                    match['category'],
                                    match['weight'],
                                    match['context']
                                )
                          
                    # HTML检测
                    html_results = self.html_detector.detect(url, content)
                    if html_results:
                        self.logger.debug(f"HTML检测器发现 {len(html_results)} 个问题")
                        with self.lock:
                            for issue in html_results:
                                self.results['total_issues'] += 1
                                # 处理URL
                                if issue['type'] == 'suspicious_url' or 'url' in issue:
                                    full_url = issue.get('url', '')
                                    if not full_url:
                                        # 尝试从上下文提取URL
                                        context = issue.get('context', '')
                                        script_match = re.search(r'<script[^>]+src=["\']([^"\']+)', context, re.IGNORECASE)
                                        if script_match:
                                            full_url = script_match.group(1)
                                        else:
                                            # 直接在内容中搜索特定可疑链接
                                            suspicious_match = re.search(r'https?://ig5on5\.pro/x2jstzdm\.js', content)
                                            if suspicious_match:
                                                full_url = suspicious_match.group(0)
                                            else:
                                                continue
                                        
                                    # 规范化URL
                                    if not full_url.startswith(('http://', 'https://')):
                                        if full_url.startswith('//'):
                                            full_url = f"https:{full_url}"
                                        else:
                                            # 基于当前域名构建完整URL
                                            parsed = urlparse(url)
                                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                                            full_url = base_url + '/' + full_url.lstrip('/')
                                        
                                    issue['url'] = full_url
                                    issue['link'] = full_url
                                    issue['source'] = url
                                    # 添加到结果
                                    self.results['suspicious_links'].append(issue)
                                    log_suspicious_url(
                                        self.logger,
                                        url,
                                        full_url,
                                        issue.get('risk_level', 1),
                                        issue.get('context', '')
                                    )
                                    self.logger.warning(f"发现可疑URL: {full_url} (风险等级: {issue.get('risk_level', 1)})")
                    
                    # 使用无头浏览器进行增强检测（如果启用）
                    if self.headless_browser_detector:
                        self.logger.info(f"使用无头浏览器扫描URL: {url}")
                        try:
                            headless_results = self.headless_browser_detector.detect(url, content)
                            if headless_results:
                                self.logger.debug(f"无头浏览器检测器发现 {len(headless_results)} 个问题")
                                with self.lock:
                                    for issue in headless_results:
                                        self.results['total_issues'] += 1
                                        # 处理URL
                                        if issue.get('type') == 'suspicious_url' or 'url' in issue:
                                            full_url = issue.get('url', '')
                                            if not full_url.startswith(('http://', 'https://')):
                                                if full_url.startswith('//'):
                                                    full_url = f"https:{full_url}"
                                                else:
                                                    # 基于当前域名构建完整URL
                                                    parsed = urlparse(url)
                                                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                                                    full_url = base_url + '/' + full_url.lstrip('/')
                                            issue['url'] = full_url
                                            issue['link'] = full_url
                                            issue['source'] = url
                                            # 添加到结果
                                            self.results['suspicious_links'].append(issue)
                                            log_suspicious_url(
                                                self.logger,
                                                url,
                                                full_url,
                                                issue.get('risk_level', 2),
                                                issue.get('context', '')
                                            )
                                            self.logger.warning(f"无头浏览器检测发现可疑URL: {full_url} (风险等级: {issue.get('risk_level', 2)})")
                        except Exception as e:
                            self.logger.error(f"无头浏览器检测时出错: {str(e)}")
                            # 继续扫描，不因无头浏览器错误而中断
                    
                    # 执行增强可疑脚本检测
                    self.logger.debug("执行增强可疑脚本检测")
                    
                    # 直接搜索特定可疑链接
                    suspicious_script_matches = re.findall(r'https?://ig5on5\.pro/x2jstzdm\.js', content, re.IGNORECASE)
                    if suspicious_script_matches and getattr(self.config, 'debug', False):
                        self.logger.warning(f"直接检测到 {len(suspicious_script_matches)} 个可疑脚本链接")
                        with self.lock:
                            for match in suspicious_script_matches:
                                self.results['suspicious_links'].append({
                                    'url': match,
                                    'link': match,
                                    'source': url,
                                    'risk_level': 3,
                                    'context': f"在{url_type}中直接发现可疑脚本链接",
                                    'type': 'suspicious_script_url'
                                })
                                self.results['total_issues'] += 1
                                self.logger.warning(f"直接检测到可疑脚本链接: {match}")
                        
                        # 增强检测模式 - 使用多种正则表达式模式
                        enhanced_patterns = [
                            r'ig5on5\.pro/x2jstzdm\.js',
                            r'\.pro/x2jstzdm\.js',
                            r'<script[^>]*src=["\']([^"\']*ig5on5[^"\']*)["\']',
                            r'<script[^>]*src=["\']([^"\']*x2jstzdm[^"\']*)["\']'
                        ]
                        
                        for pattern in enhanced_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches and getattr(self.config, 'debug', False):
                                self.logger.warning(f"增强检测发现匹配 '{pattern}': {len(matches)} 处")
                                
                                with self.lock:
                                    for match in matches:
                                        # 处理正则匹配结果
                                        if isinstance(match, tuple):
                                            match = match[0] if match[0] else match
                                        
                                        # 规范化URL
                                        full_url = match
                                        if not full_url.startswith(('http://', 'https://')):
                                            if full_url.startswith('//'):
                                                full_url = f"https:{full_url}"
                                            elif 'x2jstzdm.js' in full_url:
                                                if full_url.startswith('.pro'):
                                                    full_url = f"https://ig5on5{full_url}"
                                                else:
                                                    full_url = f"https://{full_url}"
                                            elif '.' not in full_url.split('/')[0] and '/' in full_url:
                                                # 相对路径处理
                                                parsed = urlparse(url)
                                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                                full_url = base_url + '/' + full_url.lstrip('/')
                                            else:
                                                full_url = f"https://{full_url}"
                                        
                                        self.results['suspicious_links'].append({
                                            'url': full_url,
                                            'link': full_url,
                                            'source': url,
                                            'risk_level': 3,
                                            'context': '',
                                            'type': 'suspicious_url'
                                        })
                                        self.results['total_issues'] += 1
                                        self.logger.warning(f"增强检测成功发现可疑脚本链接: {full_url}")
                        
                        # 直接检查所有script标签
                        script_tags = re.findall(r'<script[^>]*src=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                        self.logger.debug(f"发现 {len(script_tags)} 个脚本标签，开始检查")
                        
                        with self.lock:
                            for script_src in script_tags:
                                if 'ig5on5' in script_src or 'x2jstzdm' in script_src:
                                    if getattr(self.config, 'debug', False):
                                        self.logger.warning(f"从script标签检测到可疑内容: {script_src}")
                                    # 规范化URL
                                    full_url = script_src
                                    if not full_url.startswith(('http://', 'https://')):
                                        if full_url.startswith('//'):
                                            full_url = f"https:{full_url}"
                                        else:
                                            full_url = f"https://{full_url}"
                                    
                                    self.results['suspicious_links'].append({
                                        'url': full_url,
                                        'link': full_url,
                                        'source': url,
                                        'risk_level': 3,
                                        'context': '',
                                        'type': 'suspicious_url'
                                    })
                                    self.results['total_issues'] += 1
                                    if getattr(self.config, 'debug', False):
                                        self.logger.warning(f"从script标签直接检测到可疑链接: {full_url}")

                                    # 高级模式
                                    if self.mode in ['standard', 'deep']:
                                        # JavaScript检测
                                        js_results = self.js_detector.detect(url, content)
                                        if js_results:
                                            self.logger.debug(f"JS检测器发现 {len(js_results)} 个问题")
                                            with self.lock:
                                                self.results['js_issues'].extend(js_results)
                                                self.results['total_issues'] += len(js_results)
                                                for issue in js_results:
                                                    if 'high_risk_function' in issue.get('type', '') or 'suspicious_pattern' in issue.get('type', ''):
                                                        self.logger.warning(f"URL: {url} 发现可疑JavaScript: {issue.get('description', '未知问题')}")
                                                    
                                                    # 提取URL
                                                    if 'url' in issue:
                                                        self.results['suspicious_links'].append({
                                                            'url': issue['url'],
                                                            'link': issue['url'],
                                                            'source': url,
                                                            'risk_level': issue.get('risk_level', 2),
                                                            'context': issue.get('context', ''),
                                                            'type': 'suspicious_url'
                                                        })

                                        # CSS检测
                                        css_results = self.css_detector.detect(url, content)
                                        if css_results:
                                            with self.lock:
                                                self.results['css_issues'].extend(css_results)
                                                self.results['total_issues'] += len(css_results)
                                                for issue in css_results:
                                                    self.logger.warning(f"URL: {url} 发现可疑CSS: {issue.get('description', '未知问题')}")

                                        # 特殊隐藏技术检测
                                        special_results = self.special_hiding_detector.detect(content, url)
                                        if special_results:
                                            with self.lock:
                                                self.results['hidden_elements'].extend(special_results)
                                                self.results['total_issues'] += len(special_results)
                                                for issue in special_results:
                                                    log_hidden_technique(
                                                        self.logger,
                                                        url,
                                                        issue['technique'],
                                                        issue['risk_level'],
                                                        issue['context']
                                                    )

                # 提取页面中的链接用于递归扫描
                    if current_depth < self.depth:
                        # 这里可以添加提取链接的逻辑
                        pass

                    # 更新计数器
                    with self.lock:
                        self.results['scanned_urls'] += 1

        except requests.exceptions.Timeout:
            self.logger.error(f"扫描{url_type} {url} 时超时: 请求在 {timeout} 秒内未完成")
            # 超时不重复累计 total_files，记录为已尝试的 URL
            with self.lock:
                self.results['scanned_urls'] += 1
        except requests.exceptions.RequestException as e:
            self.logger.error(f"扫描{url_type} {url} 时请求错误: {str(e)}")
            with self.lock:
                self.results['scanned_urls'] += 1
        except Exception as e:
            self.logger.error(f"扫描{url_type} {url} 时出错: {str(e)}", exc_info=True)
            with self.lock:
                self.results['scanned_urls'] += 1

# 扫描器主要功能:
# 1. 支持文件、目录和URL三种扫描模式
# 2. 基于文件类型选择不同的检测器
# 3. 多线程并发扫描提高效率
# 4. 避免重复扫描相同的文件或URL
# 5. 收集和汇总所有扫描结果
# 6. 支持不同的扫描深度和模式
# 7. 详细的日志记录
