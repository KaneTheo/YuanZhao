# -*- coding: utf-8 -*-

"""
HTML检测器模块
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from utils.html_utils import (
    extract_script_tags,
    extract_link_tags,
    extract_meta_tags,
    extract_iframe_tags,
    find_hidden_elements,
    get_dom_structure,
    extract_comments
)
from utils.network_utils import (
    extract_urls,
    is_external_link,
    extract_domain
)
from utils.common_utils import (
    extract_text_between_markers,
    get_context
)

class HTMLDetector:
    """
    HTML内容检测器，用于检测HTML文件中的可疑链接和隐藏元素
    """
    
    def __init__(self, config):
        """
        初始化HTML检测器
        
        Args:
            config: 扫描配置对象
        """
        self.config = config
        self.logger = config.logger
        
        # 可疑HTML模式
        self.suspicious_patterns = {
            'suspicious_attributes': re.compile(r'\bon\w+\s*=\s*["\']?javascript:', re.IGNORECASE),
            'eval_inline': re.compile(r'\beval\s*\(', re.IGNORECASE),
            'document_write': re.compile(r'\bdocument\.write\s*\(', re.IGNORECASE),
            'base64_decode': re.compile(r'\batob\s*\(|\bfromCharCode\s*\(', re.IGNORECASE),
            'data_uri': re.compile(r'data:[^;]+;base64,', re.IGNORECASE),
            'remote_iframe': re.compile(r'<iframe[^>]+src=["\']?https?://', re.IGNORECASE),
            'hidden_divs': re.compile(r'<(div|span|p|section|article)[^>]+style=["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\']', re.IGNORECASE),
            'obfuscated_attributes': re.compile(r'\b(data-|on)[a-z0-9_-]+\s*=\s*["\']?[^"\']*(\\\\x[0-9a-f]{2}|\\\\u[0-9a-f]{4})[^"\']*["\']?', re.IGNORECASE),
        }
        
        # 可疑域名模式
        self.suspicious_domain_patterns = [
            re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+\b(?:cn|cc|tk|ml|ga|cf|pro|xyz|pw|top|loan|win|bid|online)\b', re.IGNORECASE),
            re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+\b(?:bet|casino|poker|gamble)\b', re.IGNORECASE),
            re.compile(r'\b(?:[a-z0-9]{8,}\.)+\b(?:[a-z]{2,})\b', re.IGNORECASE),  # 检测8个字符以上的随机域名前缀
        ]
        
    def detect(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML内容中的可疑元素
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            检测结果列表
        """
        results = []
        
        try:
            # 1. 检测可疑URL
            url_results = self._detect_suspicious_urls(file_path, content)
            results.extend(url_results)
            
            # 2. 检测可疑模式
            pattern_results = self._detect_suspicious_patterns(file_path, content)
            results.extend(pattern_results)
            
            # 3. 检测隐藏元素
            hidden_results = self._detect_hidden_elements(file_path, content)
            results.extend(hidden_results)
            
            # 4. 检测可疑注释
            comment_results = self._detect_suspicious_comments(file_path, content)
            results.extend(comment_results)
            
            # 5. 检测可疑Meta标签
            meta_results = self._detect_suspicious_meta(file_path, content)
            results.extend(meta_results)
            
        except Exception as e:
            self.logger.error(f"HTML检测过程中发生错误: {str(e)}", exc_info=True)
        
        return results
    
    def _detect_suspicious_urls(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑URL
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑URL检测结果
        """
        results = []
        
        # 提取所有URL
        urls = extract_urls(content)
        
        for url_obj in urls:
            url = url_obj['url']
            context = url_obj['context']
            
            # 计算风险等级
            risk_level, reason = self._calculate_url_risk(url, context)
            
            if risk_level > 0:
                result = {
                    'type': 'suspicious_url',
                    'file_path': file_path,
                    'url': url,
                    'risk_level': risk_level,
                    'reason': reason,
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _calculate_url_risk(self, url: str, context: str) -> tuple:
        """
        计算URL的风险等级
        
        Args:
            url: 要评估的URL
            context: URL的上下文
            
        Returns:
            (风险等级, 原因)
        """
        risk_level = 0
        reason = []
        
        # 检测外部链接
        if url.lower().startswith(('http://', 'https://')):
            risk_level += 2  # 提高外部链接的基础风险等级
            reason.append('外部链接')
            
            # 检测可疑域名后缀
            suspicious_tlds = ['pro', 'xyz', 'pw', 'top', 'loan', 'win', 'bid', 'online']
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            for tld in suspicious_tlds:
                if domain.endswith('.' + tld):
                    risk_level += 2
                    reason.append(f'使用高风险域名后缀: {tld}')
                    break
            
            # 检测短随机字符串域名
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2 and len(domain_parts[-2]) >= 8 and not any(c.isdigit() for c in domain_parts[-2]):
                risk_level += 2
                reason.append('可能为随机生成的可疑域名')
        
        # 检查是否使用了可疑端口
        parsed_url = urlparse(url)
        if parsed_url.port and parsed_url.port not in [80, 443, 8080, 8443]:
            risk_level += 2
            reason.append('使用非标准端口')
        
        # 检查是否包含可疑查询参数
        suspicious_params = ['redirect', 'proxy', 'referer', 'origin', 'callback']
        if parsed_url.query:
            for param in suspicious_params:
                if param in parsed_url.query.lower():
                    risk_level += 1
                    reason.append(f'包含可疑参数: {param}')
                    break
        
        # 检查是否使用了短链接服务
        short_link_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'adf.ly']
        domain = extract_domain(url)
        if domain in short_link_domains:
            risk_level += 3
            reason.append('使用短链接服务')
        
        # 检查是否匹配可疑域名模式
        for pattern in self.suspicious_domain_patterns:
            if pattern.search(url):
                risk_level += 2
                reason.append('匹配可疑域名模式')
                break
        
        # 检查上下文是否包含可疑关键词
        suspicious_context_keywords = ['hidden', 'display:none', 'visibility:hidden', 'opacity:0']
        for keyword in suspicious_context_keywords:
            if keyword.lower() in context.lower():
                risk_level += 2
                reason.append('URL位于可疑上下文中')
                break
        
        # 检查是否为JavaScript伪协议
        if url.lower().startswith('javascript:'):
            risk_level += 4
            reason.append('JavaScript伪协议')
        
        return risk_level, ', '.join(reason)
    
    def _detect_suspicious_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑模式
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑模式检测结果
        """
        results = []
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            for match in pattern.finditer(content):
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(content), match.end() + 50)
                context = get_context(content, match.start(), 50)
                
                # 计算风险等级
                risk_level = self._get_pattern_risk_level(pattern_name)
                
                result = {
                    'type': 'suspicious_pattern',
                    'file_path': file_path,
                    'pattern': pattern_name,
                    'matched_content': match.group(0),
                    'risk_level': risk_level,
                    'description': self._get_pattern_description(pattern_name),
                    'context': context
                }
                results.append(result)
        
        # 检测内联脚本
        script_tags = extract_script_tags(content)
        for script in script_tags:
            is_inline = script.get('inline') if 'inline' in script else (not script.get('src') and bool(script.get('content')))
            if is_inline:
                # 统计脚本长度
                script_length = len(script['content'])
                
                # 检测复杂内联脚本
                if script_length > 1000:
                    context = get_context(content, script['start_pos'], script['end_pos'], 100)
                    result = {
                        'type': 'suspicious_pattern',
                        'file_path': file_path,
                        'pattern': 'large_inline_script',
                        'matched_content': script['content'][:200] + '...',
                        'risk_level': 2,
                        'description': '大型内联脚本',
                        'context': context
                    }
                    results.append(result)
        
        return results
    
    def _get_pattern_risk_level(self, pattern_name: str) -> int:
        """
        获取模式的风险等级
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            风险等级
        """
        risk_levels = {
            'suspicious_attributes': 3,
            'eval_inline': 4,
            'document_write': 3,
            'base64_decode': 2,
            'data_uri': 2,
            'remote_iframe': 3,
            'hidden_divs': 2,
            'obfuscated_attributes': 3
        }
        
        return risk_levels.get(pattern_name, 1)
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """
        获取模式的描述
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            描述文本
        """
        descriptions = {
            'suspicious_attributes': '可疑的事件属性',
            'eval_inline': '内联eval函数',
            'document_write': 'document.write调用',
            'base64_decode': 'Base64解码操作',
            'data_uri': 'Data URI',
            'remote_iframe': '远程iframe',
            'hidden_divs': '隐藏的div元素',
            'obfuscated_attributes': '混淆的属性'
        }
        
        return descriptions.get(pattern_name, pattern_name)
    
    def _detect_hidden_elements(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的隐藏元素
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            隐藏元素检测结果
        """
        results = []
        
        hidden_elements = find_hidden_elements(content)
        
        for element in hidden_elements:
            # 确保元素字典包含必要的键
            if not all(key in element for key in ['type', 'method', 'context']):
                # 如果缺少必要的键，使用默认值
                element_type = element.get('type', 'unknown')
                hiding_method = element.get('method', 'unknown')
                context = element.get('context', '')
            else:
                element_type = element['type']
                hiding_method = element['method']
                context = element['context']
            
            # 计算风险等级
            risk_level = self._calculate_hidden_element_risk(element)
            
            if risk_level > 0:
                result = {
                    'type': 'hidden_element',
                    'file_path': file_path,
                    'element_type': element_type,
                    'hiding_method': hiding_method,
                    'risk_level': risk_level,
                    'context': context,
                    'description': f"隐藏的{element_type}元素，使用{hiding_method}技术"
                }
                results.append(result)
        
        return results
    
    def _calculate_hidden_element_risk(self, element: Dict[str, Any]) -> int:
        """
        计算隐藏元素的风险等级
        
        Args:
            element: 隐藏元素信息
            
        Returns:
            风险等级
        """
        # 基础风险
        risk_level = 1
        
        # 根据隐藏方法调整风险，确保'method'键存在
        high_risk_methods = ['position:absolute', 'opacity:0', 'clip-path']
        if 'method' in element and any(method in element['method'] for method in high_risk_methods):
            risk_level += 1
        
        # 检查内容长度，如果内容很长，风险更高
        if 'context' in element and len(element['context']) > 100:
            risk_level += 1
        
        # 检查是否包含链接
        if 'context' in element and ('href=' in element['context'] or 'src=' in element['context']):
            risk_level += 2
        
        return risk_level
    
    def _detect_suspicious_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑注释
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑注释检测结果
        """
        results = []
        
        comments = extract_comments(content)
        
        # 可疑注释模式
        suspicious_comment_patterns = {
            'hidden_content': re.compile(r'<!--(?:(?!-->)[\s\S])*?(?:password|secret|hidden|private|admin)(?:(?!-->)[\s\S])*?-->'),
            'encoded_content': re.compile(r'<!--(?:(?!-->)[\s\S])*?(?:base64|hex|escape|decodeURI)(?:(?!-->)[\s\S])*?-->'),
            'conditional_comments': re.compile(r'<!--\[(?:(?!\]-->)\S\s)*\]>'),
            'large_comment': re.compile(r'<!--(?:(?!-->)[\s\S]){500,}-->')
        }
        
        for c in comments:
            text = c['content'] if isinstance(c, dict) else (c if isinstance(c, str) else '')
            if not text:
                continue
                
            for pattern_name, pattern in suspicious_comment_patterns.items():
                if pattern.search(text):
                    # 计算风险等级
                    risk_level = self._get_comment_risk_level(pattern_name)
                    
                    result = {
                        'type': 'suspicious_comment',
                        'file_path': file_path,
                        'pattern': pattern_name,
                        'comment': text[:200] + ('...' if len(text) > 200 else ''),
                        'risk_level': risk_level,
                        'description': self._get_comment_description(pattern_name),
                        'context': get_context(content, content.find(text), content.find(text) + len(text), 50)
                    }
                    results.append(result)
        
        # 检测注释中的链接
        link_pattern = re.compile(r'href=["\'](https?://[^"\']+)')
        for c in comments:
            text = c['content'] if isinstance(c, dict) else (c if isinstance(c, str) else '')
            if not text:
                continue
            for match in link_pattern.finditer(text):
                url = match.group(1)
                result = {
                    'type': 'suspicious_url',
                    'file_path': file_path,
                    'url': url,
                    'risk_level': 3,
                    'reason': '链接位于HTML注释中',
                    'context': text[:200] + ('...' if len(text) > 200 else '')
                }
                results.append(result)
        
        return results
    
    def _get_comment_risk_level(self, pattern_name: str) -> int:
        """
        获取注释模式的风险等级
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            风险等级
        """
        risk_levels = {
            'hidden_content': 3,
            'encoded_content': 3,
            'conditional_comments': 1,
            'large_comment': 2
        }
        
        return risk_levels.get(pattern_name, 1)
    
    def _get_comment_description(self, pattern_name: str) -> str:
        """
        获取注释模式的描述
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            描述文本
        """
        descriptions = {
            'hidden_content': '包含敏感信息的注释',
            'encoded_content': '包含编码内容的注释',
            'conditional_comments': '条件注释',
            'large_comment': '大型注释'
        }
        
        return descriptions.get(pattern_name, pattern_name)
    
    def _detect_suspicious_meta(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测HTML中的可疑Meta标签
        
        Args:
            file_path: 文件路径或URL
            content: HTML内容
            
        Returns:
            可疑Meta标签检测结果
        """
        results = []
        
        meta_tags = extract_meta_tags(content)
        
        # 检测可疑的refresh或redirect Meta标签
        for meta in meta_tags:
            http_equiv = meta.get('http-equiv', '').lower()
            content_attr = meta.get('content', '').lower()
            
            if http_equiv in ['refresh', 'redirect'] and 'url=' in content_attr:
                # 提取URL
                url_match = re.search(r'url=(\S+)', content_attr)
                if url_match:
                    url = url_match.group(1)
                    result = {
                        'type': 'suspicious_url',
                        'file_path': file_path,
                        'url': url,
                        'risk_level': 3,
                        'reason': '通过Meta标签重定向',
                        'context': meta.get('raw', '')
                    }
                    results.append(result)
        
        # 检测包含可疑内容的Meta标签
        suspicious_meta_keywords = ['bot', 'spider', 'crawler', 'nofollow', 'noindex']
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content_attr = meta.get('content', '').lower()
            
            if name in ['robots', 'keywords', 'description']:
                for keyword in suspicious_meta_keywords:
                    if keyword in content_attr:
                        result = {
                            'type': 'suspicious_meta',
                            'file_path': file_path,
                            'meta_name': name,
                            'suspicious_keyword': keyword,
                            'risk_level': 1,
                            'description': f"包含可疑关键词'{keyword}'的Meta标签",
                            'context': meta.get('raw', '')
                        }
                        results.append(result)
        
        return results
        