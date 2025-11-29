# -*- coding: utf-8 -*-

"""
CSS检测器模块
"""

import re
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict

from utils.css_utils import (
    extract_css_urls,
    extract_import_rules,
    extract_selectors,
    extract_css_properties,
    detect_hidden_elements,
    detect_suspicious_selectors,
    remove_css_comments as css_remove_comments,
    extract_css_comments as css_extract_comments,
    analyze_css_complexity,
    find_duplicate_rules
)
from utils.common_utils import (
    get_context,
    clean_text
)
from utils.network_utils import (
    is_external_link
)

class CSSDetector:
    """
    CSS代码检测器，用于检测CSS中的隐藏元素、可疑规则和恶意链接
    """
    
    def __init__(self, config):
        """
        初始化CSS检测器
        
        Args:
            config: 扫描配置对象
        """
        self.config = config
        self.logger = config.logger
        
        # 隐藏元素的CSS属性模式
        self.hidden_element_properties = {
            'display': ['none', 'list-item', 'table-caption'],
            'visibility': ['hidden', 'collapse'],
            'opacity': ['0', '0.0', '0.00'],
            'position': {
                'absolute': {
                    'left': ['-9999px', '-999px', '-1000px'],
                    'top': ['-9999px', '-999px', '-1000px'],
                    'right': ['-9999px', '-999px', '-1000px'],
                    'bottom': ['-9999px', '-999px', '-1000px']
                }
            },
            'clip': ['rect(0, 0, 0, 0)'],
            'clip-path': ['circle(0)', 'polygon(0 0)'],
            'z-index': ['-9999', '-999', '-1000'],
            'height': ['0', '0px', '0%'],
            'width': ['0', '0px', '0%'],
            'overflow': ['hidden'],
            'text-indent': ['-9999px', '-999px', '-1000px'],
            'transform': ['translateX(-9999px)', 'translateY(-9999px)']
        }
        
        # 可疑的CSS选择器模式
        self.suspicious_selectors = {
            'attribute_selectors': re.compile(r'\[[^\]]+=[^\]]*(?:javascript:|data:)[^\]]*\]'),
            'class_name_obfuscation': re.compile(r'\.[a-zA-Z0-9_$]{15,}'),
            'id_name_obfuscation': re.compile(r'#\w{15,}'),
            'unusual_combinators': re.compile(r'\s*\+\s*\*\s*~\s*'),
            'excessive_pseudo_classes': re.compile(r':(?:after|before|hover|active|focus|visited|first-child|last-child|nth-child\(\d+\)){4,}'),
            'universal_wildcard_chain': re.compile(r'\*\s*\*\s*\*'),
            'negative_padding': re.compile(r'padding[^:]*:[^;]*-(\d+)px')
        }
        
        # 可疑的CSS属性值
        self.suspicious_properties = {
            'background-image': [
                re.compile(r'url\(\s*["\']?(?:data:|javascript:)', re.IGNORECASE),
                re.compile(r'url\(\s*["\']?https?://[^\)]+\)', re.IGNORECASE)
            ],
            'content': [
                re.compile(r':after\s*\{[^\}]*content\s*:\s*["\'](?:javascript:|data:)', re.IGNORECASE),
                re.compile(r':before\s*\{[^\}]*content\s*:\s*["\'](?:javascript:|data:)', re.IGNORECASE)
            ],
            'filter': [
                re.compile(r'filter\s*:\s*blur\(\s*\d+px\s*\)'),
                re.compile(r'filter\s*:\s*opacity\(\s*0\s*\)')
            ],
            'counter-reset': [
                re.compile(r'counter-reset\s*:\s*\w+\s+\d{10,}')
            ]
        }
        
        # 可能用于隐藏内容的特殊字符
        self.suspicious_characters = {
            'zero-width': [r'\u200B', r'\u200C', r'\u200D', r'\u2060'],
            'whitespace': [r'\u00A0', r'\u1680', r'\u2000', r'\u2001', r'\u2002', r'\u2003', 
                          r'\u2004', r'\u2005', r'\u2006', r'\u2007', r'\u2008', r'\u2009', 
                          r'\u200A', r'\u2028', r'\u2029', r'\u202F', r'\u205F', r'\u3000']
        }
    
    def detect(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测CSS代码中的可疑内容
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            
        Returns:
            检测结果列表
        """
        results = []
        
        try:
            # 预处理CSS内容
            clean_content = clean_text(content)
            
            # 1. 检测隐藏元素
            hidden_element_results = self._detect_hidden_elements(file_path, content, clean_content)
            results.extend(hidden_element_results)
            
            # 2. 检测可疑选择器
            selector_results = self._detect_suspicious_selectors(file_path, content, clean_content)
            results.extend(selector_results)
            
            # 3. 检测可疑属性和值
            property_results = self._detect_suspicious_properties(file_path, content, clean_content)
            results.extend(property_results)
            
            # 4. 检测可疑URL
            url_results = self._detect_suspicious_urls(file_path, content, clean_content)
            results.extend(url_results)
            
            # 5. 检测@Import规则
            import_results = self._detect_import_rules(file_path, content, clean_content)
            results.extend(import_results)
            
            # 6. 检测可疑注释
            comment_results = self._detect_suspicious_comments(file_path, content)
            results.extend(comment_results)
            
            # 7. 检测混淆特征
            obfuscation_results = self._detect_obfuscation(file_path, content, clean_content)
            results.extend(obfuscation_results)
            
            # 8. 代码复杂度分析
            complexity_results = self._analyze_complexity(file_path, content, clean_content)
            results.extend(complexity_results)
            
        except Exception as e:
            self.logger.error(f"CSS检测过程中发生错误: {str(e)}", exc_info=True)
        
        return results
    
    def _detect_hidden_elements(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测CSS中的隐藏元素
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            隐藏元素检测结果
        """
        results = []
        
        hidden_elements = detect_hidden_elements(content)
        
        for element_info in hidden_elements:
            t = (element_info.get('type', '') or '').lower()
            if t in ['display: none', 'visibility: hidden']:
                continue
            risk_level = 3
            result = {
                'type': 'hidden_element',
                'file_path': file_path,
                'selector': element_info.get('selector', ''),
                'techniques': [element_info.get('type', '')],
                'risk_level': risk_level,
                'description': f"发现隐藏元素: {element_info.get('type', '')}",
                'context': element_info.get('css', '')
            }
            results.append(result)
        
        # 额外检测position:absolute结合负坐标的隐藏方式
        pos_pattern = re.compile(r'(\.[a-zA-Z0-9_-]+|#[a-zA-Z0-9_-]+)[^\{]*\{[^\}]*position\s*:\s*absolute[^\}]*([left|top|right|bottom])\s*:\s*-(\d+)(px|%)[^\}]*\}', re.DOTALL | re.IGNORECASE)
        matches = list(pos_pattern.finditer(content))
        
        for match in matches:
            selector = match.group(1)
            property_name = match.group(2)
            value = match.group(3)
            unit = match.group(4)
            
            # 获取上下文
            context = get_context(content, match.start(), match.end(), 100)
            
            # 坐标值越大，风险越高
            value_num = int(value)
            if value_num > 9999:
                risk_level = 4
            elif value_num > 999:
                risk_level = 3
            else:
                risk_level = 2
            
            result = {
                'type': 'hidden_element',
                'file_path': file_path,
                'selector': selector,
                'techniques': [f'position:absolute with negative {property_name}'],
                'risk_level': risk_level,
                'description': f"使用绝对定位和负坐标隐藏元素 ({property_name}: -{value}{unit})",
                'context': context
            }
            results.append(result)
        
        return results
    
    def _detect_suspicious_selectors(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测可疑的CSS选择器
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            可疑选择器检测结果
        """
        results = []
        
        # 使用css_utils中的函数检测可疑选择器
        suspicious_selectors = detect_suspicious_selectors(content)
        
        for selector_info in suspicious_selectors:
            st = selector_info.get('type', '')
            sel = selector_info.get('selector', '')
            rl = 2
            if st in ['long_random_class','long_random_id']:
                tokens = re.findall(r'\.([A-Za-z0-9_-]+)|#([A-Za-z0-9_-]+)', sel)
                lengths = [len(t[0] or t[1]) for t in tokens if (t[0] or t[1])]
                max_len = max(lengths) if lengths else 0
                if max_len >= 15:
                    rl = 3
            if rl < 3:
                continue
            result = {
                'type': 'suspicious_selector',
                'file_path': file_path,
                'selector': sel,
                'reason': '可疑选择器',
                'risk_level': rl,
                'description': '检测到可疑CSS选择器',
                'context': ''
            }
            results.append(result)
        
        # 检测特定的可疑选择器模式
        for pattern_name, pattern in self.suspicious_selectors.items():
            matches = list(pattern.finditer(content))
            if matches:
                for match in matches:
                    # 确定风险等级
                    risk_level = self._get_pattern_risk_level(pattern_name)
                    
                    # 获取上下文
                    context = get_context(content, match.start(), match.end(), 100)
                    
                    result = {
                        'type': 'suspicious_selector_pattern',
                        'file_path': file_path,
                        'pattern': pattern_name,
                        'matched_content': match.group(0),
                        'risk_level': risk_level,
                        'description': f"检测到{self._get_pattern_description(pattern_name)}",
                        'context': context
                    }
                    results.append(result)
        
        return results
    
    def _detect_suspicious_properties(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测可疑的CSS属性和值
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            可疑属性检测结果
        """
        results = []
        
        # 使用css_utils中的函数提取属性
        properties = extract_css_properties(content)
        
        # 检查每个属性是否包含可疑值
        for prop_info in properties:
            prop_name = prop_info.get('property', '').lower()
            prop_value = prop_info.get('value', '').lower()
            selector = prop_info.get('selector', '')
            context = prop_info.get('context', '')
            
            # 检查是否在可疑属性列表中
            if prop_name in self.suspicious_properties:
                for pattern in self.suspicious_properties[prop_name]:
                    if pattern.search(prop_value):
                        risk_level = 3
                        if 'javascript:' in prop_value:
                            risk_level = 5
                        elif 'data:' in prop_value:
                            risk_level = 4
                        elif 'http' in prop_value:
                            if prop_name == 'background-image':
                                m = re.search(r'url\(\s*["\']?([^"\')]+)', prop_value)
                                link = m.group(1).lower() if m else ''
                                ext = ''
                                try:
                                    path = link.split('?', 1)[0].split('#', 1)[0]
                                    ext = path.rsplit('.', 1)[-1]
                                except Exception:
                                    ext = ''
                                img_exts = {'png','jpg','jpeg','gif','svg','webp','ico','bmp'}
                                tlds_suspicious = (link.endswith('.tk') or link.endswith('.ga') or link.endswith('.gq') or link.endswith('.ml') or link.endswith('.cf'))
                                if ext in img_exts and not tlds_suspicious:
                                    continue
                                if tlds_suspicious:
                                    risk_level = 4
                            else:
                                risk_level = 3
                        result = {
                            'type': 'suspicious_property',
                            'file_path': file_path,
                            'selector': selector,
                            'property': prop_name,
                            'value': prop_value,
                            'risk_level': risk_level,
                            'description': f"检测到可疑的{prop_name}属性值",
                            'context': context
                        }
                        results.append(result)
                        break
            
            # 检查是否包含特殊字符
            for char_type, char_patterns in self.suspicious_characters.items():
                for char_pattern in char_patterns:
                    if char_pattern in prop_value:
                        result = {
                            'type': 'suspicious_property',
                            'file_path': file_path,
                            'selector': selector,
                            'property': prop_name,
                            'value': prop_value,
                            'risk_level': 3,
                            'description': f"检测到{self._get_pattern_description(char_type)}字符",
                            'context': context
                        }
                        results.append(result)
                        break
        
        return results
    
    def _detect_suspicious_urls(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测CSS中的可疑URL
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            可疑URL检测结果
        """
        results = []
        
        # 使用css_utils中的函数提取CSS URL
        css_urls = extract_css_urls(content)
        
        for url_info in css_urls:
            url = url_info.get('url', '')
            context = url_info.get('context', '')
            property_name = url_info.get('property', '')
            
            # 检测是否为可疑URL
            risk_level = 2
            reasons = []
            
            if url.startswith('javascript:'):
                risk_level = 5
                reasons.append('JavaScript协议')
            elif url.startswith('data:'):
                risk_level = 4
                # 检查data URL长度
                data_content = url[5:]
                if len(data_content) > 500:
                    risk_level = 5
                    reasons.append('过长的Data URL')
                else:
                    reasons.append('Data URL')
            elif is_external_link(url):
                lower = url.lower()
                ext = ''
                try:
                    path = lower.split('?', 1)[0].split('#', 1)[0]
                    ext = path.rsplit('.', 1)[-1]
                except Exception:
                    ext = ''
                img_exts = {'png','jpg','jpeg','gif','svg','webp','ico','bmp'}
                tlds_suspicious = (lower.endswith('.tk') or lower.endswith('.ga') or lower.endswith('.gq') or lower.endswith('.ml') or lower.endswith('.cf'))
                if property_name in ['background-image','cursor','filter'] and (ext not in img_exts or tlds_suspicious):
                    risk_level = 3
                    reasons.append('外部链接')
                    if tlds_suspicious:
                        risk_level = 4
                        reasons.append('可疑TLD')
            
            if risk_level >= 3:
                result = {
                    'type': 'suspicious_css_url',
                    'file_path': file_path,
                    'url': url,
                    'property': property_name,
                    'risk_level': risk_level,
                    'reason': ', '.join(reasons),
                    'description': f"在CSS中发现可疑URL ({', '.join(reasons)})",
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _detect_import_rules(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测CSS中的@Import规则
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            @Import规则检测结果
        """
        results = []
        
        # 使用css_utils中的函数提取@import规则
        import_rules = extract_import_rules(content)
        
        for import_info in import_rules:
            import_url = import_info.get('url', '')
            context = import_info.get('context', '')
            
            # 检测是否为外部导入
            risk_level = 2
            reasons = []
            
            if is_external_link(import_url):
                risk_level = 3
                reasons.append('外部CSS导入')
                lower = import_url.lower()
                if lower.endswith('.tk') or lower.endswith('.ga') or lower.endswith('.gq') or lower.endswith('.ml') or lower.endswith('.cf'):
                    risk_level = 4
                    reasons.append('可疑TLD')
                if any(p in lower for p in ['cdn.', 'static.', 'assets.', 'fonts.googleapis.com']):
                    risk_level = max(2, risk_level - 1)
            
            if risk_level >= 3:
                result = {
                    'type': 'suspicious_import',
                    'file_path': file_path,
                    'url': import_url,
                    'risk_level': risk_level,
                    'reason': ', '.join(reasons),
                    'description': f"检测到可疑的@import规则 ({', '.join(reasons)})",
                    'context': context
                }
                results.append(result)
        
        # 检查@import嵌套层级
        import_count = content.lower().count('@import')
        if import_count > 10:
            result = {
                'type': 'excessive_imports',
                'file_path': file_path,
                'import_count': import_count,
                'risk_level': 3,
                'description': f"CSS文件包含过多的@import规则 ({import_count}个)",
                'context': content[:200] + ('...' if len(content) > 200 else '')
            }
            results.append(result)
        
        return results
    
    def _detect_suspicious_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测CSS中的可疑注释
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            
        Returns:
            可疑注释检测结果
        """
        results = []
        
        # 使用css_utils中的函数提取注释
        comments = css_extract_comments(content)
        
        # 可疑注释关键词
        suspicious_keywords = ['hidden', 'stealth', 'cloaking', 'obfuscate', 'invisible',
                             'seo', 'spam', 'keywords', 'backlink', 'redirect',
                             'hack', 'exploit', 'malware', 'phish']
        
        for c in comments:
            text = c.get('content', '')
            comment_lower = text.lower()
            
            # 检查是否包含可疑关键词
            for keyword in suspicious_keywords:
                if keyword in comment_lower:
                    result = {
                        'type': 'suspicious_comment',
                        'file_path': file_path,
                        'keyword': keyword,
                        'risk_level': 3,
                        'description': f"CSS注释中包含可疑关键词: {keyword}",
                        'context': text[:200] + ('...' if len(text) > 200 else '')
                    }
                    results.append(result)
                    break
            
            # 检查注释中是否包含大量关键词堆积
            words = comment_lower.split()
            unique_words = set(words)
            if len(words) > 20 and len(unique_words) / len(words) < 0.3:
                result = {
                    'type': 'suspicious_comment',
                    'file_path': file_path,
                    'risk_level': 3,
                    'description': "CSS注释中包含大量重复词汇，可能是关键词堆砌",
                    'context': text[:200] + ('...' if len(text) > 200 else '')
                }
                results.append(result)
        
        return results
    
    def _detect_obfuscation(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测CSS混淆特征
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            混淆特征检测结果
        """
        results = []
        
        # 检测异常长的类名或ID
        long_selector_pattern = re.compile(r'(\.[a-zA-Z0-9_]{20,}|#[a-zA-Z0-9_]{20,})')
        long_selectors = list(long_selector_pattern.finditer(content))
        
        if long_selectors:
            # 统计长选择器数量
            long_selector_count = len(long_selectors)
            
            # 根据数量确定风险等级
            if long_selector_count >= 10:
                risk_level = 4
            elif long_selector_count >= 5:
                risk_level = 3
            else:
                risk_level = 2
            
            # 获取第一个匹配的上下文
            first_match = long_selectors[0]
            context = get_context(content, first_match.start(), first_match.end(), 100)
            
            result = {
                'type': 'css_obfuscation',
                'file_path': file_path,
                'long_selector_count': long_selector_count,
                'risk_level': risk_level,
                'description': f"检测到{long_selector_count}个异常长的选择器名称，可能是混淆特征",
                'context': context
            }
            results.append(result)
        
        # 检测十六进制颜色堆砌
        hex_color_pattern = re.compile(r'#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}')
        hex_colors = list(hex_color_pattern.finditer(content))
        
        if len(hex_colors) > 50:
            # 检查是否有重复的颜色值
            color_counts = defaultdict(int)
            for match in hex_colors:
                color_counts[match.group(0)] += 1
            
            # 计算重复率
            unique_colors = len(color_counts)
            if unique_colors / len(hex_colors) < 0.5:
                result = {
                    'type': 'css_obfuscation',
                    'file_path': file_path,
                    'color_count': len(hex_colors),
                    'unique_colors': unique_colors,
                    'risk_level': 3,
                    'description': f"存在大量重复的十六进制颜色值 ({len(hex_colors)}个，{unique_colors}个唯一)，可能是混淆特征",
                    'context': content[:200] + ('...' if len(content) > 200 else '')
                }
                results.append(result)
        
        # 检测特殊字符
        special_char_pattern = re.compile(r'[\\\u0000-\u001F\u007F-\u009F]')
        special_chars = list(special_char_pattern.finditer(content))
        
        if len(special_chars) > 10:
            result = {
                'type': 'css_obfuscation',
                'file_path': file_path,
                'special_char_count': len(special_chars),
                'risk_level': 3,
                'description': f"检测到{len(special_chars)}个控制字符或特殊字符，可能是混淆特征",
                'context': content[:200] + ('...' if len(content) > 200 else '')
            }
            results.append(result)
        
        return results
    
    def _analyze_complexity(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        分析CSS代码复杂度
        
        Args:
            file_path: 文件路径
            content: CSS代码内容
            clean_content: 清理后的CSS内容
            
        Returns:
            代码复杂度分析结果
        """
        results = []
        
        # 使用css_utils中的函数分析复杂度
        complexity_info = analyze_css_complexity(content)
        
        # 检查选择器复杂度
        if complexity_info.get('selector_count', 0) > 200:
            risk_level = 3
            if complexity_info.get('selector_count', 0) > 800:
                risk_level = 4
            
            result = {
                'type': 'css_complexity',
                'file_path': file_path,
                'selector_complexity': complexity_info.get('selector_count', 0),
                'risk_level': risk_level,
                'description': f"CSS选择器复杂度较高 ({complexity_info.get('selector_count', 0)})，可能影响性能或包含混淆",
                'context': content[:200] + ('...' if len(content) > 200 else '')
            }
            results.append(result)
        
        # 检查规则数量
        if complexity_info.get('rule_count', 0) > 500:
            risk_level = 2
            if complexity_info.get('rule_count', 0) > 1000:
                risk_level = 3
            
            result = {
                'type': 'css_complexity',
                'file_path': file_path,
                'rule_count': complexity_info.get('rule_count', 0),
                'risk_level': risk_level,
                'description': f"CSS文件包含大量规则 ({complexity_info['rule_count']}个)，可能包含冗余或混淆",
                'context': content[:200] + ('...' if len(content) > 200 else '')
            }
            results.append(result)
        
        # 检测重复规则
        duplicate_rules = find_duplicate_rules(content)
        dup_count = len(duplicate_rules) if isinstance(duplicate_rules, list) else 0
        if dup_count > 10:
            sample = ''
            if isinstance(duplicate_rules, list) and duplicate_rules:
                sample = duplicate_rules[0].get('css_body', '')
            result = {
                'type': 'css_duplication',
                'file_path': file_path,
                'duplicate_count': dup_count,
                'risk_level': 2,
                'description': f"CSS文件包含{dup_count}个重复规则",
                'context': sample[:200] + ('...' if len(sample) > 200 else '')
            }
            results.append(result)
        
        return results
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """
        获取模式的描述
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            描述文本
        """
        descriptions = {
            # 选择器模式描述
            'attribute_selectors': '属性选择器中的JavaScript或Data URL',
            'class_name_obfuscation': '异常长的类名',
            'id_name_obfuscation': '异常长的ID名',
            'unusual_combinators': '不常见的选择器组合',
            'excessive_pseudo_classes': '过多的伪类组合',
            'universal_wildcard_chain': '过多的通用选择器',
            'negative_padding': '负内边距',
            
            # 特殊字符描述
            'zero-width': '零宽字符',
            'whitespace': '不常见空白字符'
        }
        
        return descriptions.get(pattern_name, pattern_name)
    
    def _get_pattern_risk_level(self, pattern_name: str) -> int:
        """
        获取模式的风险等级
        
        Args:
            pattern_name: 模式名称
            
        Returns:
            风险等级
        """
        risk_levels = {
            'attribute_selectors': 4,
            'class_name_obfuscation': 2,
            'id_name_obfuscation': 2,
            'unusual_combinators': 2,
            'excessive_pseudo_classes': 2,
            'universal_wildcard_chain': 1,
            'negative_padding': 2,
            'zero-width': 3,
            'whitespace': 2
        }
        
        return risk_levels.get(pattern_name, 2)
        
