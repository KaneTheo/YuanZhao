# -*- coding: utf-8 -*-

"""
JavaScript检测器模块
"""

import re
from typing import List, Dict, Any

from utils.js_utils import (
    extract_suspicious_patterns,
    extract_function_calls,
    detect_dynamic_urls,
    identify_obfuscated_code,
    detect_document_modifications,
    extract_variable_assignments,
    extract_comments as js_extract_comments,
    remove_comments as js_remove_comments
)
from utils.common_utils import (
    get_context,
    calculate_entropy,
    clean_text
)
from utils.network_utils import (
    extract_urls,
    is_external_link
)

class JSDetector:
    """
    JavaScript代码检测器，用于检测JS中的恶意代码和可疑行为
    """
    
    def __init__(self, config):
        """
        初始化JavaScript检测器
        
        Args:
            config: 扫描配置对象
        """
        self.config = config
        self.logger = config.logger
        
        # 高危JavaScript函数和方法
        self.high_risk_functions = {
            'eval': 5,
            'Function': 4,
            'setTimeout': 3,
            'setInterval': 3,
            'document.write': 4,
            'document.writeln': 4,
            'innerHTML': 4,
            'outerHTML': 4,
            'execScript': 5,
            'XMLHttpRequest': 3,
            'fetch': 3,
            'WebSocket': 3,
            'navigator.sendBeacon': 3,
            'window.open': 3,
            'unescape': 3,
            'escape': 3,
            'decodeURI': 2,
            'decodeURIComponent': 2,
            'document.createElement': 3,  # 提升DOM创建的风险等级
            'document.createElementNS': 3,
            'appendChild': 3,
            'insertBefore': 3
        }
        
        # 可疑的DOM操作
        self.suspicious_dom_operations = {
            'appendChild': 3,
            'insertBefore': 3,
            'replaceChild': 3,
            'createElement': 2,
            'createTextNode': 2,
            'createDocumentFragment': 2,
            'querySelector': 2,
            'querySelectorAll': 2,
            'getElementById': 2,
            'getElementsByClassName': 2,
            'getElementsByTagName': 2
        }
        
        # 混淆代码特征
        self.obfuscation_patterns = {
            'hex_encoding': re.compile(r'\\x[0-9a-fA-F]{2}'),
            'unicode_encoding': re.compile(r'\\u[0-9a-fA-F]{4}'),
            'string_concatenation': re.compile(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'),
            'array_manipulation': re.compile(r'\[.*\]\.join\s*\(\s*["\']'),
            'eval_with_arguments': re.compile(r'eval\s*\(\s*[a-zA-Z0-9_$\[\]]+\s*\+'),
            'reversed_string': re.compile(r'\.split\(\s*["\']\s*\)\s*\.reverse\(\)\s*\.join'),
            'base64_like': re.compile(r'[A-Za-z0-9+/=]{20,}'),
            'unusual_variable_names': re.compile(r'[a-zA-Z_$][a-zA-Z0-9_$]{15,}'),
            'suspicious_domain_pattern': re.compile(r'https?://[a-zA-Z0-9]{8,}\.(?:pro|xyz|pw|top|loan|win|bid|online)', re.IGNORECASE)
        }
        
        # 可疑的代码模式
        self.suspicious_patterns = {
            'self_executing': re.compile(r'(function\s*\(\s*\)\s*\{[^\}]*\}\s*\(\s*\))|\(([^\)]+)\)\(\)'),
            'conditional_eval': re.compile(r'if\s*\([^\)]*\)\s*\{[^\}]*eval\s*\('),
            'try_catch_eval': re.compile(r'try\s*\{[^\}]*eval\s*\([^\)]*\)[^\}]*\}\s*catch'),
            'hidden_eval': re.compile(r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*["\']eval["\'].*;.*\[.*\]\s*\('),
            'document_manipulation_with_eval': re.compile(r'document\.(body|documentElement|head)\.(appendChild|innerHTML)\s*=\s*eval\s*\('),
            'url_to_eval': re.compile(r'(document\.location|window\.location|location)\.(href|search|hash)\s*.*eval\s*\('),
            'cookie_manipulation': re.compile(r'document\.cookie'),
            'user_agent_check': re.compile(r'navigator\.userAgent'),
            'referrer_check': re.compile(r'document\.referrer')
        }
        
    def detect(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测JavaScript代码中的恶意内容
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            检测结果列表
        """
        results = []
        
        try:
            # 预处理代码，清理空白字符等
            clean_content = clean_text(content)
            
            # 1. 检测高危函数调用
            high_risk_results = self._detect_high_risk_functions(file_path, content, clean_content)
            results.extend(high_risk_results)
            
            # 2. 检测混淆代码
            obfuscation_results = self._detect_obfuscation(file_path, content, clean_content)
            results.extend(obfuscation_results)
            
            # 3. 检测可疑代码模式
            pattern_results = self._detect_suspicious_patterns(file_path, content)
            results.extend(pattern_results)
            
            # 4. 检测动态URL和网络请求
            url_results = self._detect_dynamic_urls(file_path, content)
            results.extend(url_results)
            
            # 5. 检测DOM修改操作
            dom_results = self._detect_dom_manipulations(file_path, content)
            results.extend(dom_results)
            
            # 6. 检测可疑注释
            comment_results = self._detect_suspicious_comments(file_path, content)
            results.extend(comment_results)
            
            # 7. 代码复杂度和熵分析
            complexity_results = self._analyze_code_complexity(file_path, content)
            results.extend(complexity_results)
            
        except Exception as e:
            self.logger.error(f"JavaScript检测过程中发生错误: {str(e)}", exc_info=True)
        
        return results
    
    def _detect_high_risk_functions(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测高危函数调用
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            clean_content: 清理后的代码内容
            
        Returns:
            高危函数检测结果
        """
        results = []
        
        for func_name in self.high_risk_functions.keys():
            calls = extract_function_calls(content, func_name)
            for func_call in calls:
                args_str = func_call.get('arguments', '')
                pos = func_call.get('position', (0, 0))
                risk_level = self.high_risk_functions[func_name]
                if any(pattern.search(args_str) for pattern in self.obfuscation_patterns.values()):
                    risk_level = min(5, risk_level + 1)
                context = get_context(content, pos[0], pos[1], 100)
                result = {
                    'type': 'high_risk_function',
                    'file_path': file_path,
                    'function_name': func_name,
                    'arguments': args_str,
                    'risk_level': risk_level,
                    'description': f"调用高危函数 {func_name}",
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _detect_obfuscation(self, file_path: str, content: str, clean_content: str) -> List[Dict[str, Any]]:
        """
        检测混淆代码
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            clean_content: 清理后的代码内容
            
        Returns:
            混淆代码检测结果
        """
        results = []
        
        # 使用js_utils中的函数识别混淆代码
        obfuscation_info = identify_obfuscated_code(content)
        
        if obfuscation_info['is_obfuscated']:
            # 基于混淆特征计算风险等级
            risk_level = 3 + len(obfuscation_info['detected_patterns'])
            risk_level = min(5, risk_level)
            
            result = {
                'type': 'obfuscated_code',
                'file_path': file_path,
                'risk_level': risk_level,
                'detected_patterns': obfuscation_info['detected_patterns'],
                'description': "代码疑似被混淆，可能隐藏恶意行为",
                'context': obfuscation_info.get('sample', '')[:200] + '...' if len(obfuscation_info.get('sample', '')) > 200 else obfuscation_info.get('sample', '')
            }
            results.append(result)
        
        # 额外检测特定混淆模式
        for pattern_name, pattern in self.obfuscation_patterns.items():
            matches = list(pattern.finditer(content))
            if matches:
                # 统计匹配次数
                match_count = len(matches)
                
                # 根据匹配次数确定风险等级
                if match_count >= 10:
                    risk_level = 4
                elif match_count >= 5:
                    risk_level = 3
                else:
                    risk_level = 2
                
                # 获取第一个匹配的上下文
                first_match = matches[0]
                context = get_context(content, first_match.start(), first_match.end(), 100)
                
                result = {
                    'type': 'obfuscation_pattern',
                    'file_path': file_path,
                    'pattern': pattern_name,
                    'match_count': match_count,
                    'risk_level': risk_level,
                    'description': f"检测到{self._get_pattern_description(pattern_name)}，匹配{match_count}次",
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _detect_suspicious_patterns(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测可疑代码模式
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            可疑代码模式检测结果
        """
        results = []
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = list(pattern.finditer(content))
            if matches:
                for match in matches:
                    # 确定风险等级
                    risk_level = self._get_pattern_risk_level(pattern_name)
                    
                    # 获取上下文
                    context = get_context(content, match.start(), match.end(), 100)
                    
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
        
        # 使用js_utils中的函数提取可疑模式
        suspicious_patterns = extract_suspicious_patterns(content)
        for pattern_info in suspicious_patterns:
            result = {
                'type': 'suspicious_pattern',
                'file_path': file_path,
                'pattern': pattern_info['type'],
                'matched_content': pattern_info['content'],
                'risk_level': pattern_info['risk_level'],
                'description': pattern_info['description'],
                'context': pattern_info.get('context', '')
            }
            results.append(result)
        
        return results
    
    def _detect_dynamic_urls(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测动态URL和网络请求
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            动态URL检测结果
        """
        results = []
        
        # 使用js_utils中的函数检测动态URL
        dynamic_urls = detect_dynamic_urls(content)
        
        for url_info in dynamic_urls:
            # 确定风险等级
            risk_level = url_info.get('risk_level', 3)
            
            # 分析URL构建方式
            if '+' in url_info['url'] or '[' in url_info['url']:
                risk_level = min(5, risk_level + 1)
            
            result = {
                'type': 'dynamic_url',
                'file_path': file_path,
                'url': url_info['url'],
                'risk_level': risk_level,
                'reason': url_info.get('reason', '动态构建的URL'),
                'context': url_info.get('context', '')
            }
            results.append(result)
        
        # 提取所有URL并检测可疑URL
        urls = extract_urls(content)
        for url_obj in urls:
            url = url_obj['url']
            context = url_obj['context']
            
            # 检测可疑URL
            if is_external_link(url):
                risk_level = 3
                reasons = []
                
                # 1. 检查URL是否匹配可疑域名模式
                if self.obfuscation_patterns['suspicious_domain_pattern'].search(url):
                    risk_level = 5
                    reasons.append('URL匹配可疑域名模式')
                
                # 2. 检查URL是否在可疑上下文中
                if any(keyword in context.lower() for keyword in ['eval', 'exec', 'decode', 'base64']):
                    risk_level = min(5, risk_level + 1)
                    reasons.append('URL在可疑上下文中')
                
                # 3. 检查URL域名是否使用了可疑后缀
                suspicious_suffixes = ['.pro', '.xyz', '.pw', '.top', '.loan', '.win', '.bid', '.online']
                for suffix in suspicious_suffixes:
                    if url.endswith(suffix):
                        risk_level = min(5, risk_level + 1)
                        reasons.append(f'使用了高风险域名后缀{suffix}')
                        break
                
                # 4. 检查URL路径是否包含随机字符串
                if re.search(r'/[a-zA-Z0-9]{8,}\.js$', url):
                    risk_level = min(5, risk_level + 1)
                    reasons.append('URL路径包含长随机字符串')
                
                # 如果有任何风险因素，添加结果
                if risk_level >= 3 or reasons:
                    result = {
                        'type': 'suspicious_url',
                        'file_path': file_path,
                        'url': url,
                        'risk_level': risk_level,
                        'reason': '; '.join(reasons) if reasons else '外部URL',
                        'context': context
                    }
                    results.append(result)
        
        return results
    
    def _detect_dom_manipulations(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测DOM修改操作
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            DOM操作检测结果
        """
        results = []
        
        # 使用js_utils中的函数检测文档修改
        modifications = detect_document_modifications(content)
        
        for mod_info in modifications:
            # 确定风险等级
            risk_level = mod_info.get('risk_level', 3)
            
            # 检查是否包含可疑内容
            target = mod_info.get('target', '')
            value = mod_info.get('value', '')
            
            if 'innerHTML' in target or 'outerHTML' in target:
                risk_level = min(5, risk_level + 1)
            
            if any(pattern.search(value) for pattern in self.obfuscation_patterns.values()):
                risk_level = min(5, risk_level + 1)
            
            result = {
                'type': 'dom_manipulation',
                'file_path': file_path,
                'target': target,
                'value': value[:200] + ('...' if len(value) > 200 else ''),
                'risk_level': risk_level,
                'description': mod_info.get('description', 'DOM修改操作'),
                'context': mod_info.get('context', '')
            }
            results.append(result)
        
        # 检测可疑的DOM操作函数
        for op_name, base_risk in self.suspicious_dom_operations.items():
            pattern = re.compile(r'\b(?:document|window|this)\b[^\n;]*?\b' + re.escape(op_name) + r'\s*\(')
            matches = list(pattern.finditer(content))
            
            for match in matches:
                # 获取上下文
                context = get_context(content, match.start(), match.end(), 100)
                
                # 检查是否与可疑内容组合使用
                risk_level = base_risk
                if any(keyword in context.lower() for keyword in ['eval', 'decode', 'base64', 'fromcharcode']):
                    risk_level = min(5, risk_level + 2)
                
                result = {
                    'type': 'dom_operation',
                    'file_path': file_path,
                    'operation': op_name,
                    'risk_level': risk_level,
                    'description': f"可疑的DOM操作: {op_name}",
                    'context': context
                }
                results.append(result)
        
        return results
    
    def _detect_suspicious_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        检测可疑注释
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            可疑注释检测结果
        """
        results = []
        
        # 使用js_utils中的函数提取注释
        comments = js_extract_comments(content)
        
        # 可疑注释关键词
        suspicious_keywords = ['hack', 'exploit', 'backdoor', 'trojan', 'malware', 'keylogger', 'cracker', 
                             'steal', 'inject', 'redirect', 'obfuscate', 'encrypt', 'decrypt', 'hidden',
                             'admin', 'password', 'credential', 'phish', 'spy', 'tracking']
        
        for comment in comments:
            comment_lower = comment.lower()
            
            # 检查是否包含可疑关键词
            for keyword in suspicious_keywords:
                if keyword in comment_lower:
                    result = {
                        'type': 'suspicious_comment',
                        'file_path': file_path,
                        'keyword': keyword,
                        'risk_level': 3,
                        'description': f"注释中包含可疑关键词: {keyword}",
                        'context': comment[:200] + ('...' if len(comment) > 200 else '')
                    }
                    results.append(result)
                    break
            
            # 检查注释中是否包含Base64编码内容
            base64_pattern = re.compile(r'[A-Za-z0-9+/=]{32,}')
            if base64_pattern.search(comment) and len(comment) > 50:
                result = {
                    'type': 'suspicious_comment',
                    'file_path': file_path,
                    'risk_level': 4,
                    'description': "注释中包含疑似Base64编码的长字符串",
                    'context': comment[:200] + ('...' if len(comment) > 200 else '')
                }
                results.append(result)
        
        return results
    
    def _analyze_code_complexity(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        分析代码复杂度和熵
        
        Args:
            file_path: 文件路径
            content: JavaScript代码内容
            
        Returns:
            代码复杂度分析结果
        """
        results = []
        
        # 移除注释后的代码用于熵计算
        code_without_comments = js_remove_comments(content)
        
        # 计算代码熵
        entropy = calculate_entropy(code_without_comments)
        
        # 如果熵值过高，可能是混淆代码
        if entropy > 4.5:
            result = {
                'type': 'code_complexity',
                'file_path': file_path,
                'entropy': round(entropy, 2),
                'risk_level': 4,
                'description': f"代码熵值过高 ({round(entropy, 2)})，疑似经过混淆",
                'context': code_without_comments[:200] + ('...' if len(code_without_comments) > 200 else '')
            }
            results.append(result)
        elif entropy > 3.8:
            result = {
                'type': 'code_complexity',
                'file_path': file_path,
                'entropy': round(entropy, 2),
                'risk_level': 2,
                'description': f"代码熵值较高 ({round(entropy, 2)})，可能包含复杂逻辑",
                'context': code_without_comments[:200] + ('...' if len(code_without_comments) > 200 else '')
            }
            results.append(result)
        
        # 分析变量命名模式
        var_pattern = re.compile(r'\bvar\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b|\blet\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b|\bconst\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\b')
        var_names = []
        
        for match in var_pattern.finditer(content):
            for group in match.groups():
                if group:
                    var_names.append(group)
        
        # 检查是否有大量的短变量名（可能是混淆特征）
        short_vars = [name for name in var_names if len(name) <= 2]
        if len(short_vars) > 30 and len(var_names) > 50:
            short_var_ratio = len(short_vars) / len(var_names)
            if short_var_ratio > 0.4:
                result = {
                    'type': 'code_complexity',
                    'file_path': file_path,
                    'short_var_count': len(short_vars),
                    'total_var_count': len(var_names),
                    'risk_level': 3,
                    'description': f"存在大量短变量名 ({len(short_vars)}/{len(var_names)})，可能是混淆特征",
                    'context': ', '.join(short_vars[:10]) + ('...' if len(short_vars) > 10 else '')
                }
                results.append(result)
        
        # 分析函数调用密度
        function_call_pattern = re.compile(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(')
        function_calls = len(list(function_call_pattern.finditer(content)))
        
        code_length = len(content)
        calls_per_1000 = (function_calls / code_length * 1000) if code_length > 0 else 0
        
        if calls_per_1000 > 50:
            result = {
                'type': 'code_complexity',
                'file_path': file_path,
                'function_call_density': round(calls_per_1000, 2),
                'risk_level': 2,
                'description': f"函数调用密度较高 ({round(calls_per_1000, 2)} 次/1000字符)，可能包含复杂逻辑",
                'context': content[:200] + ('...' if len(content) > 200 else '')
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
            # 混淆模式描述
            'hex_encoding': '十六进制编码',
            'unicode_encoding': 'Unicode编码',
            'string_concatenation': '字符串拼接',
            'array_manipulation': '数组操作混淆',
            'eval_with_arguments': '带参数的eval调用',
            'reversed_string': '反转字符串',
            'base64_like': '疑似Base64编码',
            'unusual_variable_names': '异常变量名',
            
            # 可疑模式描述
            'self_executing': '自执行函数',
            'conditional_eval': '条件eval调用',
            'try_catch_eval': 'try-catch中的eval',
            'hidden_eval': '隐藏的eval调用',
            'document_manipulation_with_eval': '使用eval操作DOM',
            'url_to_eval': '从URL提取数据执行eval',
            'cookie_manipulation': 'Cookie操作',
            'user_agent_check': 'User-Agent检查',
            'referrer_check': 'Referrer检查'
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
            'self_executing': 3,
            'conditional_eval': 4,
            'try_catch_eval': 4,
            'hidden_eval': 5,
            'document_manipulation_with_eval': 5,
            'url_to_eval': 5,
            'cookie_manipulation': 3,
            'user_agent_check': 1,
            'referrer_check': 1
        }
        
        return risk_levels.get(pattern_name, 2)
        
