# -*- coding: utf-8 -*-

"""
CSS处理工具模块
"""

import re
import logging
from typing import List, Dict, Optional

logger = logging.getLogger('YuanZhao.utils.css')

def extract_css_urls(css_content: str) -> List[Dict[str, str]]:
    """
    提取CSS中的URL
    
    Args:
        css_content: CSS内容
    
    Returns:
        URL列表
    """
    urls = []
    
    try:
        # 匹配CSS中的url()函数
        url_pattern = re.compile(r'url\s*\(\s*(["\']?)([^"\'\)]+)\1\s*\)', re.IGNORECASE)
        matches = url_pattern.finditer(css_content)
        
        for match in matches:
            url = match.group(2)
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            # 获取上下文
            context_start = max(0, start_pos - 50)
            context_end = min(len(css_content), end_pos + 50)
            context = css_content[context_start:context_end]
            
            urls.append({
                'url': url,
                'original': match.group(0),
                'context': context,
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取CSS URL失败: {str(e)}")
    
    return urls

def extract_import_rules(css_content: str) -> List[Dict[str, str]]:
    """
    提取CSS中的@import规则
    
    Args:
        css_content: CSS内容
    
    Returns:
        @import规则列表
    """
    import_rules = []
    
    try:
        # 匹配@import规则
        import_pattern = re.compile(r'@import\s+(["\']?)([^"\';\n]+)\1\s*([^;\n]*)\s*;', re.IGNORECASE)
        matches = import_pattern.finditer(css_content)
        
        for match in matches:
            url = match.group(2)
            media = match.group(3)
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            import_rules.append({
                'url': url,
                'media': media,
                'original': match.group(0),
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取CSS @import规则失败: {str(e)}")
    
    return import_rules

def extract_selectors(css_content: str) -> List[Dict[str, str]]:
    """
    提取CSS选择器
    
    Args:
        css_content: CSS内容
    
    Returns:
        选择器列表
    """
    selectors = []
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 匹配CSS规则
        rule_pattern = re.compile(r'([^{]+)\s*{[^}]*}', re.DOTALL)
        rules = rule_pattern.finditer(css_content)
        
        for rule in rules:
            selector_text = rule.group(1).strip()
            
            # 分割多个选择器
            for selector in selector_text.split(','):
                selector = selector.strip()
                if selector:
                    selectors.append({
                        'selector': selector,
                        'position': (rule.start(1), rule.end(1))
                    })
    
    except Exception as e:
        logger.error(f"提取CSS选择器失败: {str(e)}")
    
    return selectors

def extract_css_properties(css_content: str) -> List[Dict[str, str]]:
    """
    提取CSS属性
    
    Args:
        css_content: CSS内容
    
    Returns:
        CSS属性列表
    """
    properties = []
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 匹配CSS规则体
        body_pattern = re.compile(r'\{([^}]*)\}', re.DOTALL)
        bodies = body_pattern.finditer(css_content)
        
        for body in bodies:
            body_content = body.group(1)
            body_start = body.start(1)
            
            # 匹配属性
            prop_pattern = re.compile(r'([^:;\s]+)\s*:\s*([^;]+);')
            props = prop_pattern.finditer(body_content)
            
            for prop in props:
                prop_name = prop.group(1).strip()
                prop_value = prop.group(2).strip()
                
                properties.append({
                    'property': prop_name,
                    'value': prop_value,
                    'position': (body_start + prop.start(1), body_start + prop.end(1))
                })
    
    except Exception as e:
        logger.error(f"提取CSS属性失败: {str(e)}")
    
    return properties

def detect_hidden_elements(css_content: str) -> List[Dict[str, str]]:
    """
    检测可能用于隐藏元素的CSS规则
    
    Args:
        css_content: CSS内容
    
    Returns:
        隐藏规则列表
    """
    hidden_rules = []
    
    # 隐藏元素的属性模式
    hiding_patterns = [
        (r'display\s*:\s*none', 'display: none'),
        (r'visibility\s*:\s*hidden', 'visibility: hidden'),
        (r'opacity\s*:\s*0', 'opacity: 0'),
        (r'position\s*:\s*absolute.*left\s*:\s*[-+]?\d+(?:\.\d+)?(?:px|em|%)\s*;.*top\s*:\s*[-+]?\d+(?:\.\d+)?(?:px|em|%)\s*;.*width\s*:\s*\d+px\s*;.*height\s*:\s*\d+px', 'absolute positioned tiny element'),
        (r'position\s*:\s*absolute.*left\s*:\s*[-+]?\d+(?:\.\d+)?(?:px|em|%)\s*;.*top\s*:\s*[-+]?\d+(?:\.\d+)?(?:px|em|%)', 'absolute positioned'),
        (r'overflow\s*:\s*hidden', 'overflow: hidden'),
        (r'clip\s*:\s*rect\(0\s*px\s*0\s*px\s*0\s*px\s*0\s*px\)', 'clip: rect'),
        (r'font-size\s*:\s*0(?:px)?', 'font-size: 0'),
        (r'line-height\s*:\s*0(?:px)?', 'line-height: 0'),
        (r'text-indent\s*:\s*[-+]?\d+(?:\.\d+)?(?:px|em|%)', 'text-indent'),
        (r'color\s*:\s*transparent', 'color: transparent'),
        (r'background-color\s*:\s*transparent', 'background-color: transparent'),
        (r'height\s*:\s*0(?:px)?', 'height: 0'),
        (r'width\s*:\s*0(?:px)?', 'width: 0'),
    ]
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 匹配CSS规则
        rule_pattern = re.compile(r'([^{]+)\s*{([^}]*)}', re.DOTALL)
        rules = rule_pattern.finditer(css_content)
        
        for rule in rules:
            selector = rule.group(1).strip()
            body = rule.group(2)
            start_pos = rule.start(0)
            end_pos = rule.end(0)
            
            # 检查每个隐藏模式
            for pattern_str, hiding_type in hiding_patterns:
                pattern = re.compile(pattern_str, re.DOTALL | re.IGNORECASE)
                
                if pattern.search(body):
                    hidden_rules.append({
                        'type': hiding_type,
                        'selector': selector,
                        'css': body.strip(),
                        'original_rule': rule.group(0),
                        'position': (start_pos, end_pos)
                    })
                    break  # 每个规则只记录一次
    
    except Exception as e:
        logger.error(f"检测隐藏元素失败: {str(e)}")
    
    return hidden_rules

def detect_suspicious_selectors(css_content: str) -> List[Dict[str, str]]:
    """
    检测可疑的CSS选择器
    
    Args:
        css_content: CSS内容
    Returns:
        可疑选择器列表
    """
    suspicious_selectors = []
    
    # 可疑选择器模式
    suspicious_patterns = [
        # 随机字符串类名或ID
        (r'\.(\w{8,})[^\w\-]', 'long_random_class'),
        (r'#(\w{8,})[^\w\-]', 'long_random_id'),
        # 连续数字类名或ID
        (r'\.(\d{4,})[^\w\-]', 'numeric_class'),
        (r'#(\d{4,})[^\w\-]', 'numeric_id'),
        # 特殊字符选择器
        (r'[\[\*\+\~\^\$\|]', 'complex_selector'),
    ]
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 匹配CSS规则
        rule_pattern = re.compile(r'([^{]+)\s*{[^}]*}', re.DOTALL)
        rules = rule_pattern.finditer(css_content)
        
        for rule in rules:
            selector_text = rule.group(1).strip()
            
            # 检查每个可疑模式
            for pattern_str, selector_type in suspicious_patterns:
                pattern = re.compile(pattern_str, re.DOTALL)
                
                if pattern.search(selector_text):
                    suspicious_selectors.append({
                        'type': selector_type,
                        'selector': selector_text,
                        'position': (rule.start(1), rule.end(1))
                    })
                    break  # 每个选择器只记录一次
    
    except Exception as e:
        logger.error(f"检测可疑选择器失败: {str(e)}")
    
    return suspicious_selectors

def remove_css_comments(css_content: str) -> str:
    """
    移除CSS注释
    
    Args:
        css_content: CSS内容
    
    Returns:
        移除注释后的CSS内容
    """
    try:
        # 移除CSS注释
        css_content = re.sub(r'/\*.*?\*/', '', css_content, flags=re.DOTALL)
        return css_content
    except Exception as e:
        logger.error(f"移除CSS注释失败: {str(e)}")
        return css_content


def analyze_complexity(css_content: str) -> Dict[str, int]:
    """
    分析CSS复杂度
    
    Args:
        css_content: CSS内容
    
    Returns:
        包含复杂度指标的字典
    """
    complexity = {
        'rules_count': 0,
        'selectors_count': 0,
        'properties_count': 0,
        'imports_count': 0,
        'media_queries_count': 0
    }
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 计算规则数量
        rule_pattern = re.compile(r'\{[^}]*\}', re.DOTALL)
        complexity['rules_count'] = len(rule_pattern.findall(css_content))
        
        # 计算选择器数量
        selectors = extract_selectors(css_content)
        complexity['selectors_count'] = len(selectors)
        
        # 计算属性数量
        properties = extract_css_properties(css_content)
        complexity['properties_count'] = len(properties)
        
        # 计算导入规则数量
        imports = extract_import_rules(css_content)
        complexity['imports_count'] = len(imports)
        
        # 计算媒体查询数量
        media_query_pattern = re.compile(r'@media\s+[^\{]*\{[^}]*\}', re.DOTALL)
        complexity['media_queries_count'] = len(media_query_pattern.findall(css_content))
        
    except Exception as e:
        logger.error(f"分析CSS复杂度失败: {str(e)}")
    
    return complexity

def extract_css_comments(css_content: str) -> List[Dict[str, str]]:
    """
    提取CSS注释
    
    Args:
        css_content: CSS内容
    
    Returns:
        注释列表
    """
    comments = []
    
    try:
        comment_pattern = re.compile(r'/\*(.*?)\*/', re.DOTALL)
        matches = comment_pattern.finditer(css_content)
        
        for match in matches:
            comment_content = match.group(1).strip()
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            comments.append({
                'content': comment_content,
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取CSS注释失败: {str(e)}")
    
    return comments

def analyze_css_complexity(css_content: str) -> Dict[str, int]:
    """
    分析CSS复杂度
    
    Args:
        css_content: CSS内容
    
    Returns:
        复杂度指标
    """
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 计算规则数量
        rule_pattern = re.compile(r'[^\s\n\r]+\s*{[^}]*}', re.DOTALL)
        rules = rule_pattern.findall(css_content)
        rule_count = len(rules)
        
        # 计算选择器数量
        selectors = extract_selectors(css_content)
        selector_count = len(selectors)
        
        # 计算属性数量
        properties = extract_css_properties(css_content)
        property_count = len(properties)
        
        # 计算URL数量
        urls = extract_css_urls(css_content)
        url_count = len(urls)
        
        return {
            'rule_count': rule_count,
            'selector_count': selector_count,
            'property_count': property_count,
            'url_count': url_count,
            'file_size': len(css_content),
        }
        
    except Exception as e:
        logger.error(f"分析CSS复杂度失败: {str(e)}")
        return {}

def find_duplicate_rules(css_content: str) -> List[Dict[str, str]]:
    """
    查找重复的CSS规则
    
    Args:
        css_content: CSS内容
    
    Returns:
        重复规则列表
    """
    duplicate_rules = []
    seen_rules = {}
    
    try:
        # 移除注释
        css_content = remove_css_comments(css_content)
        
        # 匹配CSS规则
        rule_pattern = re.compile(r'([^{]+)\s*{([^}]*)}', re.DOTALL)
        rules = rule_pattern.finditer(css_content)
        
        for rule in rules:
            selector = rule.group(1).strip()
            body = rule.group(2).strip()
            
            # 使用body作为键，查找重复
            if body in seen_rules:
                duplicate_rules.append({
                    'selector': selector,
                    'duplicate_selector': seen_rules[body],
                    'css_body': body
                })
            else:
                seen_rules[body] = selector
                
    except Exception as e:
        logger.error(f"查找重复规则失败: {str(e)}")
    
    return duplicate_rules
    