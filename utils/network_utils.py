# -*- coding: utf-8 -*-

"""
网络处理工具模块
"""

import os
import re
import logging
import requests
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin

logger = logging.getLogger('YuanZhao.utils.network')

# 常见URL模式正则表达式
URL_PATTERNS = [
    # 标准URL
    re.compile(r'https?://[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 协议相对URL
    re.compile(r'//[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 仅域名
    re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?', re.IGNORECASE),
    # IP地址形式
    re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?::\d{1,5})?', re.IGNORECASE),
    # JavaScript伪协议
    re.compile(r'javascript:[^\s"\'>]+', re.IGNORECASE),
    # data URI
    re.compile(r'data:[^;]+;base64,[^\s"\'>]+', re.IGNORECASE),
    # 相对路径
    re.compile(r'/[^\s"\'>]+', re.IGNORECASE),
]


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """
    规范化URL
    
    Args:
        url: 原始URL
        base_url: 基础URL，用于解析相对路径
    
    Returns:
        规范化后的URL
    """
    try:
        # 处理双斜杠开头的URL：优先https，或继承base_url协议
        if url.startswith('//'):
            if base_url:
                base_parsed = urlparse(base_url)
                scheme = base_parsed.scheme or 'https'
                return f'{scheme}:{url}'
            return f'https:{url}'
        
        # 处理相对路径
        if base_url and not (url.startswith('http://') or url.startswith('https://')):
            return urljoin(base_url, url)
        
        # 对于纯域名，默认添加https://
        parsed = urlparse(url)
        if not parsed.scheme:
            return f'https://{url}'
        
        return url
        
    except Exception as e:
        logger.error(f"规范化URL失败: {url}, 错误: {str(e)}")
        return url

def get_url_type(url: str) -> str:
    """
    获取URL类型
    
    Args:
        url: URL字符串
    
    Returns:
        URL类型
    """
    if url.startswith('http://') or url.startswith('https://'):
        return 'absolute'
    elif url.startswith('//'):
        return 'protocol-relative'
    elif url.startswith('/'):
        return 'root-relative'
    else:
        return 'relative'

def check_url_reachability(url: str, timeout: int = 5, headers: Optional[Dict] = None) -> Tuple[bool, Optional[str]]:
    """
    检查URL是否可达
    
    Args:
        url: 要检查的URL
        timeout: 超时时间（秒）
        headers: 请求头
    
    Returns:
        (是否可达, 状态码或错误信息)
    """
    try:
        if headers is None:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        
        response = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)
        return response.status_code < 400, str(response.status_code)
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"URL检查失败: {url}, 错误: {str(e)}")
        return False, str(e)

def validate_url(url: str) -> bool:
    """
    验证URL格式是否有效
    
    Args:
        url: 要验证的URL
    
    Returns:
        URL是否有效
    """
    try:
        result = urlparse(url)
        
        # 对于绝对URL，需要有scheme和netloc
        if url.startswith('http://') or url.startswith('https://'):
            return all([result.scheme, result.netloc])
        
        # 对于相对URL，返回True
        return True
        
    except Exception as e:
        logger.error(f"URL验证失败: {url}, 错误: {str(e)}")
        return False

def get_domain(url: str) -> Optional[str]:
    """
    从URL中提取域名
    
    Args:
        url: URL字符串
    
    Returns:
        域名
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception as e:
        logger.error(f"提取域名失败: {url}, 错误: {str(e)}")
        return None

def is_external_link(url: str, base_domain: Optional[str] = None) -> bool:
    """
    判断是否为外部链接
    
    Args:
        url: 要检查的URL
        base_domain: 基础域名
    
    Returns:
        是否为外部链接
    """
    url_domain = get_domain(url)
    if not url_domain:
        return False
    if not base_domain:
        # 未提供基础域名时，尽量避免误报：只有显式协议的绝对链接视为外部
        return url.startswith(('http://', 'https://'))
    # 检查是否为同一域名或子域名
    # 同域或子域视为内部，其余为外部
    return not (url_domain == base_domain or url_domain.endswith(f'.{base_domain}'))

# 兼容性函数，用于判断字符串是否为URL
def is_url(text: str) -> bool:
    """
    判断字符串是否为URL
    
    Args:
        text: 要检查的文本
    
    Returns:
        是否为URL
    """
    try:
        # 首先检查是否为本地文件，如果是，直接返回False
        if os.path.isfile(text) or os.path.isdir(text):
            logger.debug(f"{text} 是本地文件或目录，不视为URL")
            return False
        
        # 检查是否以http://或https://开头
        if text.startswith(('http://', 'https://')):
            return True
        
        # 过滤典型代码符号，避免误判为URL
        if re.search(r"^(document|window|parent|this)\.[A-Za-z_]", text):
            return False
        if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*\(", text):
            if not re.search(r"https?://", text):
                # 若函数调用前缀，但内容中存在引号包裹的URL片段，视为URL
                quoted = re.findall(r'"([^"]+)"|\'([^\']+)' , text)
                candidates = [q[0] or q[1] for q in quoted]
                if not any((p.search(seg) for seg in URL_PATTERNS for seg in candidates)):
                    return False
        
        # 检查是否通过URL格式验证
        if not validate_url(text):
            return False
        
        # 检查是否匹配至少一个URL模式
        for pattern in URL_PATTERNS:
            if pattern.search(text):
                return True
        
        return False
    except Exception as e:
        logger.error(f"URL检查失败: {text}, 错误: {str(e)}")
        return False

# 兼容性函数，validate_url的别名
def is_valid_url(url: str) -> bool:
    """
    验证URL格式是否有效（validate_url的别名）
    
    Args:
        url: 要验证的URL
    
    Returns:
        URL是否有效
    """
    return validate_url(url)

def get_url_context(text: str, position: Tuple[int, int], context_length: int = 50) -> str:
    """
    获取URL在文本中的上下文
    
    Args:
        text: 原始文本
        position: URL在文本中的位置 (start, end)
        context_length: 上下文长度
    
    Returns:
        包含上下文的文本
    """
    start_pos, end_pos = position
    
    # 计算上下文的起始和结束位置
    context_start = max(0, start_pos - context_length)
    context_end = min(len(text), end_pos + context_length)
    
    # 提取上下文
    context = text[context_start:context_end]
    
    # 添加省略号
    prefix = '...' if context_start > 0 else ''
    suffix = '...' if context_end < len(text) else ''
    
    return f"{prefix}{context}{suffix}"

def build_request_session(proxy: Optional[str] = None, timeout: int = 10) -> requests.Session:
    """
    构建请求会话
    
    Args:
        proxy: 代理设置
        timeout: 超时时间
    
    Returns:
        请求会话对象
    """
    session = requests.Session()
    
    # 设置默认请求头
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    })
    
    # 设置代理
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        session.proxies.update(proxies)
        logger.info(f"设置代理: {proxy}")
    
    # 超时需在请求时传递
    
    return session

def fetch_url_content(url: str, session: Optional[requests.Session] = None, **kwargs) -> Optional[Tuple[str, dict]]:
    """
    获取URL内容或本地文件内容
    
    Args:
        url: 要获取的URL或本地文件路径
        session: 请求会话对象
        **kwargs: 其他请求参数
    
    Returns:
        元组 (内容字符串, 头部信息字典)，失败时返回None
    """
    try:
        # 检查是否为本地文件路径
        if not url.startswith(('http://', 'https://')):
            # 尝试作为本地文件读取
            if os.path.isfile(url):
                logger.info(f"读取本地文件: {url}")
                with open(url, 'r', encoding='utf-8') as f:
                    content = f.read()
                # 返回内容和模拟的头部信息
                return content, {'Content-Type': 'text/html'}
            else:
                logger.error(f"本地文件不存在: {url}")
                return None
        
        # 添加标准浏览器请求头以避免被反爬机制拦截
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # 合并默认请求头和传入的请求头
        headers = default_headers.copy()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # 增加重试机制
        timeout = kwargs.get('timeout', 10)
        if session:
            response = session.get(url, timeout=timeout, **kwargs)
        else:
            # 创建临时会话以设置重试策略
            temp_session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            temp_session.mount('http://', adapter)
            temp_session.mount('https://', adapter)
            response = temp_session.get(url, timeout=timeout, **kwargs)
        
        response.raise_for_status()
        
        # 尝试自动检测编码，并在失败时回退到原始字节解码
        enc = response.apparent_encoding or response.encoding or 'utf-8'
        try:
            response.encoding = enc
            text = response.text
        except Exception:
            try:
                text = response.content.decode(enc, errors='replace')
            except Exception:
                text = response.content.decode('utf-8', errors='replace')
        
        return text, dict(response.headers)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"获取URL内容失败: {url}, 错误: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"读取内容失败: {url}, 错误: {str(e)}")
        return None

# 兼容性函数，为了支持html_detector.py中的导入
def extract_domain(url: str) -> Optional[str]:
    """
    从URL中提取域名（get_domain的别名）
    
    Args:
        url: URL字符串
    
    Returns:
        域名
    """
    return get_domain(url)

def analyze_url_risk(url: str) -> Dict[str, Any]:
    """
    评估URL风险等级
    Returns: {risk_level: int, reason: str}
    """
    try:
        risk = 0
        reasons = []
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()
        # 协议风险
        if scheme == 'javascript':
            risk += 5
            reasons.append('JavaScript协议')
        elif scheme == 'data':
            risk += 4
            reasons.append('Data URI')
        elif scheme in ('http', 'https'):
            risk += 1
        # 端口风险
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            risk += 2
            reasons.append('非标准端口')
        # 可疑后缀与短链服务
        suspicious_tlds = ['pro', 'xyz', 'pw', 'top', 'loan', 'win', 'bid', 'online']
        short_link_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'adf.ly']
        if any(domain.endswith('.' + tld) for tld in suspicious_tlds):
            risk += 2
            reasons.append('高风险域名后缀')
        if any(domain.endswith(sl) or domain == sl for sl in short_link_domains):
            risk += 3
            reasons.append('短链接服务')
        # 路径随机性
        if re.search(r'/[a-zA-Z0-9]{8,}\.(?:js|php)$', parsed.path):
            risk += 1
            reasons.append('可疑随机路径')
        return {'risk_level': min(risk, 10), 'reason': ', '.join(reasons) or '普通URL'}
    except Exception as e:
        logger.error(f"URL风险评估失败: {url}, 错误: {str(e)}")
        return {'risk_level': 0, 'reason': '评估失败'}

def extract_urls(text: str, context_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    从文本中提取所有URL
    
    Args:
        text: 要提取URL的文本
    
    Returns:
        包含URL和上下文的字典列表
    """
    results = []
    urls_set = set()  # 用于去重
    
    # 增加URL模式匹配
    url_patterns = [
        re.compile(r'(https?://[\w._~:/?#[\]@!$&\'()*+,-;=]+)', re.IGNORECASE),
        re.compile(r'(/[-\w./?%&=]+)', re.IGNORECASE),
        re.compile(r'([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?)', re.IGNORECASE),
        re.compile(r'(javascript:[\w./?%&=;(),\'"`-]+)', re.IGNORECASE),
        re.compile(r'(data:[^;]+;base64,[^\s<>"]+)', re.IGNORECASE),
    ]
    
    logger.info(f"开始提取URL，文本长度: {len(text)}")
    
    for i, pattern in enumerate(url_patterns):
        matches = pattern.finditer(text)
        match_count = 0
        
        for match in matches:
            match_count += 1
            url = match.group(1)
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            
            # 清理URL
            url = url.strip('"\'')
            
            # 跳过空URL
            if not url or len(url) < 3:
                continue
            
            # 跳过纯数字或不包含有效字符的URL
            if re.match(r'^\d+$', url):
                continue
            
            # 去重
            if url not in urls_set:
                urls_set.add(url)
                results.append({
                    'url': url,
                    'context': context,
                    'position': (match.start(), match.end()),
                    'context_type': context_type or 'unknown'
                })
        
        logger.debug(f"模式 {i} 匹配到 {match_count} 个URL")
    
    logger.debug(f"共提取到 {len(results)} 个唯一URL")
    return results
EXTRA_PATTERNS = [
    # 扩展的HTTP/HTTPS URL
    re.compile(r'https?://[\w\-\.]+(?:\.[\w\-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+', re.IGNORECASE),
    # 没有协议的域名
    re.compile(r'\b[\w\-\.]+(?:\.[\w\-]+)+\b(?::\d{1,5})?/[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]*', re.IGNORECASE),
    # JavaScript伪协议
    re.compile(r'javascript:[^\s"\'>]+', re.IGNORECASE),
    # data URI
    re.compile(r'data:[^;]+;base64,[^\s"\'>]+', re.IGNORECASE),
    # 相对路径
    re.compile(r'\/[^\s"\'>]+', re.IGNORECASE),
]
# 模式去重：基于正则字符串与flags，避免重复匹配与性能开销
_unique_patterns = []
_seen = set()
for _pat in URL_PATTERNS:
    _key = (_pat.pattern, _pat.flags)
    if _key not in _seen:
        _seen.add(_key)
        _unique_patterns.append(_pat)
URL_PATTERNS = _unique_patterns
