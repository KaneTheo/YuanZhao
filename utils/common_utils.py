# -*- coding: utf-8 -*-

"""
通用工具模块
"""

import re
import time
import hashlib
import logging
import os
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger('YuanZhao.utils.common')

def calculate_file_hash(file_path: str, hash_type: str = 'md5') -> Optional[str]:
    """
    计算文件哈希值
    
    Args:
        file_path: 文件路径
        hash_type: 哈希算法类型 (md5, sha1, sha256)
    
    Returns:
        哈希值字符串
    """
    try:
        hash_func = getattr(hashlib, hash_type)
        hash_obj = hash_func()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # 64KB chunks
                if not data:
                    break
                hash_obj.update(data)
        
        return hash_obj.hexdigest()
        
    except Exception as e:
        logger.error(f"计算文件哈希失败: {file_path}, 错误: {str(e)}")
        return None

def calculate_string_hash(string: str, hash_type: str = 'md5') -> Optional[str]:
    """
    计算字符串哈希值
    
    Args:
        string: 输入字符串
        hash_type: 哈希算法类型
    
    Returns:
        哈希值字符串
    """
    try:
        hash_func = getattr(hashlib, hash_type)
        return hash_func(string.encode('utf-8')).hexdigest()
    except Exception as e:
        logger.error(f"计算字符串哈希失败: {str(e)}")
        return None

def clean_text(text: str) -> str:
    """
    清理文本，去除控制字符和多余空白
    
    Args:
        text: 输入文本
    
    Returns:
        清理后的文本
    """
    try:
        # 移除控制字符，保留换行和制表符
        text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
        # 清理多余空白
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    except Exception as e:
        logger.error(f"清理文本失败: {str(e)}")
        return text

def extract_text_between(text: str, start_marker: str, end_marker: str) -> List[str]:
    """
    提取两个标记之间的文本
    
    Args:
        text: 原始文本
        start_marker: 开始标记
        end_marker: 结束标记
    
    Returns:
        提取的文本列表
    """
    try:
        pattern = re.compile(re.escape(start_marker) + '(.*?)' + re.escape(end_marker), re.DOTALL)
        return pattern.findall(text)
    except Exception as e:
        logger.error(f"提取文本失败: {str(e)}")
        return []

def detect_encoding(text: str) -> Optional[str]:
    """
    检测文本编码（传入为 str 时返回默认编码）
    """
    try:
        # 对已解码的 str 返回 utf-8，避免误导性“探测”
        return 'utf-8'
    except Exception as e:
        logger.error(f"检测编码失败: {str(e)}")
        return None

def safe_decode(bytes_data: bytes, default_encoding: str = 'utf-8') -> str:
    """
    安全解码字节数据
    
    Args:
        bytes_data: 字节数据
        default_encoding: 默认编码
    
    Returns:
        解码后的字符串
    """
    try:
        # 尝试多种编码
        encodings = [default_encoding, 'gbk', 'gb2312', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                return bytes_data.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # 如果都失败，使用replace模式
        return bytes_data.decode(default_encoding, errors='replace')
        
    except Exception as e:
        logger.error(f"安全解码失败: {str(e)}")
        return str(bytes_data)

def format_size(size_bytes: int) -> str:
    """
    格式化文件大小
    
    Args:
        size_bytes: 字节大小
    
    Returns:
        格式化的大小字符串
    """
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    except Exception as e:
        logger.error(f"格式化大小失败: {str(e)}")
        return f"{size_bytes} B"

def format_time(seconds: float) -> str:
    """
    格式化时间
    
    Args:
        seconds: 秒数
    
    Returns:
        格式化的时间字符串
    """
    try:
        if seconds < 1:
            return f"{seconds * 1000:.2f} ms"
        elif seconds < 60:
            return f"{seconds:.2f} s"
        elif seconds < 3600:
            minutes, seconds = divmod(seconds, 60)
            return f"{int(minutes)} m {seconds:.2f} s"
        else:
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{int(hours)} h {int(minutes)} m {seconds:.2f} s"
    except Exception as e:
        logger.error(f"格式化时间失败: {str(e)}")
        return f"{seconds} s"

def get_file_extension(file_path: str) -> str:
    """
    获取文件扩展名
    
    Args:
        file_path: 文件路径
    
    Returns:
        扩展名（小写）
    """
    try:
        _, ext = os.path.splitext(file_path.lower())
        return ext
    except Exception as e:
        logger.error(f"获取文件扩展名失败: {str(e)}")
        return ''

def validate_ip_address(ip: str) -> bool:
    """
    验证IP地址格式
    
    Args:
        ip: IP地址字符串
    
    Returns:
        是否为有效IP地址
    """
    try:
        # IPv4地址验证
        pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        return bool(pattern.match(ip))
    except Exception as e:
        logger.error(f"验证IP地址失败: {str(e)}")
        return False

def count_occurrences(text: str, keyword: str, case_sensitive: bool = False) -> int:
    """
    统计关键字出现次数
    
    Args:
        text: 文本内容
        keyword: 关键字
        case_sensitive: 是否区分大小写
    
    Returns:
        出现次数
    """
    try:
        if not case_sensitive:
            text = text.lower()
            keyword = keyword.lower()
        
        return text.count(keyword)
    except Exception as e:
        logger.error(f"统计关键字失败: {str(e)}")
        return 0

def is_valid_email(email: str) -> bool:
    """
    验证邮箱格式
    
    Args:
        email: 邮箱地址
    
    Returns:
        是否为有效邮箱
    """
    try:
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(email))
    except Exception as e:
        logger.error(f"验证邮箱失败: {str(e)}")
        return False

def sanitize_filename(filename: str) -> str:
    """
    清理文件名，移除特殊字符
    
    Args:
        filename: 原始文件名
    
    Returns:
        清理后的文件名
    """
    try:
        # 移除或替换特殊字符
        sanitized = re.sub(r'[\\/:*?"<>|]', '_', filename)
        # 移除控制字符
        sanitized = ''.join(char for char in sanitized if char.isprintable() or char.isspace())
        # 限制长度
        max_length = 200
        if len(sanitized) > max_length:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:max_length - len(ext)] + ext
        return sanitized.strip() or 'unnamed'
    except Exception as e:
        logger.error(f"清理文件名失败: {str(e)}")
        return 'unnamed'

def merge_dicts(dict1: Dict, dict2: Dict, deep: bool = True) -> Dict:
    """
    合并两个字典
    
    Args:
        dict1: 第一个字典
        dict2: 第二个字典
        deep: 是否深度合并
    
    Returns:
        合并后的字典
    """
    try:
        result = dict1.copy()
        
        if deep:
            for key, value in dict2.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dicts(result[key], value, deep=True)
                else:
                    result[key] = value
        else:
            result.update(dict2)
        
        return result
    except Exception as e:
        logger.error(f"合并字典失败: {str(e)}")
        return dict1

def remove_duplicates_preserve_order(items: List) -> List:
    """
    移除列表中的重复项，保留原始顺序
    
    Args:
        items: 输入列表
    
    Returns:
        去重后的列表
    """
    try:
        seen = set()
        return [item for item in items if not (item in seen or seen.add(item))]
    except Exception as e:
        logger.error(f"去重失败: {str(e)}")
        return items

def truncate_text(text: str, max_length: int, suffix: str = '...') -> str:
    """
    截断文本
    
    Args:
        text: 输入文本
        max_length: 最大长度
        suffix: 后缀
    
    Returns:
        截断后的文本
    """
    try:
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix
    except Exception as e:
        logger.error(f"截断文本失败: {str(e)}")
        return text

def retry(func, max_retries: int = 3, delay: float = 1.0, exceptions: tuple = (Exception,)) -> Any:
    """
    重试装饰器
    
    Args:
        func: 要重试的函数
        max_retries: 最大重试次数
        delay: 重试间隔（秒）
        exceptions: 捕获的异常类型
    
    Returns:
        函数执行结果
    """
    def wrapper(*args, **kwargs):
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                last_exception = e
                if attempt < max_retries - 1:
                    logger.warning(f"尝试 {attempt + 1}/{max_retries} 失败: {str(e)}, {delay}秒后重试...")
                    time.sleep(delay)
        
        logger.error(f"所有尝试都失败了: {str(last_exception)}")
        raise last_exception
    
    return wrapper

# 移除末尾的导入语句

# 兼容性函数，为了支持html_detector.py中的导入
def extract_text_between_markers(text: str, start_marker: str, end_marker: str) -> List[str]:
    """
    提取两个标记之间的文本（extract_text_between的别名）
    
    Args:
        text: 原始文本
        start_marker: 开始标记
        end_marker: 结束标记
    
    Returns:
        提取的文本列表
    """
    return extract_text_between(text, start_marker, end_marker)

def get_context(text: str, position: int, context_length: int = 50) -> str:
    """
    获取文本中指定位置的上下文
    
    Args:
        text: 原始文本
        position: 目标位置
        context_length: 上下文长度
    
    Returns:
        包含上下文的文本
    """
    try:
        # 计算上下文的起始和结束位置
        context_start = max(0, position - context_length)
        context_end = min(len(text), position + context_length)
        
        # 提取上下文
        context = text[context_start:context_end]
        
        # 添加省略号
        prefix = '...' if context_start > 0 else ''
        suffix = '...' if context_end < len(text) else ''
        
        return f"{prefix}{context}{suffix}"
    except Exception as e:
        logger.error(f"获取上下文失败: {str(e)}")
        return text

def calculate_entropy(text: str) -> float:
    """
    计算文本的熵值
    
    Args:
        text: 输入文本
    
    Returns:
        熵值
    """
    try:
        import math
        
        # 计算字符频率
        frequency = {}
        for char in text:
            if char in frequency:
                frequency[char] += 1
            else:
                frequency[char] = 1
        
        # 计算熵
        entropy = 0.0
        total_chars = len(text)
        
        for count in frequency.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        
        return entropy
    except Exception as e:
        logger.error(f"计算熵值失败: {str(e)}")
        return 0.0
        
