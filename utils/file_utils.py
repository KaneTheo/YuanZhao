# -*- coding: utf-8 -*-

"""
文件处理工具模块
"""

import os
import logging
import chardet
from typing import List

logger = logging.getLogger('YuanZhao.utils.file')

def read_file(file_path: str, max_size: int = 10 * 1024 * 1024) -> str:
    """
    读取文件内容，自动检测编码
    
    Args:
        file_path: 文件路径
        max_size: 最大文件大小（默认10MB）
    
    Returns:
        文件内容
    """
    try:
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            logger.warning(f"文件过大，将读取前{max_size/1024/1024:.1f}MB: {file_path}")
            
        # 检测文件编码
        with open(file_path, 'rb') as f:
            raw_data = f.read(min(file_size, 10000))
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
        
        # 读取文件内容
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            content = f.read(max_size)
        
        return content
        
    except Exception as e:
        logger.error(f"读取文件失败: {file_path}, 错误: {str(e)}")
        return ''

def get_files_to_scan(directory: str, extensions: List[str]) -> List[str]:
    """
    递归获取目录中所有指定扩展名的文件
    
    Args:
        directory: 目录路径
        extensions: 需要扫描的文件扩展名列表
    
    Returns:
        文件路径列表
    """
    files_to_scan = []
    
    try:
        for root, dirs, files in os.walk(directory):
            # 过滤掉隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # 过滤掉隐藏文件
                if file.startswith('.'):
                    continue
                
                # 检查文件扩展名
                _, ext = os.path.splitext(file.lower())
                if ext in extensions:
                    file_path = os.path.join(root, file)
                    files_to_scan.append(file_path)
        
        logger.info(f"找到 {len(files_to_scan)} 个需要扫描的文件")
        
    except Exception as e:
        logger.error(f"获取文件列表失败: {str(e)}")
    
    return files_to_scan

def is_binary_file(file_path: str) -> bool:
    """
    检查文件是否为二进制文件
    
    Args:
        file_path: 文件路径
    
    Returns:
        是否为二进制文件
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            
            # 检查是否包含null字节
            if b'\x00' in chunk:
                return True
            
            # 检查非文本字符的比例
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            
            # 如果超过30%的字符是非文本字符，则认为是二进制文件
            return non_text / len(chunk) > 0.3
            
    except Exception as e:
        logger.error(f"检查文件类型失败: {file_path}, 错误: {str(e)}")
        return False

def get_file_info(file_path: str) -> dict:
    """
    获取文件信息
    
    Args:
        file_path: 文件路径
    
    Returns:
        文件信息字典
    """
    try:
        stat_info = os.stat(file_path)
        
        info = {
            'path': file_path,
            'size': stat_info.st_size,
            'created_time': stat_info.st_ctime,
            'modified_time': stat_info.st_mtime,
            'is_binary': is_binary_file(file_path)
        }
        
        return info
        
    except Exception as e:
        logger.error(f"获取文件信息失败: {file_path}, 错误: {str(e)}")
        return {}

def ensure_directory(directory: str):
    """
    确保目录存在，如果不存在则创建
    
    Args:
        directory: 目录路径
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"创建目录: {directory}")
    except Exception as e:
        logger.error(f"创建目录失败: {directory}, 错误: {str(e)}")
        raise

def get_relative_path(file_path: str, base_directory: str) -> str:
    """
    获取文件相对于基础目录的路径
    
    Args:
        file_path: 文件路径
        base_directory: 基础目录
    
    Returns:
        相对路径
    """
    try:
        return os.path.relpath(file_path, base_directory)
    except Exception as e:
        logger.error(f"获取相对路径失败: {str(e)}")
        return file_path

def filter_files_by_size(files: List[str], min_size: int = 0, max_size: int = None) -> List[str]:
    """
    根据文件大小过滤文件列表
    
    Args:
        files: 文件路径列表
        min_size: 最小文件大小（字节）
        max_size: 最大文件大小（字节）
    
    Returns:
        过滤后的文件列表
    """
    filtered_files = []
    
    for file_path in files:
        try:
            file_size = os.path.getsize(file_path)
            
            if file_size < min_size:
                continue
            
            if max_size is not None and file_size > max_size:
                continue
            
            filtered_files.append(file_path)
            
        except Exception as e:
            logger.warning(f"获取文件大小失败: {file_path}, 错误: {str(e)}")
    
    return filtered_files

def _match_exclude(path: str, exclude_patterns: List[str]) -> bool:
    try:
        import fnmatch
        for pattern in exclude_patterns or []:
            if fnmatch.fnmatch(path, pattern) or (pattern.endswith('/') and path.replace('\\','/').startswith(pattern.rstrip('/'))):
                return True
    except Exception:
        pass
    return False

# 兼容性函数，为了支持scanner.py中的导入（扩展签名）
def get_file_list(directory: str, recursive: bool = True, depth: int = 1, extensions: List[str] = None, exclude: List[str] = None) -> List[str]:
    """
    获取目录中的文件列表，支持递归、深度限制与排除模式
    
    Args:
        directory: 目录路径
        recursive: 是否递归
        depth: 递归深度（包含根层级）
        extensions: 需要扫描的文件扩展名列表
        exclude: 排除的文件或目录通配符列表
    Returns:
        文件路径列表
    """
    results: List[str] = []
    try:
        extensions = [ext.lower() for ext in (extensions or [])]
        base_depth = directory.rstrip('\\/').count(os.sep)
        for root, dirs, files in os.walk(directory):
            # 处理深度
            current_depth = root.rstrip('\\/').count(os.sep) - base_depth
            if not recursive or current_depth >= depth:
                dirs[:] = []
            # 排除目录
            if exclude:
                dirs[:] = [d for d in dirs if not _match_exclude(os.path.join(root, d), exclude)]
            for file in files:
                path = os.path.join(root, file)
                if exclude and _match_exclude(path, exclude):
                    continue
                if file.startswith('.'):
                    continue
                _, ext = os.path.splitext(file.lower())
                if not extensions or ext in extensions:
                    results.append(path)
        logger.info(f"找到 {len(results)} 个需要扫描的文件")
    except Exception as e:
        logger.error(f"获取文件列表失败: {str(e)}")
    return results
    
