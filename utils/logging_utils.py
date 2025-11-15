# -*- coding: utf-8 -*-

"""
日志处理工具模块
"""

import os
import logging
import sys
from datetime import datetime

class Logger:
    """
    自定义日志类
    """
    def __init__(self, name='YuanZhao', log_dir=None, level=logging.INFO, use_console=True):
        """
        初始化日志记录器
        
        Args:
            name (str): 日志名称
            log_dir (str): 日志文件目录
            level (int): 日志级别
            use_console (bool): 是否输出到控制台
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 控制台输出
        if use_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # 文件输出
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = os.path.join(log_dir, f'YuanZhao_{timestamp}.log')
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message):
        """记录调试信息"""
        self.logger.debug(message)
    
    def info(self, message):
        """记录普通信息"""
        self.logger.info(message)
    
    def warning(self, message):
        """记录警告信息"""
        self.logger.warning(message)
    
    def error(self, message, exc_info=False):
        """记录错误信息"""
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message, exc_info=False):
        """记录严重错误信息"""
        self.logger.critical(message, exc_info=exc_info)

def setup_logging(log_dir=None, level=logging.INFO):
    """
    全局日志配置
    
    Args:
        log_dir (str): 日志文件目录
        level (int): 日志级别
        
    Returns:
        Logger: 日志记录器实例
    """
    return Logger('YuanZhao', log_dir, level).logger

def log_exception(logger, exception, message="发生异常"):
    """
    记录异常信息
    
    Args:
        logger: 日志记录器
        exception: 异常对象
        message (str): 错误消息
    """
    logger.error(f"{message}: {str(exception)}", exc_info=True)

def log_progress(logger, current, total, message="处理进度"):
    """
    记录进度信息
    
    Args:
        logger: 日志记录器
        current (int): 当前进度
        total (int): 总进度
        message (str): 进度消息
    """
    if total > 0:
        percentage = (current / total) * 100
        logger.info(f"{message}: {current}/{total} ({percentage:.1f}%)")

def log_scan_result(logger, file_path, issues):
    """
    记录扫描结果
    
    Args:
        logger: 日志记录器
        file_path (str): 文件路径
        issues (list): 发现的问题列表
    """
    if issues:
        logger.warning(f"文件 {file_path} 发现 {len(issues)} 个问题")
        import logging as _logging
        if logger.level <= _logging.DEBUG:
            for issue in issues:
                logger.warning(f"  - {issue}")
        else:
            # 聚合重复项，仅输出前若干项
            counts = {}
            for issue in issues:
                counts[issue] = counts.get(issue, 0) + 1
            shown = 0
            for text, cnt in counts.items():
                logger.warning(f"  - {text} x{cnt}")
                shown += 1
                if shown >= 8:
                    break
            if len(counts) > shown:
                logger.warning(f"  ... 还有 {len(counts) - shown} 项未展示（非verbose模式）")
    else:
        logger.debug(f"文件 {file_path} 未发现问题")

def log_keyword_match(logger, file_path, keyword, category, weight, context):
    """
    记录关键字匹配信息
    
    Args:
        logger: 日志记录器
        file_path (str): 文件路径
        keyword (str): 匹配的关键字
        category (str): 关键字类别
        weight (int): 风险权重
        context (str): 上下文信息
    """
    logger.warning(
        f"关键字匹配 - 文件: {file_path}, "
        f"关键字: {keyword}, 类别: {category}, 风险权重: {weight}\n"
        f"上下文: {context}"
    )

def log_suspicious_url(logger, file_path, url, risk_level, context):
    """
    记录可疑URL信息
    
    Args:
        logger: 日志记录器
        file_path (str): 文件路径
        url (str): 可疑URL
        risk_level (str): 风险等级
        context (str): 上下文信息
    """
    logger.warning(
        f"可疑URL - 文件: {file_path}, "
        f"URL: {url}, 风险等级: {risk_level}\n"
        f"上下文: {context}"
    )

def log_hidden_technique(logger, file_path, technique, risk_level, context):
    """
    记录隐藏技术信息
    
    Args:
        logger: 日志记录器
        file_path (str): 文件路径
        technique (str): 隐藏技术
        risk_level (str): 风险等级
        context (str): 上下文信息
    """
    logger.warning(
        f"隐藏技术 - 文件: {file_path}, "
        f"技术: {technique}, 风险等级: {risk_level}\n"
        f"上下文: {context}"
    )

def log_file_skipped(logger, file_path, reason):
    """
    记录跳过的文件信息
    
    Args:
        logger: 日志记录器
        file_path (str): 文件路径
        reason (str): 跳过原因
    """
    logger.debug(f"跳过文件 {file_path}: {reason}")

def log_config(logger, config_dict):
    """
    记录配置信息
    
    Args:
        logger: 日志记录器
        config_dict (dict): 配置字典
    """
    logger.info("扫描配置:")
    for key, value in config_dict.items():
        logger.info(f"  {key}: {value}")

def log_summary(logger, total_files, scanned_files, issues_found, scan_time):
    """
    记录扫描总结信息
    
    Args:
        logger: 日志记录器
        total_files (int): 文件总数
        scanned_files (int): 已扫描文件数
        issues_found (int): 发现的问题数
        scan_time (float): 扫描耗时（秒）
    """
    logger.info("扫描总结:")
    logger.info(f"  总文件数: {total_files}")
    logger.info(f"  已扫描文件: {scanned_files}")
    logger.info(f"  发现问题: {issues_found}")
    logger.info(f"  扫描耗时: {scan_time:.2f} 秒")
    try:
        if scan_time > 0:
            logger.info(f"  平均速度: {scanned_files/scan_time:.2f} 文件/秒")
        else:
            logger.info("  平均速度: N/A (耗时为0)")
    except Exception:
        logger.info("  平均速度: N/A")
    
    # 根据问题数量给出警告级别
    if issues_found > 50:
        logger.critical(f"发现大量问题 ({issues_found})，建议立即检查")
    elif issues_found > 10:
        logger.error(f"发现较多问题 ({issues_found})，需要关注")
    elif issues_found > 0:
        logger.warning(f"发现少量问题 ({issues_found})，建议查看")
    else:
        logger.info("未发现明显问题")
        
