# -*- coding: utf-8 -*-

"""
配置管理模块
"""

class Config:
    """扫描配置类"""
    
    def __init__(self):
        # 扫描目标配置
        self.target_type = None  # 'local_file', 'local_directory', 'internal_url', 'external_url'
        self.target = None
        self.crawl_depth = 1
        self.depth = self.crawl_depth  # 兼容属性
        
        # 扫描模式配置
        self.scan_mode = 'standard'  # 'fast', 'standard', 'deep'
        self.mode = self.scan_mode  # 兼容属性
        self.threads = 4
        self.timeout = 30
        self.internal_timeout = 60  # 内网URL超时时间（秒）
        self.external_timeout = 30  # 公网URL超时时间（秒）
        self.proxy = None
        self.exclude = []
        
        # 关键字配置
        self.keywords_file = None
        
        # 报告配置
        self.report_type = 'txt'
        self.report_file = None
        
        # 调试模式
        self.debug = False
        # 调试日志读取参数
        self.debug_log_wait_ms = 1500
        self.debug_log_checks = 3
        self.debug_log_interval_ms = 500
        
        # 日志器
        import logging
        self.logger = logging.getLogger('YuanZhao')
        
        # 无头浏览器配置
        self.use_headless_browser = False  # 是否启用无头浏览器
        self.headless_browser = 'chrome'  # 无头浏览器类型
        self.js_wait_time = 3  # JavaScript执行等待时间（秒）
        self.headless_timeout = 60  # 无头浏览器超时时间（秒）
        self.headless_auto_download = False  # 是否自动下载驱动
        self.headless_driver_path = None  # 本地驱动路径
        
        # 文件类型配置
        self.html_extensions = ['.html', '.htm', '.shtml', '.xhtml', '.php', '.asp', '.aspx', '.jsp']
        self.css_extensions = ['.css', '.less', '.scss', '.sass']
        self.js_extensions = ['.js', '.jsx', '.ts', '.tsx']
        self.image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp']
        
        # 扫描配置项
        self.scan_html = True
        self.scan_js = True
        self.scan_css = True
        self.scan_comments = True
        self.scan_meta = True
        self.scan_iframe = True
        self.scan_dom = True
        self.scan_encoding = True
        self.scan_steganography = True
        self.scan_special_hiding = True
        self.scan_keywords = True
        
        # 根据扫描模式调整配置
        self._set_mode_config()
        # 计算当前模式下需要扫描的扩展名
        self.file_extensions = self.get_file_extensions_to_scan()
    
    def _set_mode_config(self):
        """根据扫描模式设置相应的配置"""
        if self.scan_mode == 'fast':
            # 快速模式：只进行基础扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = False
            self.scan_dom = False
            self.scan_encoding = False
            self.scan_steganography = False
            self.scan_special_hiding = False
            self.scan_keywords = True
        
        elif self.scan_mode == 'standard':
            # 标准模式：进行大部分扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = True
            self.scan_dom = True
            self.scan_encoding = True
            self.scan_steganography = False
            self.scan_special_hiding = True
            self.scan_keywords = True
        
        elif self.scan_mode == 'deep':
            # 深度模式：进行所有扫描
            self.scan_html = True
            self.scan_js = True
            self.scan_css = True
            self.scan_comments = True
            self.scan_meta = True
            self.scan_iframe = True
            self.scan_dom = True
            self.scan_encoding = True
            self.scan_steganography = True
            self.scan_special_hiding = True
            self.scan_keywords = True
        # 同步更新扩展名列表
        self.file_extensions = self.get_file_extensions_to_scan()
    
    def update_mode(self, mode):
        """更新扫描模式"""
        self.scan_mode = mode
        self._set_mode_config()
    
    def get_file_extensions_to_scan(self):
        """获取需要扫描的文件扩展名列表"""
        extensions = []
        
        if self.scan_html:
            extensions.extend(self.html_extensions)
        
        if self.scan_js:
            extensions.extend(self.js_extensions)
        
        if self.scan_css:
            extensions.extend(self.css_extensions)
        
        return list(set(extensions))  # 去重
    
    def get_proxy_dict(self):
        """将代理字符串转换为requests使用的代理字典格式"""
        if not self.proxy:
            return None
        
        proxies = {
            'http': self.proxy,
            'https': self.proxy
        }
        return proxies
    
    def __str__(self):
        """返回配置的字符串表示"""
        return (
            f"Config(" 
            f"target_type={self.target_type}, "
            f"target={self.target}, "
            f"scan_mode={self.scan_mode}, "
            f"threads={self.threads}, "
            f"timeout={self.timeout}, "
            f"internal_timeout={self.internal_timeout}, "
            f"external_timeout={self.external_timeout}, "
            f"report_type={self.report_type}, "
            f"report_file={self.report_file})"
        )
    
    def get_config_dict(self):
        """返回配置的字典表示，用于日志记录"""
        return {
            'target_type': self.target_type,
            'target': self.target,
            'crawl_depth': self.crawl_depth,
            'scan_mode': self.scan_mode,
            'threads': self.threads,
            'timeout': self.timeout,
            'internal_timeout': self.internal_timeout,
            'external_timeout': self.external_timeout,
            'proxy': '***' if self.proxy else None,
            'keywords_file': self.keywords_file,
            'report_type': self.report_type,
            'report_file': self.report_file,
            'debug': self.debug
        }
        
