"""无头浏览器检测器模块

用于通过Chrome无头浏览器检测动态生成的暗链和隐藏内容。
支持检测JavaScript动态生成的内容、DOM操作、iframe内容等。
"""
import logging
from typing import List, Dict, Any
from core.config import Config

class HeadlessBrowserDetector:
    """无头浏览器检测器类"""
    
    def __init__(self, config: Config):
        """初始化无头浏览器检测器
        
        Args:
            config: 配置对象
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.driver = None
        self._initialize_driver()
    
    def _initialize_driver(self):
        """初始化Chrome无头浏览器驱动"""
        try:
            # 动态导入，避免在不使用时产生依赖问题
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            import os
            driver_path = getattr(self.config, 'headless_driver_path', None)
            binary_path = getattr(self.config, 'headless_binary', None)
            
            # 创建Chrome选项
            chrome_options = Options()
            if binary_path:
                chrome_options.binary_location = binary_path
            chrome_options.add_argument('--headless')  # 无头模式
            chrome_options.add_argument('--disable-gpu')  # 禁用GPU加速
            chrome_options.add_argument('--no-sandbox')  # 禁用沙箱
            chrome_options.add_argument('--disable-dev-shm-usage')  # 解决内存问题
            chrome_options.add_argument('--window-size=1920,1080')  # 设置窗口大小
            chrome_options.add_argument('--log-level=3')  # 减少日志输出
            
            # 选择驱动来源：优先本地路径；否则在允许时自动下载
            if driver_path and os.path.exists(driver_path):
                service = Service(driver_path)
            else:
                if getattr(self.config, 'headless_auto_download', False):
                    from webdriver_manager.chrome import ChromeDriverManager
                    service = Service(ChromeDriverManager().install())
                else:
                    self.logger.error("未提供本地驱动路径且未启用自动下载，跳过无头浏览器初始化")
                    return
            
            # 创建浏览器驱动
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # 设置超时时间
            self.driver.set_page_load_timeout(self.config.headless_timeout)
            self.driver.set_script_timeout(self.config.headless_timeout)
            
            self.logger.info("Chrome无头浏览器初始化成功")
            
        except ImportError as e:
            self.logger.error(f"缺少无头浏览器相关依赖: {str(e)}")
            self.logger.error("请安装依赖: pip install selenium webdriver-manager")
        except Exception as e:
            self.logger.error(f"无头浏览器初始化失败: {str(e)}")

    def close(self):
        """释放浏览器驱动资源"""
        try:
            if self.driver:
                self.driver.quit()
                self.driver = None
                self.logger.info("已释放无头浏览器驱动")
        except Exception as e:
            self.logger.error(f"释放无头浏览器驱动失败: {str(e)}")

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
    
    def detect(self, url: str, content: str = None) -> List[Dict[str, Any]]:
        """使用无头浏览器检测暗链
        
        Args:
            url: 要检测的URL
            content: 可选，页面内容（如果已获取）
            
        Returns:
            检测结果列表
        """
        results = []
        
        if not self.driver:
            self.logger.error("无头浏览器未初始化，跳过检测")
            return results
        
        try:
            from selenium.webdriver.support.ui import WebDriverWait
            # 加载页面
            self.logger.info(f"无头浏览器正在加载页面: {url}")
            self.driver.get(url)
            
            # 等待JavaScript执行完成
            try:
                WebDriverWait(self.driver, self.config.js_wait_time).until(
                    lambda d: d.execute_script("return document.readyState") in ("complete", "interactive")
                )
            except Exception:
                pass
            self.logger.info(f"等待页面加载/JS执行完成 (<= {self.config.js_wait_time}秒)")
            
            # 执行各项检测
            self.logger.info("开始执行动态链接检测")
            dynamic_links = self._detect_dynamic_links()
            results.extend(dynamic_links)
            
            self.logger.info("开始执行DOM操作检测")
            dom_operations = self._detect_dom_manipulations()
            results.extend(dom_operations)
            
            self.logger.info("开始执行iframe内容检测")
            iframe_content = self._detect_iframe_content()
            results.extend(iframe_content)
            
            self.logger.info("开始执行隐藏元素检测")
            hidden_elements = self._detect_hidden_elements()
            results.extend(hidden_elements)
            
            self.logger.info(f"无头浏览器检测完成，发现 {len(results)} 个可疑项")
            
        except Exception as e:
            self.logger.error(f"无头浏览器检测过程中出错: {str(e)}")
        
        return results
    
    def _detect_dynamic_links(self) -> List[Dict[str, Any]]:
        """检测动态生成的链接
        
        Returns:
            检测到的可疑链接列表
        """
        results = []
        
        try:
            from selenium.webdriver.common.by import By
            # 获取所有链接元素
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            self.logger.info(f"发现 {len(links)} 个链接元素")
            
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href:
                        # 分析链接风险（使用现有工具类）
                        from utils.network_utils import analyze_url_risk
                        risk_info = analyze_url_risk(href)
                        
                        if risk_info['risk_level'] > 0:
                            text = link.text.strip()[:100]  # 限制文本长度
                            results.append({
                                'type': 'suspicious_url',
                                'url': href,
                                'risk_level': risk_info['risk_level'],
                                'context': f"动态生成链接: {text}",
                                'detection_method': 'headless_browser',
                                'element': 'a',
                                'risk_reason': risk_info.get('reason', '未知风险')
                            })
                except Exception as e:
                    self.logger.error(f"分析动态链接时出错: {str(e)}")
        except Exception as e:
            self.logger.error(f"获取链接元素时出错: {str(e)}")
        
        return results
    
    def _detect_dom_manipulations(self) -> List[Dict[str, Any]]:
        """检测可疑的DOM操作
        
        Returns:
            检测到的可疑DOM操作列表
        """
        results = []
        
        # 注入JavaScript以检测可疑的DOM操作
        monitor_script = r"""
        (function() {
            const suspiciousPatterns = [];
            
            // 初始化正则表达式
            const eval_pattern = /eval[\s]*\(/;
            const doc_write_pattern = /document\.write[\s]*\(/;
            const innerhtml_pattern = /innerHTML[\s]*=/;
            const base64_pattern = /base64/i;
            const fromCharCode_pattern = /fromCharCode/;
            const escape_pattern = /escape[\s]*\(/;
            const unescape_pattern = /unescape[\s]*\(/;
            
            // 检测可疑的JavaScript代码模式
            const scriptElements = document.querySelectorAll('script');
            scriptElements.forEach(script => {
                if (script.textContent) {
                    const content = script.textContent;
                    if (eval_pattern.test(content) || 
                        doc_write_pattern.test(content) ||
                        innerhtml_pattern.test(content) ||
                        base64_pattern.test(content) ||
                        fromCharCode_pattern.test(content) ||
                        escape_pattern.test(content) ||
                        unescape_pattern.test(content)) {
                        suspiciousPatterns.push({
                            type: 'suspicious_script',
                            content: content.substring(0, 200) + '...',
                            lineCount: content.split('\n').length
                        });
                    }
                }
            });
            
            // 检测动态创建的元素
            const dynamicElements = [];
            document.querySelectorAll('*').forEach(element => {
                if (element.tagName === 'SCRIPT' && element.getAttribute('src') === null && 
                    element.textContent.length > 50) {
                    dynamicElements.push({tag: element.tagName, type: 'inline_script'});
                }
                if (element.tagName === 'IFRAME') {
                    dynamicElements.push({tag: element.tagName, src: element.getAttribute('src')});
                }
            });
            
            return {suspiciousPatterns, dynamicElements};
        })();
        """
        
        try:
            result = self.driver.execute_script(monitor_script)
            
            # 分析可疑脚本模式
            for pattern in result['suspiciousPatterns']:
                risk_level = 8  # 较高风险
                results.append({
                    'type': 'suspicious_dom_operation',
                    'technique': pattern['type'],
                    'risk_level': risk_level,
                    'context': f"检测到可疑脚本模式: {pattern['content']}",
                    'detection_method': 'headless_browser',
                    'risk_reason': '包含可疑JavaScript操作函数'
                })
            
            # 分析动态创建的元素
            for element in result['dynamicElements']:
                if element['tag'] == 'IFRAME' and element.get('src'):
                    from utils.network_utils import analyze_url_risk
                    risk_info = analyze_url_risk(element['src'])
                    if risk_info['risk_level'] > 0:
                        results.append({
                            'type': 'suspicious_iframe',
                            'url': element['src'],
                            'risk_level': risk_info['risk_level'],
                            'context': f"动态创建的iframe",
                            'detection_method': 'headless_browser',
                            'risk_reason': risk_info.get('reason', '可疑iframe')
                        })
        except Exception as e:
            self.logger.error(f"检测DOM操作时出错: {str(e)}")
        
        return results
    
    def _detect_iframe_content(self) -> List[Dict[str, Any]]:
        """检测iframe中的内容
        
        Returns:
            检测到的iframe中的可疑内容列表
        """
        results = []
        
        try:
            from selenium.webdriver.common.by import By
            # 获取所有iframe
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            self.logger.info(f"发现 {len(iframes)} 个iframe元素")
            
            for index, iframe in enumerate(iframes):
                try:
                    iframe_src = iframe.get_attribute('src')
                    self.logger.info(f"处理iframe {index + 1}/{len(iframes)}: {iframe_src or '无src属性'}")
                    
                    # 分析iframe的src属性
                    if iframe_src:
                        from utils.network_utils import analyze_url_risk
                        risk_info = analyze_url_risk(iframe_src)
                        
                        if risk_info['risk_level'] > 0:
                            results.append({
                                'type': 'suspicious_iframe',
                                'url': iframe_src,
                                'risk_level': risk_info['risk_level'],
                                'context': f"iframe中的可疑链接",
                                'detection_method': 'headless_browser',
                                'risk_reason': risk_info.get('reason', '可疑iframe源')
                            })
                    
                    # 尝试切换到iframe上下文分析内容
                    try:
                        self.driver.switch_to.frame(iframe)
                        
                        # 获取iframe中的链接
                        iframe_links = self.driver.find_elements(By.TAG_NAME, 'a')
                        for link in iframe_links:
                            href = link.get_attribute('href')
                            if href:
                                from utils.network_utils import analyze_url_risk
                                risk_info = analyze_url_risk(href)
                                
                                if risk_info['risk_level'] > 0:
                                    results.append({
                                        'type': 'suspicious_url',
                                        'url': href,
                                        'risk_level': risk_info['risk_level'],
                                        'context': f"iframe内部的可疑链接",
                                        'detection_method': 'headless_browser',
                                        'risk_reason': risk_info.get('reason', 'iframe内部链接风险')
                                    })
                    except Exception as iframe_e:
                        self.logger.error(f"分析iframe内容时出错: {str(iframe_e)}")
                    finally:
                        # 确保切回主文档
                        self.driver.switch_to.default_content()
                
                except Exception as e:
                    self.logger.error(f"处理iframe时出错: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"获取iframe元素时出错: {str(e)}")
        
        return results
    
    def _detect_hidden_elements(self) -> List[Dict[str, Any]]:
        """检测视觉上隐藏的元素
        
        Returns:
            检测到的隐藏元素列表
        """
        results = []
        
        # 注入JavaScript获取隐藏元素
        hidden_elements_script = """
        (function() {
            const hiddenElements = [];
            
            // 获取所有元素
            const allElements = document.querySelectorAll('*');
            
            allElements.forEach(element => {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                
                // 检查各种隐藏技术
                const isHidden = 
                    style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    style.opacity === '0' ||
                    rect.width <= 1 ||
                    rect.height <= 1 ||
                    parseInt(style.fontSize) <= 0 ||
                    element.offsetParent === null;
                
                // 检查绝对定位隐藏
                const isAbsPosHidden = 
                    style.position === 'absolute' &&
                    (parseInt(style.left) < -1000 || parseInt(style.top) < -1000 ||
                     parseInt(style.right) < -1000 || parseInt(style.bottom) < -1000);
                
                // 检查文本颜色与背景色相同
                const textColor = style.color;
                const bgColor = style.backgroundColor || style.background;
                const isSameColor = textColor === bgColor && textColor !== 'rgba(0, 0, 0, 0)';
                
                // 检查是否包含链接或文本
                const hasLinks = element.querySelector('a') !== null;
                const hasText = element.textContent.trim().length > 0;
                const hasContent = hasLinks || hasText;
                
                if ((isHidden || isAbsPosHidden || isSameColor) && hasContent) {
                    // 获取元素中的链接（如果有）
                    const links = [];
                    if (hasLinks) {
                        const linkElements = element.querySelectorAll('a');
                        linkElements.forEach(link => {
                            const href = link.getAttribute('href');
                            if (href) links.push(href);
                        });
                    }
                    
                    hiddenElements.push({
                        tagName: element.tagName,
                        id: element.id || '无ID',
                        classes: element.className || '无类名',
                        hiddenBy: isSameColor ? 'color_matching' : 
                                  isAbsPosHidden ? 'absolute_position' : 'visibility',
                        content: element.textContent.trim().substring(0, 200) + '...',
                        hasLinks: hasLinks,
                        links: links,
                        textColor: textColor,
                        bgColor: bgColor
                    });
                }
            });
            
            return hiddenElements;
        })();
        """
        
        try:
            hidden_elements = self.driver.execute_script(hidden_elements_script)
            self.logger.info(f"发现 {len(hidden_elements)} 个隐藏元素")
            
            for elem in hidden_elements:
                # 计算风险等级
                risk_level = 8 if elem['hasLinks'] else 6
                
                # 构建风险描述
                context = f"隐藏元素 ({elem['tagName']}): {elem['content']}"
                if elem['hasLinks']:
                    context += f" 包含 {len(elem['links'])} 个链接"
                
                result_item = {
                    'type': 'hidden_element',
                    'technique': elem['hiddenBy'],
                    'risk_level': risk_level,
                    'context': context,
                    'detection_method': 'headless_browser',
                    'risk_reason': '视觉上隐藏的元素可能包含暗链'
                }
                
                # 如果有链接，添加链接信息
                if elem['hasLinks'] and elem['links']:
                    result_item['hidden_links'] = elem['links']
                
                results.append(result_item)
                
                # 对于包含链接的隐藏元素，分别记录每个链接
                if elem['hasLinks'] and elem['links']:
                    for link in elem['links']:
                        from utils.network_utils import analyze_url_risk
                        risk_info = analyze_url_risk(link)
                        results.append({
                            'type': 'suspicious_url',
                            'url': link,
                            'risk_level': max(risk_level, risk_info['risk_level']),
                            'context': f"隐藏元素中的链接: {link}",
                            'detection_method': 'headless_browser',
                            'risk_reason': f"隐藏在{elem['hiddenBy']}类型的{elem['tagName']}元素中"
                        })
        
        except Exception as e:
            self.logger.error(f"检测隐藏元素时出错: {str(e)}")
        
        return results
    
    def close(self):
        """关闭无头浏览器驱动
        
        清理资源，避免内存泄漏
        """
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("无头浏览器已关闭")
            except Exception as e:
                self.logger.error(f"关闭无头浏览器时出错: {str(e)}")
            finally:
                self.driver = None
    
    def __del__(self):
        """析构函数，确保资源被释放"""
        self.close()
