# -*- coding: utf-8 -*-

"""
关键字检测器模块
"""

import re
import logging
from typing import List, Dict, Tuple
import chardet

logger = logging.getLogger('YuanZhao.detector.keyword')

class KeywordDetector:
    """关键字检测器"""
    
    def __init__(self, config):
        self.config = config
        self.keywords = []  # 存储关键字列表 [(keyword, category, weight), ...]
        self.keyword_patterns = []  # 编译后的正则表达式模式列表
    
    def load_keywords(self, keywords_file: str) -> bool:
        """从文件加载关键字"""
        try:
            # 检测文件编码
            with open(keywords_file, 'rb') as f:
                raw_data = f.read(10000)
                result = chardet.detect(raw_data)
                encoding = result['encoding'] or 'utf-8'
            
            # 读取关键字文件
            with open(keywords_file, 'r', encoding=encoding) as f:
                for line_num, line in enumerate(f, 1):
                    # 去除注释行和空行
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # 解析CSV格式：关键字,类别,风险权重
                    parts = line.split(',')
                    if len(parts) < 3:
                        logger.warning(f"关键字文件第{line_num}行格式错误，跳过: {line}")
                        continue
                    
                    keyword = parts[0].strip()
                    category = parts[1].strip()
                    
                    # 验证风险权重
                    try:
                        weight = int(parts[2].strip())
                        if not 1 <= weight <= 10:
                            logger.warning(f"关键字文件第{line_num}行风险权重超出范围(1-10)，使用默认值5: {line}")
                            weight = 5
                    except ValueError:
                        logger.warning(f"关键字文件第{line_num}行风险权重不是数字，使用默认值5: {line}")
                        weight = 5
                    
                    # 验证类别
                    valid_categories = ['gambling', 'porn', 'malware', 'phishing', 'other']
                    if category not in valid_categories:
                        logger.warning(f"关键字文件第{line_num}行类别无效，使用默认类别other: {line}")
                        category = 'other'
                    
                    # 添加关键字
                    self.keywords.append((keyword, category, weight))
            
            # 编译正则表达式模式
            self._compile_keyword_patterns()
            
            logger.info(f"成功加载 {len(self.keywords)} 个关键字")
            return True
            
        except Exception as e:
            logger.error(f"加载关键字文件失败: {str(e)}", exc_info=True)
            # 如果加载失败，使用内置的默认关键字
            self._load_default_keywords()
            return False
    
    def _load_default_keywords(self):
        """加载内置的默认关键字"""
        default_keywords = [
            # 博彩类
            ('bet365', 'gambling', 9),
            ('皇冠体育', 'gambling', 9),
            ('时时彩', 'gambling', 9),
            ('六合彩', 'gambling', 9),
            ('百家乐', 'gambling', 9),
            ('赌场', 'gambling', 8),
            ('赌博', 'gambling', 8),
            ('彩票', 'gambling', 7),
            ('投注', 'gambling', 7),
            
            # 色情类
            ('色情', 'porn', 9),
            ('黄色', 'porn', 9),
            ('成人', 'porn', 8),
            ('av', 'porn', 9),
            ('性爱', 'porn', 9),
            ('裸体', 'porn', 8),
            ('性交', 'porn', 9),
            
            # 恶意软件类
            ('木马', 'malware', 10),
            ('病毒', 'malware', 10),
            ('后门', 'malware', 10),
            ('勒索', 'malware', 10),
            ('挖矿', 'malware', 9),
            ('病毒下载', 'malware', 9),
            ('远程控制', 'malware', 9),
            
            # 钓鱼类
            ('钓鱼', 'phishing', 10),
            ('账号密码', 'phishing', 9),
            ('银行账号', 'phishing', 10),
            ('登录验证', 'phishing', 9),
            ('支付验证', 'phishing', 9),
            ('验证码', 'phishing', 8),
            
            # 其他可疑
            ('暗链', 'other', 8),
            ('黑帽SEO', 'other', 8),
            ('权重传递', 'other', 7),
            ('网站劫持', 'other', 9),
        ]
        
        self.keywords = default_keywords
        self._compile_keyword_patterns()
        logger.info(f"使用默认关键字，共 {len(self.keywords)} 个")
    
    def _compile_keyword_patterns(self):
        """编译关键字正则表达式模式"""
        self.keyword_patterns = []
        
        for keyword, category, weight in self.keywords:
            if keyword.isascii() and re.fullmatch(r'[A-Za-z]+', keyword) and len(keyword) <= 2:
                pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            else:
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            self.keyword_patterns.append((pattern, keyword, category, weight))
    
    def detect(self, content: str, source: str) -> List[Dict]:
        """检测内容中的关键字匹配"""
        results = []
        
        # 如果没有加载关键字，使用默认关键字
        if not self.keywords:
            self._load_default_keywords()
        
        try:
            # 对每个关键字模式进行匹配
            for pattern, original_keyword, category, weight in self.keyword_patterns:
                for match in pattern.finditer(content):
                    # 获取匹配上下文
                    context = self._get_context(content, match.start(), match.end())
                    
                    # 构建结果
                    result = {
                        'keyword': original_keyword,
                        'category': self._get_category_name(category),
                        'weight': weight,
                        'source': source,
                        'context': context,
                        'match_position': match.start()
                    }
                    
                    # 避免重复添加相同位置的匹配
                    if not self._is_duplicate_match(results, result):
                        results.append(result)
            
            # 按风险权重排序
            results.sort(key=lambda x: x['weight'], reverse=True)
            
        except Exception as e:
            logger.error(f"关键字检测失败: {str(e)}", exc_info=True)
        
        return results
    
    def _get_category_name(self, category: str) -> str:
        """获取类别的中文名称"""
        category_names = {
            'gambling': '博彩',
            'porn': '色情',
            'malware': '恶意软件',
            'phishing': '钓鱼',
            'other': '其他'
        }
        
        return category_names.get(category, '其他')
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """获取匹配内容的上下文"""
        start_context = max(0, start - context_size)
        end_context = min(len(content), end + context_size)
        
        context = content[start_context:end_context]
        context = context.replace('\n', ' ').replace('\r', ' ')
        
        # 截断过长的上下文
        if len(context) > 200:
            context = context[:100] + '...' + context[-100:]
        
        return context
    
    def _is_duplicate_match(self, existing_results: List[Dict], new_result: Dict) -> bool:
        """检查是否为重复的匹配"""
        # 检查是否在相同位置附近有相同关键字的匹配
        position = new_result['match_position']
        keyword = new_result['keyword']
        source = new_result['source']
        
        for result in existing_results:
            if (result['keyword'] == keyword and 
                result['source'] == source and 
                abs(result['match_position'] - position) < 10):
                return True
        
        return False
    
    def get_keyword_statistics(self) -> Dict:
        """获取关键字统计信息"""
        stats = {
            'total_keywords': len(self.keywords),
            'by_category': {}
        }
        
        # 按类别统计
        for _, category, _ in self.keywords:
            category_name = self._get_category_name(category)
            if category_name not in stats['by_category']:
                stats['by_category'][category_name] = 0
            stats['by_category'][category_name] += 1
        
        return stats
    
    def add_keyword(self, keyword: str, category: str = 'other', weight: int = 5):
        """动态添加关键字"""
        # 验证参数
        if not keyword or not keyword.strip():
            logger.warning("尝试添加空关键字，跳过")
            return False
        
        weight = max(1, min(10, weight))  # 限制在1-10范围内
        
        valid_categories = ['gambling', 'porn', 'malware', 'phishing', 'other']
        if category not in valid_categories:
            category = 'other'
        
        # 检查是否已存在
        for existing_keyword, _, _ in self.keywords:
            if existing_keyword == keyword:
                logger.warning(f"关键字 '{keyword}' 已存在")
                return False
        
        # 添加关键字
        self.keywords.append((keyword, category, weight))
        
        # 编译新的模式
        if keyword.isascii() and re.fullmatch(r'[A-Za-z]+', keyword) and len(keyword) <= 2:
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        else:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        self.keyword_patterns.append((pattern, keyword, category, weight))
        
        logger.info(f"成功添加关键字: {keyword} (类别: {category}, 权重: {weight})")
        return True
    
    def clear_keywords(self):
        """清空所有关键字"""
        self.keywords = []
        self.keyword_patterns = []
        logger.info("已清空所有关键字")
        
