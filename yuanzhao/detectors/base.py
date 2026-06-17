"""检测器抽象基类与统一结果模型."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """统一的检测结果."""

    rule_id: str
    severity: int  # 1-10
    category: str  # suspicious_url | hidden_element | keyword_match | js_issue | css_issue | suspicious_pattern
    source_type: str  # html | js | css | dynamic | comments | meta
    location: str  # 来源文件/URL
    evidence: str  # 匹配的证据（URL、代码片段等）
    context: str = ""  # 上下文文本
    position: tuple[int, int] = (0, 0)  # (start, end)
    metadata: dict[str, Any] = field(default_factory=dict)  # 额外信息


class BaseDetector(ABC):
    """检测器抽象基类.

    子类只需实现 detect() 方法，返回 Finding 列表。
    可以通过 rules 字典访问加载的规则数据。
    """

    def __init__(self, rules: dict[str, Any] | None = None):
        self.rules = rules or {}

    @abstractmethod
    def detect(self, content: str, source: str) -> list[Finding]:
        """检测内容中的可疑项.

        Args:
            content: 要检测的内容（HTML/JS/CSS 文本）
            source: 来源标识（文件路径或 URL）

        Returns:
            Finding 列表
        """
        ...

    def enabled(self, config) -> bool:
        """检查此检测器在当前配置下是否启用."""
        return True
