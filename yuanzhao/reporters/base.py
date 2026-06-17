"""报告生成器抽象基类."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from yuanzhao.detectors.base import Finding


class BaseReporter(ABC):
    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)

    @abstractmethod
    def generate(self, findings: list[Finding], metadata: dict) -> str:
        """生成报告，返回输出文件路径."""
        ...

    def _ensure_dir(self):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
