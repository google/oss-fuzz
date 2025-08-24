#!/usr/bin/env python3
"""
Base plugin classes for Gemini CLI fuzzing infrastructure
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class PluginResult:
    """Result from plugin execution"""
    success: bool = False
    data: Dict[str, Any] = None
    errors: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.errors is None:
            self.errors = []
        if self.metadata is None:
            self.metadata = {}


class LanguagePlugin(ABC):
    """Base class for language-specific plugins"""

    def __init__(self, name: str, language: str):
        self.name = name
        self.language = language
        self.supported_file_types = []

    @abstractmethod
    def analyze_file(self, file_path: str) -> PluginResult:
        """Analyze a single file"""
        pass

    @abstractmethod
    def generate_fuzzer(self, target: str, output_dir: str) -> PluginResult:
        """Generate fuzz targets for a given target"""
        pass

    def is_supported_file(self, file_path: str) -> bool:
        """Check if file type is supported by this plugin"""
        if not self.supported_file_types:
            return True
        for ext in self.supported_file_types:
            if file_path.endswith(ext):
                return True
        return False


class AnalysisPlugin(ABC):
    """Base class for analysis plugins"""

    def __init__(self, name: str):
        self.name = name
        self.analysis_type = "generic"

    @abstractmethod
    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> PluginResult:
        """Perform analysis on provided data"""
        pass

    def get_analysis_metadata(self) -> Dict[str, Any]:
        """Get metadata about this analysis plugin"""
        return {
            "name": self.name,
            "type": self.analysis_type,
            "version": "1.0.0"
        }


class HumanLanguagePlugin(LanguagePlugin):
    """Plugin for human language analysis"""

    def __init__(self, name: str):
        super().__init__(name, "human")
        self.supported_file_types = ['.txt', '.md', '.rst', '.doc', '.docx']

    def analyze_file(self, file_path: str) -> PluginResult:
        """Analyze human language file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            return PluginResult(
                success=True,
                data={
                    'word_count': len(content.split()),
                    'char_count': len(content),
                    'line_count': len(content.split('\n'))
                },
                metadata={'file_path': file_path}
            )
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[str(e)],
                metadata={'file_path': file_path}
            )

    def generate_fuzzer(self, target: str, output_dir: str) -> PluginResult:
        """Generate fuzz targets for human language processing"""
        return PluginResult(
            success=False,
            errors=["Human language fuzzer generation not implemented"],
            metadata={'target': target, 'output_dir': output_dir}
        )
