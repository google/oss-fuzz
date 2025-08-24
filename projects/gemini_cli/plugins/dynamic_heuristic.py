#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

"""
Dynamic Heuristic Plugin - The Self-Extending Plugin

This plugin's behavior is not hardcoded. Its rules and patterns are loaded from the
analytics database at runtime, allowing it to learn and improve automatically.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Pattern, Match
import re
import sqlite3

# Add the parent directory to the path to import rapid_expand
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from rapid_expand import AnalyticsDatabase, PluginResult
except ImportError:
    # Fallback for standalone usage
    class AnalyticsDatabase:
        def __init__(self, db_path: str = None): 
            self.db_path = db_path
        def get_successful_patterns(self, *args): return []
        def get_top_keywords(self, *args): return []
        def get_insights(self, *args, **kwargs): return []

    class PluginResult:
        def __init__(self, success: bool, data: Dict = None, error: str = None):
            self.success = success
            self.data = data or {}
            self.error = error

try:
    from plugins.base_plugin import AnalysisPlugin
except ImportError:
    # Fallback for standalone usage
    class AnalysisPlugin:
        def __init__(self):
            pass
        
        @property
        def name(self) -> str:
            return "base"
        
        @property
        def analysis_type(self) -> str:
            return "base"
        
        def analyze(self, data: Any) -> 'PluginResult':
            return PluginResult(False, error="Base plugin not implemented")

class DynamicHeuristicPlugin(AnalysisPlugin):
    """A plugin that learns and adapts based on historical data"""

    def __init__(self, analytics_db_path: str = "analytics.db"):
        super().__init__()
        self.analytics_db_path = Path(analytics_db_path)
        self._learned_patterns: Dict[str, List[Pattern]] = {}
        self._keyword_weights: Dict[str, float] = {}
        self._language_insights: Dict[str, Dict[str, Any]] = {}

        # Initialize connection to analytics database
        self.analytics_db = AnalyticsDatabase(str(self.analytics_db_path))

        # Load learned patterns and insights
        self._load_learned_patterns()
        self._load_keyword_weights()
        self._load_language_insights()

    @property
    def name(self) -> str:
        return "dynamic_heuristic"

    @property
    def analysis_type(self) -> str:
        return "intelligent_analysis"

    def analyze(self, data: Any) -> PluginResult:
        """Perform intelligent analysis using learned patterns"""
        try:
            if isinstance(data, dict) and 'file_path' in data:
                file_path = Path(data['file_path'])
                return self._analyze_file(file_path)
            elif isinstance(data, str):
                return self._analyze_content(data)
            else:
                return PluginResult(False, error="Unsupported data type for analysis")

        except Exception as e:
            return PluginResult(False, error=f"Analysis failed: {e}")

    def _analyze_file(self, file_path: Path) -> PluginResult:
        """Analyze a file using learned patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Detect language
            language = self._detect_language(content)

            # Apply learned patterns for this language
            patterns_found = self._apply_learned_patterns(content, language)

            # Extract keywords using learned weights
            keywords = self._extract_weighted_keywords(content, language)

            # Generate insights
            insights = self._generate_file_insights(file_path, content, language, patterns_found)

            analysis_data = {
                'language': language,
                'patterns_found': patterns_found,
                'keywords': keywords,
                'insights': insights,
                'file_path': str(file_path),
                'file_size': len(content),
                'line_count': len(content.splitlines())
            }

            return PluginResult(True, data=analysis_data)

        except Exception as e:
            return PluginResult(False, error=f"File analysis failed: {e}")

    def _analyze_content(self, content: str) -> PluginResult:
        """Analyze content using learned patterns"""
        try:
            # Detect language
            language = self._detect_language(content)

            # Apply learned patterns
            patterns_found = self._apply_learned_patterns(content, language)

            # Extract keywords
            keywords = self._extract_weighted_keywords(content, language)

            analysis_data = {
                'language': language,
                'patterns_found': patterns_found,
                'keywords': keywords,
                'content_length': len(content)
            }

            return PluginResult(True, data=analysis_data)

        except Exception as e:
            return PluginResult(False, error=f"Content analysis failed: {e}")

    def _load_learned_patterns(self):
        """Load successful patterns from the analytics database"""
        print("🧠 Dynamic Heuristic: Loading learned patterns...")

        try:
            # Get patterns for all supported languages
            supported_languages = ['go', 'javascript', 'java', 'python', 'cpp', 'c', 'rust']

            for language in supported_languages:
                successful_patterns = self.analytics_db.get_successful_patterns(language, limit=20)

                self._learned_patterns[language] = []
                for pattern_data in successful_patterns:
                    pattern_str = pattern_data.get('pattern', '') if isinstance(pattern_data, dict) else str(pattern_data)
                    if pattern_str:
                        try:
                            # Compile regex pattern
                            compiled_pattern = re.compile(pattern_str, re.MULTILINE | re.IGNORECASE)
                            self._learned_patterns[language].append(compiled_pattern)
                        except re.error as e:
                            print(f"⚠️  Invalid regex pattern for {language}: {pattern_str} - {e}")

            print(f"✅ Loaded patterns for {len(self._learned_patterns)} languages")

        except Exception as e:
            print(f"⚠️  Failed to load learned patterns: {e}")
            self._learned_patterns = {}

    def _load_keyword_weights(self):
        """Load keyword effectiveness weights from the database"""
        print("🧠 Dynamic Heuristic: Loading keyword weights...")

        try:
            supported_languages = ['go', 'javascript', 'java', 'python', 'cpp', 'c', 'rust']

            for language in supported_languages:
                top_keywords = self.analytics_db.get_top_keywords(language, limit=50)

                for keyword_data in top_keywords:
                    if isinstance(keyword_data, dict):
                        keyword = keyword_data.get('keyword', '')
                        coverage_improvement = keyword_data.get('coverage_improvement', 1.0)
                        success_count = keyword_data.get('success_count', 1)
                        weight = coverage_improvement * success_count
                    else:
                        keyword = str(keyword_data)
                        weight = 1.0
                    
                    if keyword:
                        self._keyword_weights[f"{language}:{keyword}"] = weight

            print(f"✅ Loaded {len(self._keyword_weights)} keyword weights")

        except Exception as e:
            print(f"⚠️  Failed to load keyword weights: {e}")
            self._keyword_weights = {}

    def _load_language_insights(self):
        """Load language-specific insights"""
        print("🧠 Dynamic Heuristic: Loading language insights...")

        try:
            # Get language performance insights
            insights = self.analytics_db.get_insights('language_performance', limit=50)

            for insight in insights:
                if isinstance(insight, dict):
                    data = insight.get('data', {})
                    language = data.get('language')
                    if language:
                        if language not in self._language_insights:
                            self._language_insights[language] = []

                        self._language_insights[language].append({
                            'success_rate': data.get('success_rate', 0),
                            'file_count': data.get('file_count', 0),
                            'patterns_found': data.get('patterns_found', 0),
                            'confidence': insight.get('confidence', 0.5)
                        })

            print(f"✅ Loaded insights for {len(self._language_insights)} languages")

        except Exception as e:
            print(f"⚠️  Failed to load language insights: {e}")
            self._language_insights = {}

    def _detect_language(self, content: str) -> str:
        """Detect programming language using learned patterns and heuristics"""
        scores = {}

        # Use learned patterns for language detection
        for language, patterns in self._learned_patterns.items():
            score = 0
            for pattern in patterns:
                matches = pattern.findall(content)
                score += len(matches)

            # Boost score based on historical success rate
            if language in self._language_insights:
                avg_success = sum(insight['success_rate'] for insight in self._language_insights[language]) / len(self._language_insights[language])
                score *= (1 + avg_success)

            scores[language] = score

        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]

        # Fallback to simple heuristic detection
        content_lower = content.lower()
        if 'func ' in content_lower and 'package ' in content_lower:
            return 'go'
        elif 'function' in content_lower and ('const ' in content_lower or 'let ' in content_lower):
            return 'javascript'
        elif 'public class' in content_lower and 'import java.' in content_lower:
            return 'java'
        elif 'def ' in content_lower and 'import ' in content_lower:
            return 'python'
        elif '#include' in content_lower:
            return 'cpp'
        else:
            return 'unknown'

    def _apply_learned_patterns(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Apply learned regex patterns to extract structured data"""
        patterns_found = []

        if language not in self._learned_patterns:
            return patterns_found

        for pattern in self._learned_patterns[language]:
            try:
                matches = pattern.finditer(content)
                for match in matches:
                    patterns_found.append({
                        'pattern': pattern.pattern,
                        'match': match.group(0),
                        'start': match.start(),
                        'end': match.end(),
                        'groups': match.groups()
                    })
            except Exception as e:
                continue  # Skip problematic patterns

        return patterns_found

    def _extract_weighted_keywords(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Extract keywords weighted by historical effectiveness"""
        keywords = []

        # Split content into potential keywords
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content)

        # Score each word based on learned weights
        word_scores = {}
        for word in words:
            key = f"{language}:{word}"
            weight = self._keyword_weights.get(key, 0.1)  # Default weight for unknown words
            word_scores[word] = weight

        # Sort by weight and return top keywords
        sorted_words = sorted(word_scores.items(), key=lambda x: x[1], reverse=True)

        for word, weight in sorted_words[:50]:  # Return top 50
            keywords.append({
                'keyword': word,
                'weight': weight,
                'language': language
            })

        return keywords

    def _generate_file_insights(self, file_path: Path, content: str, language: str,
                              patterns_found: List[Dict]) -> Dict[str, Any]:
        """Generate intelligent insights about the file"""
        insights = {
            'complexity_score': 0.0,
            'testability_score': 0.0,
            'security_risk_score': 0.0,
            'recommendations': []
        }

        # Calculate complexity score based on patterns found
        insights['complexity_score'] = min(len(patterns_found) / 10.0, 1.0)

        # Calculate testability score based on function patterns
        function_patterns = [p for p in patterns_found if 'func' in p['pattern'] or 'function' in p['pattern']]
        insights['testability_score'] = min(len(function_patterns) / 5.0, 1.0)

        # Generate recommendations based on learned insights
        if language in self._language_insights:
            avg_success = sum(insight['success_rate'] for insight in self._language_insights[language]) / len(self._language_insights[language])
            if avg_success < 0.5:
                insights['recommendations'].append(f"Consider improving {language} code patterns - historical success rate is low")

        # Security recommendations
        dangerous_patterns = ['eval(', 'exec(', 'system(', 'popen(']
        for pattern in dangerous_patterns:
            if pattern in content:
                insights['security_risk_score'] = max(insights['security_risk_score'], 0.8)
                insights['recommendations'].append(f"Found potentially dangerous pattern: {pattern}")

        return insights

    def learn_from_feedback(self, feedback_data: Dict[str, Any]):
        """Learn from feedback and update internal models"""
        # This method could be called by the core engine to provide
        # real-time feedback about the effectiveness of recommendations
        print(f"🧠 Dynamic Heuristic: Learning from feedback: {feedback_data}")


def main():
    """Main function for testing the dynamic heuristic plugin"""
    plugin = DynamicHeuristicPlugin()

    # Test with a sample Go file content
    test_content = '''
    package main

    import "fmt"

    func main() {
        fmt.Println("Hello, World!")
    }

    func add(a int, b int) int {
        return a + b
    }
    '''

    result = plugin.analyze(test_content)

    if result.success:
        print("✅ Dynamic analysis successful:")
        print(f"   Language: {result.data.get('language')}")
        print(f"   Patterns found: {len(result.data.get('patterns_found', []))}")
        print(f"   Keywords: {len(result.data.get('keywords', []))}")
    else:
        print(f"❌ Analysis failed: {result.error}")


if __name__ == "__main__":
    main()
