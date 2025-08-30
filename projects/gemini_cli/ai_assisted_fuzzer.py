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
Intelligent Fuzzing for Gemini CLI
Uses pattern analysis to optimize fuzzing campaigns and generate effective test inputs
"""

import json
import os
import sys
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import numpy as np
from collections import defaultdict, Counter


class FuzzingPatternLearner:
    """Learns patterns from successful fuzzing campaigns"""

    def __init__(self):
        self.successful_inputs = []
        self.failed_inputs = []
        self.crash_patterns = defaultdict(list)
        self.coverage_patterns = defaultdict(list)

    def add_successful_input(self, input_data: bytes, coverage: float):
        """Add a successful fuzzing input"""
        self.successful_inputs.append((input_data, coverage))

    def add_failed_input(self, input_data: bytes, error: str):
        """Add a failed fuzzing input"""
        self.failed_inputs.append((input_data, error))

    def add_crash_pattern(self, input_data: bytes, crash_type: str):
        """Add a crash pattern for analysis"""
        self.crash_patterns[crash_type].append(input_data)

    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze collected patterns to generate insights"""
        analysis = {
            "total_successful": len(self.successful_inputs),
            "total_failed": len(self.failed_inputs),
            "average_coverage": 0.0,
            "common_error_patterns": {},
            "crash_type_distribution": {},
            "coverage_distribution": {}
        }

        # Analyze coverage
        if self.successful_inputs:
            coverages = [coverage for _, coverage in self.successful_inputs]
            analysis["average_coverage"] = sum(coverages) / len(coverages)

        # Analyze error patterns
        error_counter = Counter(error for _, error in self.failed_inputs)
        analysis["common_error_patterns"] = dict(error_counter.most_common(10))

        # Analyze crash patterns
        analysis["crash_type_distribution"] = {crash_type: len(patterns)
                                             for crash_type, patterns in self.crash_patterns.items()}

        return analysis

    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on pattern analysis"""
        recommendations = []
        analysis = self.analyze_patterns()

        # Coverage-based recommendations
        if analysis["average_coverage"] < 50.0:
            recommendations.append("Consider adding more diverse seed inputs to improve coverage")

        # Error-based recommendations
        common_errors = analysis["common_error_patterns"]
        if "timeout" in common_errors:
            recommendations.append("Increase timeout values for complex test cases")

        if "memory" in common_errors:
            recommendations.append("Reduce input sizes or increase memory limits")

        # Crash-based recommendations
        for crash_type, count in analysis["crash_type_distribution"].items():
            if count > 5:
                recommendations.append(f"Focus on {crash_type} crashes - found {count} instances")

        return recommendations


class IntelligentMutator:
    """Pattern-based input mutator that learns from successful fuzzing"""

    def __init__(self, learner: FuzzingPatternLearner):
        self.learner = learner
        self.mutation_strategies = [
            self._bit_flip_mutation,
            self._byte_insert_mutation,
            self._chunk_deletion_mutation,
            self._pattern_based_mutation,
            self._coverage_guided_mutation
        ]

    def mutate(self, input_data: bytes) -> bytes:
        """Generate a mutated version of the input"""
        if not input_data:
            return self._generate_random_input()

        # Choose mutation strategy based on learning
        strategy = random.choice(self.mutation_strategies)
        return strategy(input_data)

    def _bit_flip_mutation(self, data: bytes) -> bytes:
        """Simple bit flip mutation"""
        if len(data) == 0:
            return data

        mutated = bytearray(data)
        position = random.randint(0, len(data) - 1)
        mutated[position] ^= 1  # Flip a random bit
        return bytes(mutated)

    def _byte_insert_mutation(self, data: bytes) -> bytes:
        """Insert random bytes"""
        if len(data) == 0:
            return data

        position = random.randint(0, len(data))
        new_byte = random.randint(0, 255)
        return data[:position] + bytes([new_byte]) + data[position:]

    def _chunk_deletion_mutation(self, data: bytes) -> bytes:
        """Delete a chunk of data"""
        if len(data) < 2:
            return data

        start = random.randint(0, len(data) - 2)
        end = random.randint(start + 1, min(start + 10, len(data)))
        return data[:start] + data[end:]

    def _pattern_based_mutation(self, data: bytes) -> bytes:
        """Apply mutations based on learned patterns"""
        # Look for common patterns in successful inputs
        successful_patterns = self._extract_patterns()

        if successful_patterns and random.random() < 0.3:
            pattern = random.choice(successful_patterns)
            return self._apply_pattern_mutation(data, pattern)

        return self._bit_flip_mutation(data)

    def _coverage_guided_mutation(self, data: bytes) -> bytes:
        """Apply mutations that historically led to better coverage"""
        # Prioritize mutations that led to successful coverage
        if self.learner.successful_inputs and random.random() < 0.4:
            successful_input, _ = random.choice(self.learner.successful_inputs)
            return self._hybrid_mutation(data, successful_input)

        return self._bit_flip_mutation(data)

    def _extract_patterns(self) -> List[bytes]:
        """Extract common patterns from successful inputs"""
        patterns = []
        for input_data, _ in self.learner.successful_inputs:
            # Extract substrings of length 3-10 that appear frequently
            for i in range(len(input_data) - 3):
                for j in range(4, min(11, len(input_data) - i + 1)):
                    pattern = input_data[i:i+j]
                    patterns.append(pattern)
        return patterns[:100]  # Limit patterns

    def _apply_pattern_mutation(self, data: bytes, pattern: bytes) -> bytes:
        """Apply a pattern-based mutation"""
        if len(data) == 0:
            return pattern

        position = random.randint(0, len(data))
        return data[:position] + pattern + data[position:]

    def _hybrid_mutation(self, data: bytes, successful_input: bytes) -> bytes:
        """Create a hybrid of current input and successful input"""
        if len(data) == 0 or len(successful_input) == 0:
            return data or successful_input

        # Take a chunk from successful input and insert it
        chunk_size = min(10, len(successful_input))
        start = random.randint(0, len(successful_input) - chunk_size)
        chunk = successful_input[start:start + chunk_size]

        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + chunk + data[insert_pos:]

    def _generate_random_input(self) -> bytes:
        """Generate a completely random input"""
        size = random.randint(1, 1000)
        return bytes([random.randint(0, 255) for _ in range(size)])


class AdaptiveFuzzer:
    """Adaptive fuzzing system that learns and optimizes"""

    def __init__(self, target_program: str):
        self.target_program = target_program
        self.learner = FuzzingPatternLearner()
        self.mutator = IntelligentMutator(self.learner)
        self.iteration = 0
        self.max_iterations = 10000

    def fuzz(self) -> Dict[str, Any]:
        """Run adaptive fuzzing campaign"""
        results = {
            "iterations": 0,
            "crashes_found": 0,
            "coverage_improvements": 0,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "insights": []
        }

        print(f"Starting pattern-based fuzzing for {self.target_program}")
        print(f"Target iterations: {self.max_iterations}")

        try:
            while self.iteration < self.max_iterations:
                self.iteration += 1

                # Generate or mutate input
                if self.iteration == 1:
                    # Start with seed input
                    input_data = self._generate_seed_input()
                else:
                    # Mutate based on learning
                    previous_input = self._get_previous_input()
                    input_data = self.mutator.mutate(previous_input)

                # Run the fuzz target
                success, coverage, error = self._run_target(input_data)

                # Learn from the result
                if success:
                    self.learner.add_successful_input(input_data, coverage)
                    if coverage > self._get_average_coverage():
                        results["coverage_improvements"] += 1
                else:
                    self.learner.add_failed_input(input_data, error)
                    if "crash" in error.lower() or "segmentation" in error.lower():
                        results["crashes_found"] += 1
                        self.learner.add_crash_pattern(input_data, "crash")

                # Periodic analysis and reporting
                if self.iteration % 100 == 0:
                    analysis = self.learner.analyze_patterns()
                    insights = self.learner.generate_recommendations()

                    print(f"Iteration {self.iteration}: "
                          f"Coverage: {analysis['average_coverage']:.1f}%, "
                          f"Crashes: {results['crashes_found']}")

                    results["insights"].extend(insights)

                # Adaptive adjustment
                if self.iteration % 500 == 0:
                    self._adapt_strategy()

        except KeyboardInterrupt:
            print("Fuzzing interrupted by user")

        results["end_time"] = datetime.now().isoformat()
        results["iterations"] = self.iteration

        return results

    def _generate_seed_input(self) -> bytes:
        """Generate initial seed input"""
        seeds = [
            b'{"model": "gemini-pro", "messages": [{"role": "user", "content": "Hello"}]}',
            b'{"prompt": "Write a story", "max_tokens": 100}',
            b'{"input": "test", "temperature": 0.7}',
            b'API_KEY=sk-test123',
            b'<script>alert(1)</script>',
            b'../../../../etc/passwd',
            b'{"malicious": true}',
        ]
        return random.choice(seeds)

    def _get_previous_input(self) -> bytes:
        """Get a previous input for mutation"""
        if self.learner.successful_inputs:
            return random.choice(self.learner.successful_inputs)[0]
        return self._generate_seed_input()

    def _run_target(self, input_data: bytes) -> Tuple[bool, float, str]:
        """Run the fuzz target with input data"""
        try:
            # This would normally execute the actual fuzz target
            # For simulation, we'll simulate success/failure

            # Simulate some inputs causing crashes
            if len(input_data) > 500 and random.random() < 0.1:
                return False, 0.0, "Simulated crash"

            # Simulate some inputs succeeding with varying coverage
            coverage = random.uniform(10.0, 90.0)
            return True, coverage, ""

        except Exception as e:
            return False, 0.0, str(e)

    def _get_average_coverage(self) -> float:
        """Get average coverage from successful inputs"""
        if not self.learner.successful_inputs:
            return 0.0

        coverages = [coverage for _, coverage in self.learner.successful_inputs]
        return sum(coverages) / len(coverages)

    def _adapt_strategy(self):
        """Adapt fuzzing strategy based on learning"""
        analysis = self.learner.analyze_patterns()

        # Adjust mutation probabilities based on success rates
        if analysis["total_successful"] > analysis["total_failed"] * 2:
            # High success rate - increase mutation complexity
            self.mutator.mutation_strategies.append(self.mutator._pattern_based_mutation)

        # Add more aggressive mutations if coverage is low
        if analysis["average_coverage"] < 30.0:
            self.mutator.mutation_strategies.append(self.mutator._chunk_deletion_mutation)

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive fuzzing report"""
        report = []
        report.append("=" * 60)
        report.append("Pattern-Based Fuzzing Report")
        report.append("=" * 60)
        report.append(f"Target: {self.target_program}")
        report.append(f"Iterations: {results['iterations']:,}")
        report.append(f"Crashes Found: {results['crashes_found']}")
        report.append(f"Coverage Improvements: {results['coverage_improvements']}")
        report.append(f"Start Time: {results['start_time']}")
        report.append(f"End Time: {results['end_time']}")
        report.append("")

        # Analysis
        analysis = self.learner.analyze_patterns()
        report.append("📊 Analysis:")
        report.append(f"  Successful Inputs: {analysis['total_successful']:,}")
        report.append(f"  Failed Inputs: {analysis['total_failed']:,}")
        report.append(f"  Average Coverage: {analysis['average_coverage']:.1f}%")
        report.append("")

        # Crash Distribution
        report.append("🚨 Crash Distribution:")
        for crash_type, count in analysis["crash_type_distribution"].items():
            report.append(f"  {crash_type}: {count}")
        report.append("")

        # Insights and Recommendations
        recommendations = self.learner.generate_recommendations()
        if recommendations:
            report.append("💡 Recommendations:")
            for rec in recommendations:
                report.append(f"  • {rec}")
            report.append("")

        # Insights from fuzzing
        if results["insights"]:
            report.append("🔍 Key Insights:")
            for insight in set(results["insights"][:10]):  # Show top 10 unique insights
                report.append(f"  • {insight}")

        return "\n".join(report)


def main():
    """Main function for pattern-based fuzzing"""
    if len(sys.argv) != 2:
        print("Usage: python ai_assisted_fuzzer.py <target_program>")
        sys.exit(1)

    target_program = sys.argv[1]
    fuzzer = AdaptiveFuzzer(target_program)

    print("🚀 Starting pattern-based fuzzing campaign...")
    results = fuzzer.fuzz()

    # Generate and display report
    report = fuzzer.generate_report(results)
    print("\n" + report)

    # Save report to file
    report_file = f"pattern_fuzzing_report_{int(time.time())}.txt"
    with open(report_file, 'w') as f:
        f.write(report)

    print(f"\n📄 Report saved to: {report_file}")


if __name__ == "__main__":
    main()
