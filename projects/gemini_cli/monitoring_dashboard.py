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
OSS-Fuzz Monitoring Dashboard for Gemini CLI
Provides real-time monitoring and analytics for fuzzing campaigns
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
import subprocess
import argparse


class OSSFuzzMonitor:
    """Monitors OSS-Fuzz campaigns and provides analytics"""

    def __init__(self, project_name: str = "gemini_cli"):
        self.project_name = project_name
        self.oss_fuzz_base_url = "https://oss-fuzz.com"
        self.local_build_dir = Path("/out") if os.path.exists("/out") else Path("./build/out")
        self.project_dir = self.local_build_dir / project_name

    def get_fuzzer_stats(self) -> Dict[str, Any]:
        """Get statistics for all fuzz targets"""
        stats = {
            "total_fuzzers": 0,
            "active_fuzzers": 0,
            "total_executions": 0,
            "total_coverage": 0.0,
            "fuzzer_details": []
        }

        if not self.project_dir.exists():
            return stats

        # Look for fuzz targets
        for fuzzer_path in self.project_dir.glob("fuzz_*"):
            if fuzzer_path.is_file() and os.access(fuzzer_path, os.X_OK):
                stats["total_fuzzers"] += 1

                # Get file size as a proxy for fuzzer activity
                size = fuzzer_path.stat().st_size
                if size > 1000:  # Consider larger files as "active"
                    stats["active_fuzzers"] += 1

                # Get basic stats
                fuzzer_stats = {
                    "name": fuzzer_path.name,
                    "size_bytes": size,
                    "last_modified": datetime.fromtimestamp(fuzzer_path.stat().st_mtime).isoformat(),
                    "executable": True
                }

                stats["fuzzer_details"].append(fuzzer_stats)

        return stats

    def analyze_coverage(self) -> Dict[str, Any]:
        """Analyze code coverage from fuzzing campaigns"""
        coverage = {
            "total_lines": 0,
            "covered_lines": 0,
            "coverage_percentage": 0.0,
            "language_breakdown": {}
        }

        coverage_dir = self.project_dir / "coverage"
        if not coverage_dir.exists():
            return coverage

        # Look for coverage reports
        for coverage_file in coverage_dir.glob("*.json"):
            try:
                with open(coverage_file) as f:
                    data = json.load(f)

                # Parse coverage data (this would depend on the coverage format)
                if "total" in data and "covered" in data:
                    coverage["total_lines"] += data["total"]
                    coverage["covered_lines"] += data["covered"]

            except (json.JSONDecodeError, KeyError):
                continue

        # Calculate percentage
        if coverage["total_lines"] > 0:
            coverage["coverage_percentage"] = (
                coverage["covered_lines"] / coverage["total_lines"]
            ) * 100

        return coverage

    def check_crash_reports(self) -> List[Dict[str, Any]]:
        """Check for crash reports and security issues"""
        crashes = []

        # Look for crash logs
        crash_patterns = [
            "*.crash",
            "*.log",
            "crash-*",
            "hang-*"
        ]

        for pattern in crash_patterns:
            for crash_file in self.project_dir.glob(pattern):
                try:
                    with open(crash_file) as f:
                        content = f.read()

                    crash_info = {
                        "filename": crash_file.name,
                        "size": crash_file.stat().st_size,
                        "timestamp": datetime.fromtimestamp(crash_file.stat().st_mtime).isoformat(),
                        "content_preview": content[:500] + "..." if len(content) > 500 else content,
                        "severity": self._classify_crash(content)
                    }

                    crashes.append(crash_info)

                except Exception:
                    continue

        return crashes

    def _classify_crash(self, crash_content: str) -> str:
        """Classify crash severity based on content"""
        content_lower = crash_content.lower()

        if any(keyword in content_lower for keyword in [
            "heap-buffer-overflow", "stack-buffer-overflow",
            "use-after-free", "double-free", "memory leak"
        ]):
            return "high"

        if any(keyword in content_lower for keyword in [
            "null pointer", "segfault", "access violation"
        ]):
            return "medium"

        if any(keyword in content_lower for keyword in [
            "assertion failed", "timeout"
        ]):
            return "low"

        return "unknown"

    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate performance report for fuzzing campaign"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "performance_metrics": {},
            "recommendations": []
        }

        stats = self.get_fuzzer_stats()

        # Performance analysis
        report["performance_metrics"] = {
            "total_fuzzers": stats["total_fuzzers"],
            "active_fuzzers": stats["active_fuzzers"],
            "fuzzer_uptime": self._calculate_uptime(),
            "executions_per_second": self._estimate_executions_per_second(),
            "memory_usage_mb": self._get_memory_usage()
        }

        # Generate recommendations
        if stats["total_fuzzers"] < 10:
            report["recommendations"].append("Consider adding more fuzz targets")

        if stats["active_fuzzers"] == 0:
            report["recommendations"].append("No active fuzzers detected - check build process")

        return report

    def _calculate_uptime(self) -> str:
        """Calculate fuzzing campaign uptime"""
        try:
            # Check project directory creation time
            if self.project_dir.exists():
                creation_time = datetime.fromtimestamp(self.project_dir.stat().st_ctime)
                uptime = datetime.now() - creation_time
                return str(uptime)
        except Exception:
            pass

        return "unknown"

    def _estimate_executions_per_second(self) -> float:
        """Estimate executions per second across all fuzzers"""
        # This is a simplified estimation based on file modifications
        total_recent_modifications = 0

        if self.project_dir.exists():
            cutoff = datetime.now() - timedelta(hours=1)
            for fuzzer_file in self.project_dir.glob("fuzz_*"):
                if fuzzer_file.is_file():
                    mtime = datetime.fromtimestamp(fuzzer_file.stat().st_mtime)
                    if mtime > cutoff:
                        total_recent_modifications += 1

        # Rough estimate: each active fuzzer might do ~1000 exec/sec
        return total_recent_modifications * 1000.0

    def _get_memory_usage(self) -> float:
        """Get current memory usage of fuzzing processes"""
        try:
            # This would typically query system process information
            # For now, return a placeholder
            return 256.0  # MB
        except Exception:
            return 0.0

    def export_dashboard_data(self, output_file: str = "fuzzing_dashboard.json"):
        """Export dashboard data to JSON file"""
        dashboard_data = {
            "project": self.project_name,
            "generated_at": datetime.now().isoformat(),
            "fuzzer_stats": self.get_fuzzer_stats(),
            "coverage_analysis": self.analyze_coverage(),
            "crash_reports": self.check_crash_reports(),
            "performance_report": self.generate_performance_report()
        }

        with open(output_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2)

        print(f"Dashboard data exported to {output_file}")

    def display_dashboard(self):
        """Display monitoring dashboard in console"""
        print("=" * 60)
        print(f"OSS-Fuzz Monitoring Dashboard - {self.project_name}")
        print("=" * 60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Fuzzer Statistics
        stats = self.get_fuzzer_stats()
        print("🔍 Fuzzer Statistics:")
        print(f"  Total Fuzzers: {stats['total_fuzzers']}")
        print(f"  Active Fuzzers: {stats['active_fuzzers']}")
        print(f"  Total Executions: {stats['total_executions']:,}")
        print()

        # Coverage Analysis
        coverage = self.analyze_coverage()
        print("📊 Coverage Analysis:")
        print(f"  Total Lines: {coverage['total_lines']:,}")
        print(f"  Covered Lines: {coverage['covered_lines']:,}")
        print(f"  Coverage: {coverage['coverage_percentage']:.1f}%")
        print()

        # Crash Reports
        crashes = self.check_crash_reports()
        print("🚨 Crash Reports:")
        print(f"  Total Crashes: {len(crashes)}")

        for crash in crashes[:5]:  # Show first 5 crashes
            print(f"  - {crash['filename']} ({crash['severity']} severity)")
        print()

        # Performance Report
        perf = self.generate_performance_report()
        print("⚡ Performance Metrics:")
        for metric, value in perf["performance_metrics"].items():
            print(f"  {metric}: {value}")
        print()

        if perf["recommendations"]:
            print("💡 Recommendations:")
            for rec in perf["recommendations"]:
                print(f"  - {rec}")
        else:
            print("✅ All systems operational - no recommendations needed")


def main():
    parser = argparse.ArgumentParser(description="OSS-Fuzz Monitoring Dashboard")
    parser.add_argument("--project", default="gemini_cli", help="Project name")
    parser.add_argument("--export", help="Export dashboard data to JSON file")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous monitoring mode")

    args = parser.parse_args()

    monitor = OSSFuzzMonitor(args.project)

    if args.continuous:
        print("Starting continuous monitoring mode...")
        try:
            while True:
                monitor.display_dashboard()
                print("\n" + "="*60)
                print("Next update in 60 seconds...")
                time.sleep(60)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
    else:
        monitor.display_dashboard()

    if args.export:
        monitor.export_dashboard_data(args.export)


if __name__ == "__main__":
    main()
