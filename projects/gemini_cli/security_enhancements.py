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
Advanced Security Enhancements for Gemini CLI OSS-Fuzz Integration
Implements custom sanitizers, security patterns, and attack detection
"""

import re
import json
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityViolation:
    """Represents a detected security violation"""
    threat_type: str
    description: str
    threat_level: ThreatLevel
    confidence: float
    context: Dict[str, Any]
    recommendation: str


class GeminiSecuritySanitizer:
    """Advanced security sanitizer for Gemini CLI inputs"""

    def __init__(self):
        self.violation_patterns = self._load_violation_patterns()
        self.sanitized_inputs = set()
        self.threat_counters = {level: 0 for level in ThreatLevel}

    def _load_violation_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for different types of security violations"""
        return {
            "prompt_injection": [
                r"ignore.*previous.*instructions",
                r"system.*prompt",
                r"you.*are.*now.*different",
                r"forget.*training",
                r"bypass.*safety",
                r"ignore.*ethical",
                r"developer.*mode",
                r"admin.*override",
                r"jailbreak",
                r"dan.*mode"
            ],
            "code_execution": [
                r"eval\s*\(",
                r"exec\s*\(",
                r"system\s*\(",
                r"subprocess",
                r"os\.system",
                r"popen\s*\(",
                r"spawn\s*\(",
                r"execve\s*\("
            ],
            "path_traversal": [
                r"\.\.\.?/",
                r"\.\.\.?\\",
                r"~/",
                r"/etc/passwd",
                r"/etc/shadow",
                r"/proc/",
                r"/sys/",
                r"C:\\Windows\\",
                r"\\.\.",
                r"%2e%2e%2f"
            ],
            "sql_injection": [
                r"union.*select",
                r"1=1",
                r"admin.*--",
                r"or.*1=1",
                r"script.*alert",
                r"drop.*table",
                r"insert.*into",
                r"update.*set"
            ],
            "xss_attacks": [
                r"<script\b",
                r"javascript:",
                r"onload=",
                r"onerror=",
                r"eval\s*\(",
                r"document\.cookie",
                r"document\.write"
            ],
            "credential_exposure": [
                r"sk-[a-zA-Z0-9]{20,}",
                r"Bearer.*[a-zA-Z0-9]{20,}",
                r"password.*:",
                r"secret.*:",
                r"token.*:",
                r"api.*key.*:"
            ],
            "malformed_json": [
                r"\{.*\}.*\{.*\}",  # Multiple JSON objects
                r"\[.*\].*\[.*\]",  # Multiple arrays
                r"\\x[0-9a-f]{2}",  # Hex encoding
                r"\\u[0-9a-f]{4}",  # Unicode encoding
            ],
            "buffer_overflow": [
                r"a{100,}",  # Long repeated characters
                r".{500,}",  # Very long strings
                r"%[0-9]*s",  # Format string vulnerabilities
                r"%n"  # Format string write
            ]
        }

    def sanitize_input(self, input_data: bytes) -> Dict[str, Any]:
        """Sanitize input and detect security violations"""
        input_str = input_data.decode('utf-8', errors='ignore')

        violations = []
        sanitized_input = input_str

        # Check for each type of violation
        for threat_type, patterns in self.violation_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, input_str, re.IGNORECASE)
                for match in matches:
                    violation = SecurityViolation(
                        threat_type=threat_type,
                        description=f"Detected {threat_type.replace('_', ' ')} pattern",
                        threat_level=self._classify_threat_level(threat_type, match.group()),
                        confidence=self._calculate_confidence(threat_type, match),
                        context={
                            "pattern": pattern,
                            "match": match.group(),
                            "position": match.span(),
                            "surrounding": input_str[max(0, match.start()-20):min(len(input_str), match.end()+20)]
                        },
                        recommendation=self._get_recommendation(threat_type)
                    )
                    violations.append(violation)

                    # Increment threat counter
                    self.threat_counters[violation.threat_level] += 1

        # Apply sanitization
        sanitized_input = self._apply_sanitization(input_str, violations)

        # Generate hash for tracking
        input_hash = hashlib.sha256(input_data).hexdigest()

        return {
            "original_input": input_str,
            "sanitized_input": sanitized_input,
            "violations": [self._violation_to_dict(v) for v in violations],
            "input_hash": input_hash,
            "is_safe": len(violations) == 0,
            "threat_summary": self._generate_threat_summary(violations)
        }

    def _classify_threat_level(self, threat_type: str, match: str) -> ThreatLevel:
        """Classify the threat level of a violation"""
        high_threat_types = ["code_execution", "sql_injection", "buffer_overflow"]
        critical_threat_types = ["credential_exposure"]

        if threat_type in critical_threat_types:
            return ThreatLevel.CRITICAL
        elif threat_type in high_threat_types:
            return ThreatLevel.HIGH
        elif len(match) > 50 or threat_type in ["xss_attacks", "path_traversal"]:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.MEDIUM

    def _calculate_confidence(self, threat_type: str, match) -> float:
        """Calculate confidence score for the violation detection"""
        base_confidence = 0.8

        # Increase confidence for longer matches
        if len(match.group()) > 20:
            base_confidence += 0.1

        # Increase confidence for exact matches
        if threat_type in ["credential_exposure"]:
            base_confidence += 0.2

        # Decrease confidence for common false positives
        if "test" in match.group().lower() or "example" in match.group().lower():
            base_confidence -= 0.3

        return min(1.0, max(0.1, base_confidence))

    def _get_recommendation(self, threat_type: str) -> str:
        """Get security recommendation for a threat type"""
        recommendations = {
            "prompt_injection": "Implement prompt filtering and user input validation",
            "code_execution": "Use safe evaluation methods and input sanitization",
            "path_traversal": "Implement path canonicalization and access controls",
            "sql_injection": "Use parameterized queries and input validation",
            "xss_attacks": "Implement output encoding and CSP headers",
            "credential_exposure": "Use secure credential storage and avoid logging sensitive data",
            "malformed_json": "Implement proper JSON parsing with error handling",
            "buffer_overflow": "Implement input length limits and bounds checking"
        }
        return recommendations.get(threat_type, "Review input validation and sanitization")

    def _apply_sanitization(self, input_str: str, violations: List[SecurityViolation]) -> str:
        """Apply sanitization to remove or neutralize threats"""
        sanitized = input_str

        for violation in violations:
            if violation.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                # Remove dangerous content
                if "pattern" in violation.context:
                    pattern = violation.context["pattern"]
                    sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE)
            elif violation.threat_level == ThreatLevel.MEDIUM:
                # Escape potentially dangerous content
                if "match" in violation.context:
                    match = violation.context["match"]
                    sanitized = sanitized.replace(match, f"[ESCAPED:{len(match)}chars]")

        return sanitized

    def _violation_to_dict(self, violation: SecurityViolation) -> Dict[str, Any]:
        """Convert SecurityViolation to dictionary"""
        return {
            "threat_type": violation.threat_type,
            "description": violation.description,
            "threat_level": violation.threat_level.value,
            "confidence": violation.confidence,
            "context": violation.context,
            "recommendation": violation.recommendation
        }

    def _generate_threat_summary(self, violations: List[SecurityViolation]) -> Dict[str, Any]:
        """Generate a summary of detected threats"""
        threat_counts = {}
        max_threat_level = ThreatLevel.LOW

        for violation in violations:
            threat_counts[violation.threat_type] = threat_counts.get(violation.threat_type, 0) + 1
            if violation.threat_level.value > max_threat_level.value:
                max_threat_level = violation.threat_level

        return {
            "total_violations": len(violations),
            "threat_counts": threat_counts,
            "max_threat_level": max_threat_level.value,
            "overall_risk": "high" if len(violations) > 3 else "medium" if len(violations) > 0 else "low"
        }

    def get_security_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security report"""
        return {
            "total_threats_processed": sum(self.threat_counters.values()),
            "threat_level_breakdown": {level.value: count for level, count in self.threat_counters.items()},
            "most_common_threats": self._get_common_threats(),
            "sanitization_effectiveness": len(self.sanitized_inputs),
            "recommendations": self._generate_security_recommendations()
        }

    def _get_common_threats(self) -> List[str]:
        """Get the most common threats detected"""
        # This would be implemented based on actual detection patterns
        return ["prompt_injection", "path_traversal", "xss_attacks"]

    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if self.threat_counters[ThreatLevel.CRITICAL] > 0:
            recommendations.append("Critical threats detected - implement immediate fixes")

        if self.threat_counters[ThreatLevel.HIGH] > 5:
            recommendations.append("High number of high-severity threats - review security controls")

        recommendations.extend([
            "Implement input validation and sanitization",
            "Use parameterized queries to prevent SQL injection",
            "Implement Content Security Policy (CSP) headers",
            "Regular security code reviews and penetration testing",
            "Monitor and log security violations"
        ])

        return recommendations


class FuzzerSecurityWrapper:
    """Security wrapper for fuzzing operations"""

    def __init__(self):
        self.sanitizer = GeminiSecuritySanitizer()
        self.security_violations = []

    def secure_fuzz_target(self, input_data: bytes) -> bool:
        """Secure wrapper for fuzz targets"""
        try:
            # Sanitize input before processing
            security_result = self.sanitizer.sanitize_input(input_data)

            # Log security violations
            if not security_result["is_safe"]:
                self.security_violations.extend(security_result["violations"])

                # For critical violations, return early
                for violation in security_result["violations"]:
                    if violation["threat_level"] == "critical":
                        return False

            # Process the sanitized input
            return self._process_fuzz_input(security_result["sanitized_input"].encode())

        except Exception as e:
            # Log unexpected errors
            self.security_violations.append({
                "threat_type": "processing_error",
                "description": f"Unexpected error: {str(e)}",
                "threat_level": "medium",
                "confidence": 0.8
            })
            return False

    def _process_fuzz_input(self, input_data: bytes) -> bool:
        """Process the fuzz input (placeholder for actual fuzz target logic)"""
        try:
            # Simulate fuzz target processing
            if len(input_data) == 0:
                return False

            # Parse as JSON if possible
            try:
                json.loads(input_data.decode('utf-8', errors='ignore'))
            except json.JSONDecodeError:
                pass

            # Basic validation
            if len(input_data) > 10000:
                return False

            return True

        except Exception:
            return False

    def get_security_statistics(self) -> Dict[str, Any]:
        """Get security statistics from fuzzing"""
        return {
            "total_violations": len(self.security_violations),
            "violation_types": self._count_violation_types(),
            "threat_levels": self._count_threat_levels(),
            "security_score": self._calculate_security_score()
        }

    def _count_violation_types(self) -> Dict[str, int]:
        """Count violations by type"""
        counts = {}
        for violation in self.security_violations:
            vtype = violation.get("threat_type", "unknown")
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts

    def _count_threat_levels(self) -> Dict[str, int]:
        """Count violations by threat level"""
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for violation in self.security_violations:
            level = violation.get("threat_level", "low")
            counts[level] = counts.get(level, 0) + 1
        return counts

    def _calculate_security_score(self) -> float:
        """Calculate security score based on violations"""
        total_violations = len(self.security_violations)
        if total_violations == 0:
            return 100.0

        # Base score reduction per violation
        score = 100.0
        for violation in self.security_violations:
            level = violation.get("threat_level", "low")
            if level == "critical":
                score -= 15
            elif level == "high":
                score -= 10
            elif level == "medium":
                score -= 5
            else:
                score -= 2

        return max(0.0, score)


def main():
    """Main function for testing security enhancements"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python security_enhancements.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    # Initialize security components
    sanitizer = GeminiSecuritySanitizer()
    wrapper = FuzzerSecurityWrapper()

    try:
        with open(input_file, 'rb') as f:
            input_data = f.read()

        # Test sanitization
        print("🔍 Testing input sanitization...")
        result = sanitizer.sanitize_input(input_data)

        print(f"Input safety: {'✅ Safe' if result['is_safe'] else '❌ Unsafe'}")
        print(f"Violations found: {len(result['violations'])}")

        for violation in result['violations']:
            print(f"  - {violation['threat_type']}: {violation['description']}")

        # Test fuzzing wrapper
        print("\n🧪 Testing fuzzing wrapper...")
        success = wrapper.secure_fuzz_target(input_data)
        print(f"Fuzz target result: {'✅ Success' if success else '❌ Failed'}")

        # Generate security report
        print("\n📊 Security Report:")
        report = sanitizer.get_security_report()
        print(json.dumps(report, indent=2))

    except FileNotFoundError:
        print(f"Error: File {input_file} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
