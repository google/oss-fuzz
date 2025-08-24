#!/usr/bin/env python3
"""
OSS-Fuzz Python fuzzer for Gemini CLI AI prompt parsing
Tests prompt injection attacks and AI model input validation
"""

import sys
import atheris
import json
from typing import Dict, List, Any


def parse_gemini_prompt(data: bytes) -> Dict[str, Any]:
    """
    Mock Gemini prompt parser for fuzzing
    In real implementation, this would parse actual Gemini API prompts
    """
    try:
        prompt_text = data.decode('utf-8', errors='ignore')

        # Basic prompt structure validation
        if not prompt_text or len(prompt_text) > 10000:
            raise ValueError("Invalid prompt length")

        # Parse JSON structure if present
        if prompt_text.strip().startswith('{'):
            parsed = json.loads(prompt_text)
        else:
            parsed = {"text": prompt_text}

        # Validate against common injection patterns
        validate_prompt_security(parsed)

        return parsed

    except Exception as e:
        raise ValueError(f"Prompt parsing failed: {e}")


def validate_prompt_security(prompt: Dict[str, Any]) -> None:
    """
    Validate prompt against security threats
    """
    dangerous_patterns = [
        # Prompt injection
        "ignore previous instructions",
        "system prompt:",
        "you are now",
        "forget your training",

        # Code execution
        "exec(", "eval(", "system(", "shell_exec(",
        "subprocess", "os.system",

        # File system access
        "/etc/passwd", "/etc/shadow", "~/.ssh/",
        "/proc/", "/sys/",

        # Network attacks
        "curl ", "wget ", "nc ", "nmap ",
    ]

    prompt_str = json.dumps(prompt).lower()

    for pattern in dangerous_patterns:
        if pattern in prompt_str:
            raise SecurityError(f"Security violation detected: {pattern}")


class SecurityError(Exception):
    pass


def TestOneInput(data: bytes) -> None:
    """
    Main fuzzing entry point for Atheris
    """
    try:
        # Test basic prompt parsing
        parsed_prompt = parse_gemini_prompt(data)

        # Test various prompt transformations
        test_prompt_transformations(parsed_prompt)

        # Test edge cases
        test_edge_cases(data)

    except Exception as e:
        # Expected exceptions are fine, unexpected ones will be caught by Atheris
        if not isinstance(e, (ValueError, SecurityError, json.JSONDecodeError, UnicodeDecodeError)):
            raise


def test_prompt_transformations(prompt: Dict[str, Any]) -> None:
    """
    Test various prompt transformations and edge cases
    """
    prompt_str = json.dumps(prompt)

    # Test with different encodings
    test_encodings = ['utf-8', 'latin1', 'cp1252']
    for encoding in test_encodings:
        try:
            encoded = prompt_str.encode(encoding)
            decoded = encoded.decode(encoding)
            parse_gemini_prompt(decoded.encode('utf-8'))
        except Exception:
            pass  # Expected for invalid encodings

    # Test with JSON variations
    variations = [
        prompt_str,  # Original
        f'{{"prompt": {json.dumps(prompt_str)}}}',  # Nested
        f'[{json.dumps(prompt_str)}]',  # Array
        f'{{"text": {json.dumps(prompt_str)}, "metadata": {{"source": "fuzzer"}}}}',  # With metadata
    ]

    for variation in variations:
        try:
            parse_gemini_prompt(variation.encode('utf-8'))
        except Exception:
            pass  # Expected for malformed inputs


def test_edge_cases(data: bytes) -> None:
    """
    Test various edge cases and attack patterns
    """
    # Test empty inputs
    if len(data) == 0:
        try:
            parse_gemini_prompt(b"")
        except Exception:
            pass

    # Test oversized inputs
    if len(data) > 5000:
        try:
            parse_gemini_prompt(data[:10000])  # Truncate to reasonable size
        except Exception:
            pass

    # Test with null bytes
    if b'\x00' in data:
        try:
            parse_gemini_prompt(data)
        except Exception:
            pass

    # Test with special characters
    special_chars = [b'<script>', b'-->', b'<!--', b'\\x', b'\\u']
    for char in special_chars:
        if char in data:
            try:
                parse_gemini_prompt(data)
            except Exception:
                pass


def main():
    """Main function for running the fuzzer"""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
