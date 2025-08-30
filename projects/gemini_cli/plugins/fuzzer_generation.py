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
Fuzzer Generation Plugin - The "Polyglot Hydra" Fuzzer Factory
Automatically generates fuzzing harnesses for any programming language and fuzzing engine
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import sys
import re
import json

# Add the parent directory to the path for imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from rapid_expand import AnalysisPlugin, PluginResult

class FuzzerGenerationPlugin(AnalysisPlugin):
    """The Universal Fuzzer Factory - Supporting all major programming languages and fuzzing engines"""

    # Language-specific fuzzing engine mappings
    FUZZING_ENGINES = {
        'go': ['go-fuzz', 'native-go-fuzz'],
        'rust': ['cargo-fuzz', 'libfuzzer'],
        'c': ['libfuzzer', 'afl++'],
        'cpp': ['libfuzzer', 'afl++'],
        'java': ['jazzer', 'jqf'],
        'kotlin': ['jazzer'],
        'scala': ['jazzer'],
        'javascript': ['jazzer.js', 'jsfuzz'],
        'typescript': ['jazzer.js'],
        'python': ['atheris', 'pythonfuzz'],
        'ruby': ['ruby-fuzz'],
        'php': ['php-fuzzer'],
        'csharp': ['sharpfuzz'],
        'fsharp': ['sharpfuzz'],
        'swift': ['swift-fuzzing'],
        'shell': ['bashfuzz'],
        'powershell': ['pester-fuzz']
    }

    @property
    def name(self) -> str:
        return "polyglot_fuzzer_gen"

    @property
    def analysis_type(self) -> str:
        return "universal_fuzzer_generation"

    def analyze(self, data: Any) -> PluginResult:
        """Generate fuzzing harnesses for any detected programming language"""
        try:
            language = data.get('language', '')
            function_signatures = data.get('function_signatures', [])
            output_dir = data.get('output_dir', Path('.'))
            fuzzing_engine = data.get('fuzzing_engine', 'auto')

            # Auto-detect best fuzzing engine for language
            if fuzzing_engine == 'auto':
                fuzzing_engine = self._select_optimal_engine(language)

            generated_files = []
            harness_metadata = []

            # Generate harnesses for all detected functions
            for signature in function_signatures[:50]:  # Increased limit for comprehensive coverage
                try:
                    harness_code = self._generate_harness(language, signature, fuzzing_engine)
                    filename = self._get_harness_filename(language, signature, fuzzing_engine)
                    output_path = output_dir / filename

                    # Ensure output directory exists
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(harness_code)

                    generated_files.append(str(output_path))
                    harness_metadata.append({
                        'signature': signature,
                        'language': language,
                        'engine': fuzzing_engine,
                        'file': str(output_path)
                    })

                except Exception as e:
                    print(f"Failed to generate harness for {signature}: {e}")

            # Generate build configuration files
            build_files = self._generate_build_configs(language, fuzzing_engine, output_dir, harness_metadata)
            generated_files.extend(build_files)

            return PluginResult(
                success=True,
                data={
                    'generated_files': generated_files,
                    'language': language,
                    'fuzzing_engine': fuzzing_engine,
                    'harness_count': len(harness_metadata),
                    'harness_metadata': harness_metadata
                },
                confidence=1.0,
                metadata={
                    'output_dir': str(output_dir),
                    'supported_engines': self.FUZZING_ENGINES.get(language, [])
                }
            )

        except Exception as e:
            return PluginResult(
                success=False,
                data={'generated_files': []},
                errors=[str(e)],
                confidence=0.0
            )

    def _select_optimal_engine(self, language: str) -> str:
        """Select the best fuzzing engine for the given language"""
        engines = self.FUZZING_ENGINES.get(language.lower(), ['generic'])
        return engines[0] if engines else 'generic'

    def _generate_harness(self, language: str, signature: str, engine: str) -> str:
        """Generate harness code for the given language, signature, and fuzzing engine"""
        parsed_info = self._parse_function_signature(signature)
        
        # Route to appropriate generator based on language and engine
        generator_key = f"{language.lower()}_{engine.replace('-', '_').replace('.', '_')}"
        
        # Try specific generator first, fall back to language-generic, then universal
        if hasattr(self, f'_generate_{generator_key}_harness'):
            return getattr(self, f'_generate_{generator_key}_harness')(signature, parsed_info)
        elif hasattr(self, f'_generate_{language.lower()}_harness'):
            return getattr(self, f'_generate_{language.lower()}_harness')(signature, parsed_info, engine)
        else:
            return self._generate_universal_harness(language, signature, parsed_info, engine)

    def _parse_function_signature(self, signature: str) -> dict:
        """Enhanced function signature parser supporting multiple languages"""
        try:
            # Language-specific parsing patterns
            patterns = {
                'go': r'func\s+(\w+)\s*\(([^)]*)\)',
                'rust': r'fn\s+(\w+)\s*\(([^)]*)\)',
                'java': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(([^)]*)\)',
                'javascript': r'(?:function\s+)?(\w+)\s*\(([^)]*)\)',
                'python': r'def\s+(\w+)\s*\(([^)]*)\)',
                'c': r'(?:\w+\s+)*(\w+)\s*\(([^)]*)\)',
                'cpp': r'(?:\w+\s+)*(\w+)\s*\(([^)]*)\)',
                'csharp': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(([^)]*)\)'
            }

            # Try language-specific patterns first
            for lang, pattern in patterns.items():
                match = re.search(pattern, signature, re.IGNORECASE)
                if match:
                    func_name = match.group(1)
                    param_text = match.group(2)
                    break
            else:
                # Fallback to generic pattern
                match = re.search(r'(\w+)\s*\(([^)]*)\)', signature)
                if match:
                    func_name = match.group(1)
                    param_text = match.group(2)
                else:
                    func_name = 'targetFunction'
                    param_text = ''

            # Parse parameters
            params = []
            if param_text.strip():
                param_list = [p.strip() for p in param_text.split(',') if p.strip()]
                for param in param_list:
                    if ' ' in param:
                        parts = param.split()
                        param_name = parts[-1].strip('*&')
                        param_type = ' '.join(parts[:-1])
                    else:
                        param_name = param.strip('*&')
                        param_type = 'unknown'
                    params.append({'name': param_name, 'type': param_type})

            return {
                'name': func_name,
                'parameters': params,
                'signature': signature,
                'param_count': len(params)
            }

        except Exception:
            return {
                'name': 'targetFunction',
                'parameters': [],
                'signature': signature,
                'param_count': 0
            }

    def _generate_go_harness(self, signature: str, parsed_info: dict, engine: str = 'go-fuzz') -> str:
        """Generate Go fuzzing harness"""
        func_name = parsed_info['name']
        params = parsed_info['parameters']

        if engine == 'native-go-fuzz':
            return self._generate_go_native_fuzz_harness(signature, parsed_info)
        
        # Default to go-fuzz style
        param_handling = self._generate_go_param_handling(params)
        func_call = self._generate_go_func_call(func_name, params)

        return f'''package fuzz

import (
    "testing"
    "encoding/binary"
    "math"
)

// Fuzz function for {func_name}
// Original signature: {signature}
func Fuzz{func_name}(f *testing.F) {{
    f.Fuzz(func(t *testing.T, data []byte) {{
        if len(data) < 4 {{
            return
        }}

        {param_handling}

        // Call the target function with fuzzer-generated data
        defer func() {{
            if r := recover(); r != nil {{
                // Log panics but don't fail the test
                t.Logf("Panic recovered: %v", r)
            }}
        }}()

        result := {func_call}
        _ = result  // Prevent unused variable error
    }})
}}

// Benchmark for performance testing
func Benchmark{func_name}(b *testing.B) {{
    data := []byte("benchmark test data")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {{
        {func_call}
    }}
}}
'''

    def _generate_rust_harness(self, signature: str, parsed_info: dict, engine: str = 'cargo-fuzz') -> str:
        """Generate Rust fuzzing harness"""
        func_name = parsed_info['name']
        
        return f'''#![no_main]
use libfuzzer_sys::fuzz_target;

// Cargo-fuzz harness for {func_name}
// Original signature: {signature}
// Run with: cargo fuzz run fuzz_{func_name}

fuzz_target!(|data: &[u8]| {{
    if data.is_empty() {{
        return;
    }}

    // Convert fuzzer data to string for text processing
    if let Ok(input) = std::str::from_utf8(data) {{
        // Call the target function
        let _ = {func_name}(input);
    }}

    // Also test with raw bytes
    let _ = {func_name}_bytes(data);
}});

// Template implementations - replace with actual target functions
fn {func_name}(input: &str) -> Result<String, Box<dyn std::error::Error>> {{
    if input.len() > 10000 {{
        return Err("Input too long".into());
    }}
    Ok(input.to_uppercase())
}}

fn {func_name}_bytes(data: &[u8]) -> Vec<u8> {{
    data.iter().map(|b| b.wrapping_add(1)).collect()
}}
'''

    def _generate_java_harness(self, signature: str, parsed_info: dict, engine: str = 'jazzer') -> str:
        """Generate Java fuzzing harness"""
        func_name = parsed_info['name']
        params = parsed_info['parameters']

        param_handling = self._generate_java_param_handling(params)
        func_call = self._generate_java_func_call(func_name, params)

        return f'''import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

/**
 * Jazzer fuzzing harness for {func_name}
 * Original signature: {signature}
 * 
 * Compile: javac -cp jazzer_api_deploy.jar {func_name}Fuzzer.java
 * Run: java -cp .:jazzer_api_deploy.jar -javaagent:jazzer_agent_deploy.jar {func_name}Fuzzer
 */
public class {func_name}Fuzzer {{

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        try {{
            if (data.remainingBytes() == 0) {{
                return;
            }}

            {param_handling}

            // Call the target function with fuzzer-generated data
            Object result = {func_call};

            // Validate result
            if (result instanceof String && ((String) result).length() > 100000) {{
                throw new FuzzerSecurityIssueMedium("Excessive output length detected");
            }}

        }} catch (OutOfMemoryError e) {{
            throw new FuzzerSecurityIssueHigh("Out of memory", e);
        }} catch (StackOverflowError e) {{
            throw new FuzzerSecurityIssueHigh("Stack overflow", e);
        }} catch (Exception e) {{
            // Expected exceptions are fine
            if (e.getMessage() != null && 
                (e.getMessage().contains("Invalid input") || 
                 e.getMessage().contains("Input too long"))) {{
                return;
            }}
            // Unexpected exceptions might be bugs
            throw new FuzzerSecurityIssueMedium("Unexpected exception", e);
        }}
    }}

    // Template method - replace with actual implementation
    private static Object {func_name}(String input) {{
        if (input == null || input.length() > 10000) {{
            throw new IllegalArgumentException("Invalid input");
        }}
        return input.toUpperCase();
    }}
}}
'''

    def _generate_python_harness(self, signature: str, parsed_info: dict, engine: str = 'atheris') -> str:
        """Generate Python fuzzing harness"""
        func_name = parsed_info['name']
        
        if engine == 'atheris':
            return f'''#!/usr/bin/env python3
"""
Atheris fuzzing harness for {func_name}
Original signature: {signature}

Install: pip install atheris
Run: python {func_name}_fuzzer.py
"""

import atheris
import sys

def TestOneInput(data):
    """Atheris fuzz target"""
    if len(data) == 0:
        return
    
    try:
        # Convert bytes to string
        fdp = atheris.FuzzedDataProvider(data)
        input_str = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
        
        # Call target function
        result = {func_name}(input_str)
        
        # Basic validation
        if isinstance(result, str) and len(result) > 100000:
            raise ValueError("Output too large")
            
    except (ValueError, TypeError, UnicodeError) as e:
        # Expected exceptions
        if "Invalid input" in str(e) or "Input too long" in str(e):
            return
        raise

def {func_name}(input_data):
    """Template target function - replace with actual implementation"""
    if not isinstance(input_data, str):
        raise TypeError("Expected string input")
    
    if len(input_data) > 10000:
        raise ValueError("Input too long")
    
    return input_data.upper()

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
'''
        else:
            return self._generate_pythonfuzz_harness(signature, parsed_info)

    def _generate_javascript_harness(self, signature: str, parsed_info: dict, engine: str = 'jazzer.js') -> str:
        """Generate JavaScript fuzzing harness"""
        func_name = parsed_info['name']
        
        return f'''/**
 * Jazzer.js fuzzing harness for {func_name}
 * Original signature: {signature}
 * 
 * Install: npm install @jazzer.js/core
 * Run: npx jazzer {func_name}_fuzzer.js
 */

const {{ FuzzedDataProvider }} = require('@jazzer.js/core');

function fuzz(data) {{
    if (data.length === 0) return;
    
    try {{
        const fdp = new FuzzedDataProvider(data);
        const input = fdp.consumeRemainingAsString();
        
        // Call target function
        const result = {func_name}(input);
        
        // Validate result
        if (typeof result === 'string' && result.length > 100000) {{
            throw new Error('Output too large');
        }}
        
    }} catch (error) {{
        // Filter expected errors
        if (error.message.includes('Invalid input') || 
            error.message.includes('Input too long')) {{
            return;
        }}
        throw error;
    }}
}}

// Template target function - replace with actual implementation
function {func_name}(input) {{
    if (typeof input !== 'string') {{
        throw new Error('Invalid input type');
    }}
    
    if (input.length > 10000) {{
        throw new Error('Input too long');
    }}
    
    return input.toUpperCase();
}}

module.exports = {{ fuzz }};
'''

    def _generate_universal_harness(self, language: str, signature: str, parsed_info: dict, engine: str) -> str:
        """Generate a universal harness template for unsupported languages"""
        func_name = parsed_info['name']
        
        return f'''/*
 * Universal Fuzzing Harness Template
 * Language: {language}
 * Engine: {engine}
 * Target Function: {func_name}
 * Original Signature: {signature}
 * 
 * This is a template that needs to be customized for your specific language and target.
 */

// TODO: Implement language-specific fuzzing harness
// 1. Set up the fuzzing framework for {language}
// 2. Parse fuzzer input data appropriately
// 3. Call the target function: {func_name}
// 4. Add appropriate error handling and validation
// 5. Configure build system integration

/*
 * Recommended fuzzing engines for {language}:
 * - Check OSS-Fuzz documentation for supported engines
 * - Consider libFuzzer for C/C++ compatible languages
 * - Look for language-specific fuzzing frameworks
 */

function fuzz_target(input_data) {{
    // Template implementation
    try {{
        // Parse input data
        var parsed_input = parse_input(input_data);
        
        // Call target function
        var result = {func_name}(parsed_input);
        
        // Validate result
        validate_result(result);
        
    }} catch (error) {{
        // Handle expected vs unexpected errors
        if (is_expected_error(error)) {{
            return; // Expected error, continue fuzzing
        }}
        throw error; // Unexpected error, report as potential bug
    }}
}}

// Helper functions to implement:
function parse_input(data) {{ /* TODO */ }}
function validate_result(result) {{ /* TODO */ }}
function is_expected_error(error) {{ /* TODO */ }}
function {func_name}(input) {{ /* TODO: Replace with actual target */ }}
'''

    def _generate_build_configs(self, language: str, engine: str, output_dir: Path, harness_metadata: List[Dict]) -> List[str]:
        """Generate build configuration files for the fuzzing harnesses"""
        build_files = []
        
        if language.lower() == 'go':
            # Generate go.mod if it doesn't exist
            go_mod_path = output_dir / 'go.mod'
            if not go_mod_path.exists():
                with open(go_mod_path, 'w') as f:
                    f.write(f'''module fuzz

go 1.19

require (
    // Add your dependencies here
)
''')
                build_files.append(str(go_mod_path))
                
        elif language.lower() == 'rust':
            # Generate Cargo.toml for cargo-fuzz
            cargo_toml_path = output_dir / 'Cargo.toml'
            if not cargo_toml_path.exists():
                with open(cargo_toml_path, 'w') as f:
                    f.write(f'''[package]
name = "fuzz-targets"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

# Add your target dependencies here

[[bin]]
name = "fuzz_target_1"
path = "fuzz_targets/fuzz_target_1.rs"
test = false
doc = false
''')
                build_files.append(str(cargo_toml_path))
                
        elif language.lower() == 'java':
            # Generate Maven pom.xml
            pom_path = output_dir / 'pom.xml'
            if not pom_path.exists():
                with open(pom_path, 'w') as f:
                    f.write(f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>fuzz-targets</artifactId>
    <version>1.0-SNAPSHOT</version>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>com.code-intelligence</groupId>
            <artifactId>jazzer-api</artifactId>
            <version>0.17.0</version>
        </dependency>
    </dependencies>
</project>
''')
                build_files.append(str(pom_path))
        
        # Generate a universal build script
        build_script_path = output_dir / 'build_fuzzers.sh'
        with open(build_script_path, 'w') as f:
            f.write(self._generate_build_script(language, engine, harness_metadata))
        build_files.append(str(build_script_path))
        
        return build_files

    def _generate_build_script(self, language: str, engine: str, harness_metadata: List[Dict]) -> str:
        """Generate a build script for the fuzzing harnesses"""
        return f'''#!/bin/bash
# Universal Fuzzer Build Script
# Language: {language}
# Engine: {engine}
# Generated harnesses: {len(harness_metadata)}

set -e

echo "Building fuzzing harnesses for {language} using {engine}..."

case "{language.lower()}" in
    "go")
        echo "Building Go fuzzers..."
        go mod tidy
        go test -c ./...
        ;;
    "rust")
        echo "Building Rust fuzzers..."
        cargo fuzz build
        ;;
    "java")
        echo "Building Java fuzzers..."
        mvn compile
        ;;
    "javascript"|"typescript")
        echo "Building JavaScript fuzzers..."
        npm install
        ;;
    "python")
        echo "Building Python fuzzers..."
        pip install -r requirements.txt || echo "No requirements.txt found"
        ;;
    *)
        echo "Build instructions for {language} need to be implemented"
        echo "Please refer to the fuzzing engine documentation for {engine}"
        ;;
esac

echo "Build completed successfully!"
echo "Generated harnesses:"
{chr(10).join([f'echo "  - {h["file"]}"' for h in harness_metadata])}
'''

    def _generate_go_param_handling(self, params: List[Dict]) -> str:
        """Generate Go parameter handling code"""
        if not params:
            return "        input := string(data[4:])"
        
        handling = "        // Parse parameters from fuzzer data\n"
        handling += "        offset := 0\n"
        
        for i, param in enumerate(params):
            if 'string' in param['type'].lower() or 'str' in param['type'].lower():
                handling += f"        {param['name']} := string(data[offset:])\n"
                handling += f"        offset = len(data) // Use remaining data\n"
            elif 'int' in param['type'].lower():
                handling += f"        if offset+4 > len(data) {{ return }}\n"
                handling += f"        {param['name']} := int(binary.LittleEndian.Uint32(data[offset:offset+4]))\n"
                handling += f"        offset += 4\n"
            else:
                handling += f"        {param['name']} := string(data[offset:]) // {param['type']}\n"
                handling += f"        offset = len(data)\n"
        
        return handling

    def _generate_go_func_call(self, func_name: str, params: List[Dict]) -> str:
        """Generate Go function call"""
        if params:
            param_names = [p['name'] for p in params]
            return f"{func_name}({', '.join(param_names)})"
        else:
            return f"{func_name}(input)"

    def _generate_java_param_handling(self, params: List[Dict]) -> str:
        """Generate Java parameter handling code"""
        if not params:
            return "            String input = data.consumeRemainingAsString();"
        
        handling = "            // Parse parameters from fuzzer data\n"
        for param in params:
            if 'string' in param['type'].lower():
                handling += f"            String {param['name']} = data.consumeString(data.remainingBytes() / {len(params)});\n"
            elif 'int' in param['type'].lower():
                handling += f"            int {param['name']} = data.consumeInt();\n"
            elif 'byte' in param['type'].lower():
                handling += f"            byte[] {param['name']} = data.consumeBytes(data.remainingBytes() / {len(params)});\n"
            else:
                handling += f"            String {param['name']} = data.consumeString(100); // {param['type']}\n"
        
        return handling

    def _generate_java_func_call(self, func_name: str, params: List[Dict]) -> str:
        """Generate Java function call"""
        if params:
            param_names = [p['name'] for p in params]
            return f"{func_name}({', '.join(param_names)})"
        else:
            return f"{func_name}(input)"

    def _get_harness_filename(self, language: str, signature: str, engine: str) -> str:
        """Generate filename for the harness based on language and engine"""
        func_name = self._parse_function_signature(signature)['name']
        
        filename_map = {
            'go': f"fuzz_{func_name}_test.go",
            'rust': f"fuzz_targets/fuzz_{func_name}.rs",
            'java': f"{func_name}Fuzzer.java",
            'javascript': f"{func_name}_fuzzer.js",
            'typescript': f"{func_name}_fuzzer.ts",
            'python': f"{func_name}_fuzzer.py",
            'c': f"{func_name}_fuzzer.c",
            'cpp': f"{func_name}_fuzzer.cpp",
            'csharp': f"{func_name}Fuzzer.cs",
            'ruby': f"{func_name}_fuzzer.rb",
            'php': f"{func_name}_fuzzer.php",
            'shell': f"{func_name}_fuzzer.sh"
        }
        
        return filename_map.get(language.lower(), f"{func_name}_fuzzer.{language.lower()}")
