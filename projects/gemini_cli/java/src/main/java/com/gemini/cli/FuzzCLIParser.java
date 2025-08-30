// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.gemini.cli;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Java implementation of CLI parser fuzzer for cross-language validation
 * This mirrors the Go and JavaScript CLI parser fuzzers
 */
public class FuzzCLIParser {

    /**
     * Main fuzz target method for Jazzer
     * @param data Fuzzed input data
     */
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Get fuzzed input as bytes
            byte[] input = data.consumeBytes(data.remainingBytes());

            // Test CLI argument parsing
            String inputStr = new String(input, java.nio.charset.StandardCharsets.UTF8);
            parseCLIArguments(inputStr);

            // Test with different encoding
            if (input.length > 1) {
                String utf16Str = new String(input, java.nio.charset.StandardCharsets.UTF16);
                parseCLIArguments(utf16Str);
            }

        } catch (Exception e) {
            // Expected exceptions are fine, we just don't want crashes
        }
    }

    /**
     * Parse CLI arguments (simplified implementation)
     * @param input CLI input string
     */
    private static void parseCLIArguments(String input) {
        if (input == null || input.trim().isEmpty()) {
            return;
        }

        // Basic argument parsing logic
        String[] parts = input.split("\\s+");
        String currentArg = null;
        java.util.List<String> args = new java.util.ArrayList<>();

        for (String part : parts) {
            if (part.startsWith("--")) {
                currentArg = part;
                args.add(part);
            } else if (part.startsWith("-")) {
                currentArg = part;
                args.add(part);
            } else if (currentArg != null) {
                // Value for previous argument
                args.add(part);
                currentArg = null;
            } else {
                // Positional argument
                args.add(part);
            }
        }

        // Validate parsed arguments
        validateArguments(args);
    }

    /**
     * Validate parsed CLI arguments
     * @param args List of arguments to validate
     */
    private static void validateArguments(java.util.List<String> args) {
        for (String arg : args) {
            // Check for dangerous patterns
            if (arg.contains("..") || arg.contains("/") || arg.contains("\\")) {
                throw new SecurityException("Potentially dangerous path detected");
            }

            // Check for command injection patterns
            if (arg.contains(";") || arg.contains("&&") || arg.contains("||")) {
                throw new SecurityException("Command injection pattern detected");
            }

            // Check for null bytes
            if (arg.contains("\0")) {
                throw new SecurityException("Null byte detected");
            }
        }
    }

    /**
     * Alternative fuzz target using consumeRemainingAsBytes
     * @param input Raw fuzzer input
     */
    public static void fuzzerTestOneInput(byte[] input) {
        fuzzerTestOneInput(FuzzedDataProvider.fromByteArray(input));
    }
}
