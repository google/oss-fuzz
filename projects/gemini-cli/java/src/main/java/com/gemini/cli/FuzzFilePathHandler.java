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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;

/**
 * Java implementation of file path handler fuzzer for cross-language validation
 * This mirrors the Go and JavaScript file path handler fuzzers
 */
public class FuzzFilePathHandler {

    /**
     * Main fuzz target method for Jazzer
     * @param data Fuzzed input data
     */
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Get fuzzed input as bytes
            byte[] input = data.consumeBytes(data.remainingBytes());

            // Test file path handling
            String inputStr = new String(input, java.nio.charset.StandardCharsets.UTF8);
            handleFilePath(inputStr);

            // Test with different encodings
            testPathEncodings(input);

        } catch (Exception e) {
            // Expected exceptions are fine, we just don't want crashes
        }
    }

    /**
     * Handle file path processing
     * @param pathInput File path input string
     */
    private static void handleFilePath(String pathInput) {
        if (pathInput == null || pathInput.trim().isEmpty()) {
            return;
        }

        try {
            // Create Path object
            Path path = Paths.get(pathInput);

            // Test path operations
            testPathOperations(path);

            // Validate path security
            validatePathSecurity(path);

        } catch (Exception e) {
            // Path creation failed, try alternative approaches
            handleInvalidPath(pathInput);
        }
    }

    /**
     * Test various path operations
     * @param path Path object to test
     */
    private static void testPathOperations(Path path) {
        // Test path normalization
        Path normalized = path.normalize();

        // Test path resolution
        Path resolved = path.resolve("test");

        // Test relative path conversion
        Path relativized = path.relativize(Paths.get("."));

        // Test path components
        int nameCount = path.getNameCount();
        if (nameCount > 0) {
            Path fileName = path.getFileName();
            Path parent = path.getParent();
            Path root = path.getRoot();
        }

        // Test path properties
        boolean isAbsolute = path.isAbsolute();
        boolean isRelative = !isAbsolute;

        // Test toString and other conversions
        String pathString = path.toString();
        java.net.URI uri = path.toUri();
    }

    /**
     * Validate path security
     * @param path Path to validate
     */
    private static void validatePathSecurity(Path path) {
        String pathStr = path.toString();

        // Check for path traversal attempts
        if (pathStr.contains("..")) {
            throw new SecurityException("Path traversal attempt detected: " + pathStr);
        }

        // Check for absolute path attempts that could escape intended directories
        if (pathStr.startsWith("/") || pathStr.startsWith("\\") || pathStr.contains(":\\")) {
            // This might be okay depending on context, but flag it for testing
            if (pathStr.contains("..") || pathStr.contains("../") || pathStr.contains("..\\")) {
                throw new SecurityException("Suspicious absolute path: " + pathStr);
            }
        }

        // Check for null bytes
        if (pathStr.contains("\0")) {
            throw new SecurityException("Null byte in path: " + pathStr);
        }

        // Check for very long paths that could cause issues
        if (pathStr.length() > 4096) {
            throw new SecurityException("Path too long: " + pathStr.length());
        }

        // Check for unusual characters that could cause issues
        for (char c : pathStr.toCharArray()) {
            if (c < 32 || c == 127) { // Control characters
                throw new SecurityException("Control character in path: " + (int)c);
            }
        }
    }

    /**
     * Handle invalid path input
     * @param pathInput Invalid path input
     */
    private static void handleInvalidPath(String pathInput) {
        // Try various alternative parsing approaches
        String[] separators = {"/", "\\", "\\\\", "//"};
        for (String separator : separators) {
            String[] parts = pathInput.split(separator);
            for (String part : parts) {
                validatePathComponent(part);
            }
        }
    }

    /**
     * Validate individual path component
     * @param component Path component to validate
     */
    private static void validatePathComponent(String component) {
        if (component.contains("..")) {
            throw new SecurityException("Path traversal in component: " + component);
        }

        if (component.contains("\0")) {
            throw new SecurityException("Null byte in component: " + component);
        }

        // Check for reserved names on Windows
        String upper = component.toUpperCase();
        if (upper.equals("CON") || upper.equals("PRN") || upper.equals("AUX") ||
            upper.equals("NUL") || (upper.length() == 4 && upper.startsWith("COM") && Character.isDigit(upper.charAt(3))) ||
            (upper.length() == 4 && upper.startsWith("LPT") && Character.isDigit(upper.charAt(3)))) {
            throw new SecurityException("Reserved name: " + component);
        }
    }

    /**
     * Test different path encodings
     * @param input Original input bytes
     */
    private static void testPathEncodings(byte[] input) {
        // Test with UTF-8
        String utf8Path = new String(input, java.nio.charset.StandardCharsets.UTF8);
        handleFilePath(utf8Path);

        // Test with UTF-16 (if enough bytes)
        if (input.length >= 2) {
            String utf16Path = new String(input, java.nio.charset.StandardCharsets.UTF16);
            handleFilePath(utf16Path);
        }

        // Test with ISO-8859-1
        String isoPath = new String(input, java.nio.charset.StandardCharsets.ISO_8859_1);
        handleFilePath(isoPath);
    }

    /**
     * Alternative fuzz target using consumeRemainingAsBytes
     * @param input Raw fuzzer input
     */
    public static void fuzzerTestOneInput(byte[] input) {
        fuzzerTestOneInput(FuzzedDataProvider.fromByteArray(input));
    }
}
