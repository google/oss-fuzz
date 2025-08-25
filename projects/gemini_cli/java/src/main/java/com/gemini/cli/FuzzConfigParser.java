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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Java implementation of configuration parser fuzzer for cross-language validation
 * This mirrors the Go and JavaScript configuration parser fuzzers
 */
public class FuzzConfigParser {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Main fuzz target method for Jazzer
     * @param data Fuzzed input data
     */
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Get fuzzed input as bytes
            byte[] input = data.consumeBytes(data.remainingBytes());

            // Test JSON configuration parsing
            String inputStr = new String(input, java.nio.charset.StandardCharsets.UTF8);
            parseConfiguration(inputStr);

            // Test with different input formats
            testInputVariations(input);

        } catch (Exception e) {
            // Expected exceptions are fine, we just don't want crashes
        }
    }

    /**
     * Parse configuration from various formats
     * @param input Configuration input string
     */
    private static void parseConfiguration(String input) {
        if (input == null || input.trim().isEmpty()) {
            return;
        }

        try {
            // Try parsing as JSON
            JsonNode jsonNode = objectMapper.readTree(input);
            validateConfiguration(jsonNode);

        } catch (Exception e) {
            // If JSON parsing fails, try other formats
            parseAsProperties(input);
        }
    }

    /**
     * Validate parsed JSON configuration
     * @param config JSON configuration node
     */
    private static void validateConfiguration(JsonNode config) {
        if (config == null) {
            return;
        }

        // Validate common configuration fields
        validateConfigField(config, "model");
        validateConfigField(config, "temperature");
        validateConfigField(config, "maxTokens");
        validateConfigField(config, "apiKey");
        validateConfigField(config, "endpoint");
        validateConfigField(config, "timeout");

        // Check for nested objects
        if (config.has("auth")) {
            JsonNode auth = config.get("auth");
            validateConfigField(auth, "token");
            validateConfigField(auth, "refreshToken");
        }

        if (config.has("proxy")) {
            JsonNode proxy = config.get("proxy");
            validateConfigField(proxy, "host");
            validateConfigField(proxy, "port");
        }
    }

    /**
     * Validate individual configuration field
     * @param node JSON node containing the field
     * @param fieldName Field name to validate
     */
    private static void validateConfigField(JsonNode node, String fieldName) {
        if (node.has(fieldName)) {
            JsonNode field = node.get(fieldName);
            String value = field.asText();

            // Check for potentially dangerous values
            if (value.contains("..") || value.contains("../") || value.contains("..\\")) {
                throw new SecurityException("Path traversal attempt in " + fieldName);
            }

            if (value.contains("<script") || value.contains("javascript:")) {
                throw new SecurityException("Script injection attempt in " + fieldName);
            }
        }
    }

    /**
     * Parse as properties format (key=value)
     * @param input Properties format string
     */
    private static void parseAsProperties(String input) {
        String[] lines = input.split("\\n");
        java.util.Properties props = new java.util.Properties();

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split("=", 2);
            if (parts.length == 2) {
                String key = parts[0].trim();
                String value = parts[1].trim();

                // Validate property values
                validatePropertyValue(key, value);
                props.setProperty(key, value);
            }
        }
    }

    /**
     * Validate property key-value pair
     * @param key Property key
     * @param value Property value
     */
    private static void validatePropertyValue(String key, String value) {
        // Check for dangerous patterns in values
        if (value.contains("..") || value.contains("/") || value.contains("\\")) {
            if (!key.equals("path") && !key.equals("directory")) {
                throw new SecurityException("Suspicious path in property: " + key);
            }
        }
    }

    /**
     * Test various input variations
     * @param input Original input bytes
     */
    private static void testInputVariations(byte[] input) {
        // Test with truncated input
        if (input.length > 1) {
            byte[] truncated = new byte[input.length / 2];
            System.arraycopy(input, 0, truncated, 0, truncated.length);
            parseConfiguration(new String(truncated, java.nio.charset.StandardCharsets.UTF8));
        }

        // Test with modified input
        if (input.length > 0) {
            byte[] modified = input.clone();
            for (int i = 0; i < modified.length && i < 10; i++) {
                modified[i] ^= 0xFF; // Flip bits
            }
            parseConfiguration(new String(modified, java.nio.charset.StandardCharsets.UTF8));
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
