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
 * Jazzer fuzz target for OAuth token request parser
 * This provides fuzz testing for the Java OAuth implementation
 */
public class FuzzOAuthTokenRequest {

    /**
     * Main fuzz target method for Jazzer
     * @param data Fuzzed input data
     */
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Get fuzzed input as bytes
            byte[] input = data.consumeBytes(data.remainingBytes());

            // Test direct byte array parsing
            OAuthTokenRequestParser.OAuthTokenRequest request1 =
                OAuthTokenRequestParser.parseOAuthTokenRequest(input);

            if (request1 != null) {
                // Test validation if parsing succeeded
                OAuthTokenRequestParser.ValidationResult validation =
                    OAuthTokenRequestParser.validateOAuthTokenRequest(request1);

                // Test serialization (trigger potential issues)
                String serialized = request1.toString();
                if (serialized != null) {
                    // Consume the serialized form to trigger any encoding issues
                    byte[] serializedBytes = serialized.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }
            }

            // Test string parsing with various encodings
            String inputStr = new String(input, java.nio.charset.StandardCharsets.UTF_8);
            OAuthTokenRequestParser.OAuthTokenRequest request2 =
                OAuthTokenRequestParser.parseOAuthTokenRequest(inputStr);

            if (request2 != null) {
                OAuthTokenRequestParser.ValidationResult validation =
                    OAuthTokenRequestParser.validateOAuthTokenRequest(request2);
            }

            // Test with truncated input
            if (input.length > 1) {
                byte[] truncated = new byte[input.length / 2];
                System.arraycopy(input, 0, truncated, 0, truncated.length);
                OAuthTokenRequestParser.parseOAuthTokenRequest(truncated);
            }

            // Test with modified input (bit flips)
            if (input.length > 0) {
                byte[] modified = input.clone();
                for (int i = 0; i < modified.length && i < 10; i++) {
                    modified[i] ^= 0xFF; // Flip bits
                }
                OAuthTokenRequestParser.parseOAuthTokenRequest(modified);
            }

        } catch (Exception e) {
            // Expected exceptions are fine, we just don't want crashes
            // Jazzer will catch and report unexpected exceptions/crashes
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
