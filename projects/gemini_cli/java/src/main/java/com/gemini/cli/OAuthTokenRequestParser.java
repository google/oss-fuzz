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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * OAuth Token Request Parser for Java fuzz testing
 * This mirrors the JavaScript implementation for cross-language validation
 */
public class OAuthTokenRequestParser {

    private static final Logger logger = LoggerFactory.getLogger(OAuthTokenRequestParser.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * OAuth Token Request data class
     */
    public static class OAuthTokenRequest {
        public String grant_type;
        public String code;
        public String redirect_uri;
        public String client_id;
        public String client_secret;
        public String refresh_token;
        public String scope;

        @Override
        public String toString() {
            return String.format("OAuthTokenRequest{grant_type='%s', client_id='%s'}",
                               grant_type, client_id);
        }
    }

    /**
     * OAuth Token Response data class
     */
    public static class OAuthTokenResponse {
        public String access_token;
        public String token_type;
        public Long expires_in;
        public String refresh_token;
        public String scope;

        @Override
        public String toString() {
            return String.format("OAuthTokenResponse{token_type='%s', expires_in=%d}",
                               token_type, expires_in);
        }
    }

    /**
     * Parse OAuth token request from byte array
     * @param data Input data to parse
     * @return Parsed OAuthTokenRequest or null if invalid
     */
    public static OAuthTokenRequest parseOAuthTokenRequest(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }

        String input = new String(data, StandardCharsets.UTF_8);
        return parseOAuthTokenRequest(input);
    }

    /**
     * Parse OAuth token request from string
     * @param input Input string to parse
     * @return Parsed OAuthTokenRequest or null if invalid
     */
    public static OAuthTokenRequest parseOAuthTokenRequest(String input) {
        if (input == null || input.trim().isEmpty()) {
            return null;
        }

        try {
            // Try to parse as JSON first
            JsonNode jsonNode = objectMapper.readTree(input);
            OAuthTokenRequest request = new OAuthTokenRequest();

            if (jsonNode.has("grant_type")) {
                request.grant_type = jsonNode.get("grant_type").asText();
            }
            if (jsonNode.has("code")) {
                request.code = jsonNode.get("code").asText();
            }
            if (jsonNode.has("redirect_uri")) {
                request.redirect_uri = jsonNode.get("redirect_uri").asText();
            }
            if (jsonNode.has("client_id")) {
                request.client_id = jsonNode.get("client_id").asText();
            }
            if (jsonNode.has("client_secret")) {
                request.client_secret = jsonNode.get("client_secret").asText();
            }
            if (jsonNode.has("refresh_token")) {
                request.refresh_token = jsonNode.get("refresh_token").asText();
            }
            if (jsonNode.has("scope")) {
                request.scope = jsonNode.get("scope").asText();
            }

            return request;
        } catch (IOException e) {
            logger.debug("Failed to parse as JSON: {}", e.getMessage());
        }

        try {
            // Try to parse as URL-encoded form data
            return parseUrlEncoded(input);
        } catch (Exception e) {
            logger.debug("Failed to parse as URL-encoded: {}", e.getMessage());
        }

        try {
            // Try to parse as Base64 encoded
            return parseBase64(input);
        } catch (Exception e) {
            logger.debug("Failed to parse as Base64: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Parse URL-encoded form data
     */
    private static OAuthTokenRequest parseUrlEncoded(String input) {
        OAuthTokenRequest request = new OAuthTokenRequest();
        String[] pairs = input.split("&");

        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                String key = java.net.URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                String value = java.net.URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);

                switch (key) {
                    case "grant_type":
                        request.grant_type = value;
                        break;
                    case "code":
                        request.code = value;
                        break;
                    case "redirect_uri":
                        request.redirect_uri = value;
                        break;
                    case "client_id":
                        request.client_id = value;
                        break;
                    case "client_secret":
                        request.client_secret = value;
                        break;
                    case "refresh_token":
                        request.refresh_token = value;
                        break;
                    case "scope":
                        request.scope = value;
                        break;
                }
            }
        }

        return request.grant_type != null ? request : null;
    }

    /**
     * Parse Base64 encoded data
     */
    private static OAuthTokenRequest parseBase64(String input) throws IOException {
        byte[] decoded = Base64.getDecoder().decode(input.trim());
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        return parseOAuthTokenRequest(decodedStr);
    }

    /**
     * Validate OAuth token request
     * @param request Request to validate
     * @return Validation result
     */
    public static ValidationResult validateOAuthTokenRequest(OAuthTokenRequest request) {
        ValidationResult result = new ValidationResult();

        if (request == null) {
            result.valid = false;
            result.errors.add("Request is null");
            return result;
        }

        if (request.grant_type == null || request.grant_type.trim().isEmpty()) {
            result.errors.add("grant_type is required");
        } else {
            // Check for valid grant types
            switch (request.grant_type) {
                case "authorization_code":
                    if (request.code == null || request.code.trim().isEmpty()) {
                        result.errors.add("code is required for authorization_code grant");
                    }
                    break;
                case "refresh_token":
                    if (request.refresh_token == null || request.refresh_token.trim().isEmpty()) {
                        result.errors.add("refresh_token is required for refresh_token grant");
                    }
                    break;
                case "client_credentials":
                    if (request.client_secret == null || request.client_secret.trim().isEmpty()) {
                        result.errors.add("client_secret is required for client_credentials grant");
                    }
                    break;
                default:
                    result.errors.add("Unsupported grant_type: " + request.grant_type);
            }
        }

        if (request.client_id == null || request.client_id.trim().isEmpty()) {
            result.errors.add("client_id is required");
        }

        if (request.redirect_uri != null && !isValidUrl(request.redirect_uri)) {
            result.errors.add("redirect_uri must be a valid URL");
        }

        result.valid = result.errors.isEmpty();
        return result;
    }

    /**
     * Simple URL validation
     */
    private static boolean isValidUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }

    /**
     * Validation result class
     */
    public static class ValidationResult {
        public boolean valid = true;
        public java.util.List<String> errors = new java.util.ArrayList<>();

        @Override
        public String toString() {
            return String.format("ValidationResult{valid=%s, errors=%s}", valid, errors);
        }
    }
}
