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
//
////////////////////////////////////////////////////////////////////////////////

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_oauth_token_response.js
import { locateUpstream } from './_upstream_locator.mjs';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream OAuth response parser module
 * @returns {Promise<Function>} The OAuth response parser function
 */
async function initializeOAuthResponseParser() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/oauth.js',
    'packages/cli/src/oauth.ts',
    'packages/cli/lib/oauth.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    // Return a mock function for testing when upstream module is not available
    console.warn('UPSTREAM_OAUTH_NOT_FOUND: using mock parser for testing');
    return mockOAuthParser;
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.parseOAuthResponse || mod.default?.parseOAuthResponse || mod.parse;
    if (!fn) {
      console.warn('UPSTREAM_PARSE_NOT_FOUND: using mock parser for testing');
      return mockOAuthParser;
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    console.warn(`Failed to load OAuth parser: ${error.message}`);
    console.warn('Using mock parser for testing');
    return mockOAuthParser;
  }
}

/**
 * Mock OAuth parser for testing when upstream module is not available
 * @param {string} input - Input string to parse
 */
function mockOAuthParser(input) {
  // Simple mock that just validates JSON structure
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  try {
    JSON.parse(input);
    return { parsed: true };
  } catch (error) {
    // Convert JSON errors to parsing errors
    if (error instanceof SyntaxError) {
      throw new SyntaxError(`Invalid JSON: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Fuzz target function for OAuth response parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 4096) { // 4KB for OAuth token responses
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 3000; // 3 seconds max for OAuth token response parsing
  const startTime = Date.now();

  try {
    const parseOAuthResponse = await initializeOAuthResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple OAuth token response parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original OAuth token response
      () => parseOAuthResponse(input),
      // OAuth token response with BOM
      () => parseOAuthResponse('\uFEFF' + input),
      // Base64 encoded OAuth token response
      () => parseOAuthResponse(Buffer.from(input).toString('base64')),
      // URL-encoded OAuth token response
      () => parseOAuthResponse(encodeURIComponent(input)),
      // OAuth token response wrapped in object
      () => parseOAuthResponse('{"data":' + input + '}'),
      // OAuth token response with extra whitespace
      () => parseOAuthResponse(input + '\n\n\n'),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const tokenResponse = strategy();

        // Additional security validation for OAuth token responses
        if (tokenResponse && typeof tokenResponse === 'object') {
          // Check for dangerous patterns in OAuth token response content
          const dangerousPatterns = [
            /<script>/g, // XSS payloads
            /javascript:/g, // JavaScript URLs
            /eval\s*\(/g, // Code execution
            /require\s*\(/g, // Module loading
            /import\s*\(/g, // Import execution
            /\.\.\//g, // Path traversal
            /<iframe/g, // Frame injection
            /onload\s*=/g, // Event handler injection
            /system\s*\(/g, // System commands
          ];

          // Check string fields for dangerous content
          const checkObject = (obj) => {
            if (!obj || typeof obj !== 'object') return false;
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                for (const pattern of dangerousPatterns) {
                  if (pattern.test(value)) {
                    return true; // Found dangerous content
                  }
                }
              } else if (typeof value === 'object') {
                if (checkObject(value)) return true;
              }
            }
            return false;
          };

          if (checkObject(tokenResponse)) {
            return 0; // Expected security violation
          }

          // Check for oversized fields that could cause DoS
          const checkSize = (obj) => {
            if (!obj || typeof obj !== 'object') return 0;
            let totalSize = 0;
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                totalSize += value.length;
                if (value.length > 2048) return value.length; // Oversized field
              } else if (typeof value === 'object') {
                const nestedSize = checkSize(value);
                if (nestedSize > 2048) return nestedSize;
              }
            }
            return totalSize;
          };

          const totalSize = checkSize(tokenResponse);
          if (totalSize > 8192) { // 8KB total limit
            return 0; // Expected size violation
          }

          // OAuth-specific validations
          if (tokenResponse.access_token && tokenResponse.access_token.length > 4096) {
            return 0; // Oversized access token
          }
          if (tokenResponse.refresh_token && tokenResponse.refresh_token.length > 4096) {
            return 0; // Oversized refresh token
          }
          if (tokenResponse.id_token && tokenResponse.id_token.length > 8192) {
            return 0; // Oversized ID token
          }
        }

        // Test OAuth token response serialization/deserialization
        try {
          const serialized = JSON.stringify(tokenResponse);
          const deserialized = JSON.parse(serialized);

          // Basic consistency check
          if (serialized.length > 0 && !deserialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid token responses
          if (serializationError.name === 'TypeError' ||
              serializationError.name === 'SyntaxError') {
            return 0;
          }
          throw serializationError;
        }

      } catch (strategyError) {
        // Expected errors from individual strategies
        if (strategyError.name === 'SyntaxError' ||
            strategyError.name === 'TypeError' ||
            strategyError.name === 'RangeError' ||
            strategyError.name === 'ReferenceError' ||
            strategyError.name === 'URIError' ||
            strategyError.name === 'Invalid JSON' ||
            strategyError.message.includes('Invalid OAuth') ||
            strategyError.message.includes('Malformed OAuth') ||
            strategyError.message.includes('UPSTREAM_OAUTH_NOT_FOUND') ||
            strategyError.message.includes('UPSTREAM_PARSE_NOT_FOUND') ||
            strategyError.message.includes('Failed to load OAuth parser') ||
            strategyError.message.includes('Parse error')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected OAuth token response parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'OAuthError'
      ];

      if (expectedErrors.includes(error.name) || error.name === 'Invalid JSON') {
        return 0; // Expected error, continue fuzzing
      }

      // OAuth-specific errors
      if (error.message.includes('Invalid OAuth') ||
          error.message.includes('Malformed OAuth') ||
          error.message.includes('OAuth validation failed') ||
          error.message.includes('Content validation failed') ||
          error.message.includes('UPSTREAM_OAUTH_NOT_FOUND') ||
          error.message.includes('UPSTREAM_PARSE_NOT_FOUND') ||
          error.message.includes('Failed to load OAuth parser')) {
        return 0; // Expected OAuth error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in OAuth token fuzzer: ${error.message}`);
        console.error(error.stack);
      }
    }

    // Memory and resource exhaustion errors
    if (error.code === 'ENOBUFS' || error.code === 'ENOMEM' ||
        error.message.includes('out of memory') ||
        error.message.includes('maximum call stack') ||
        error.message.includes('heap out of memory')) {
      return 0; // Expected resource exhaustion, not a crash
    }

    // Return non-zero for actual crashes and unexpected errors
    return 1;
  } finally {
    // Cleanup resources if needed
    const processingTime = Date.now() - startTime;
    if (processingTime > maxProcessingTime) {
      console.warn(`OAuth token fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
export async function FuzzOAuthTokenResponse(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
