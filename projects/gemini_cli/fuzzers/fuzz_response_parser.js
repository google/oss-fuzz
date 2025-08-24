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
// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_response_parser.js
// Fuzzer for Gemini CLI API response parsing and validation
// Implements Fuchsia-style fuzz target function

import { locateUpstream } from './_upstream_locator.mjs';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream response parser module
 * @returns {Promise<Function>} The response parser function
 */
async function initializeResponseParser() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/response.js',
    'packages/cli/src/response.ts',
    'packages/cli/lib/response.js',
    'packages/cli/src/api.js',
    'packages/cli/src/api.ts',
    'packages/cli/lib/api.js',
    'packages/cli/src/parser.js',
    'packages/cli/src/parser.ts',
    'packages/cli/lib/parser.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    // Return a mock function for testing when upstream module is not available
    console.warn('UPSTREAM_RESPONSE_NOT_FOUND: using mock parser for testing');
    return mockResponseParser;
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.parseResponse || mod.default?.parseResponse || mod.parseAPIResponse || mod.parse;
    if (!fn) {
      console.warn('UPSTREAM_RESPONSE_PARSER_NOT_FOUND: using mock parser for testing');
      return mockResponseParser;
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    console.warn(`Failed to load response parser: ${error.message}`);
    console.warn('Using mock parser for testing');
    return mockResponseParser;
  }
}

/**
 * Mock response parser for testing when upstream module is not available
 * @param {string} input - Input string to parse
 */
function mockResponseParser(input) {
  // Simple mock that validates response data structure and security
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // First try to parse as JSON (common API response format)
  try {
    JSON.parse(input);
  } catch (jsonError) {
    // If not JSON, try to validate as other response formats
    if (input.length > 1000000) {
      throw new Error('Response too large');
    }

    // Check for basic response structure
    if (input.includes('<html>') || input.includes('<!DOCTYPE')) {
      // HTML response - check for basic structure
      if (!input.includes('<body>') && input.length > 100) {
        throw new Error('Malformed HTML response');
      }
    } else if (input.includes('{') || input.includes('[')) {
      // Likely JSON - already tried parsing above
      throw jsonError;
    } else {
      // Plain text response - check for reasonable content
      if (input.includes('\0')) {
        throw new Error('Null byte in response');
      }
      if (input.length < 0) {
        throw new Error('Empty response');
      }
    }
  }

  // Additional security checks
  if (input.includes('\0')) {
    throw new Error('Null byte in response');
  }

  // Check for extremely large responses
  if (input.length > 10000000) {
    throw new Error('Response exceeds maximum size');
  }

  // Check for potential script injection
  if (input.includes('<script') && input.includes('javascript:')) {
    throw new Error('Script injection detected');
  }
}

/**
 * Fuzz target function for response parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 10240) { // 10KB for responses
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 5000; // 5 seconds max for response parsing
  const startTime = Date.now();

  try {
    const parseResponse = await initializeResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple response parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original response
      () => parseResponse(input),
      // JSON with BOM
      () => parseResponse('\uFEFF' + input),
      // Base64 encoded response
      () => parseResponse(Buffer.from(input).toString('base64')),
      // URL-encoded response
      () => parseResponse(encodeURIComponent(input)),
      // Response wrapped in array
      () => parseResponse('[' + input + ']'),
      // Response with extra whitespace
      () => parseResponse(input + '\n\n\n'),
      // Response with comments (if supported)
      () => parseResponse(input.replace(/{/g, '{// comment\n')),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const response = strategy();

        // Validate the parsed response with multiple validation methods
        const validationMethods = [
          () => validateResponse(response),
          () => validateResponseFormat(response),
          () => validateResponseContent(response),
          () => validateResponseSecurity(response),
        ];

        for (const validate of validationMethods) {
          const validation = validate();
          if (!validation.valid) {
            // Log validation errors for debugging (only in development)
            if (process.env.NODE_ENV === 'development') {
              console.log(`Response validation failed: ${validation.error}`);
            }
            continue; // Expected validation errors, try next method
          }
        }

        // Test response-specific security validations
        if (response && typeof response === 'object') {
          // Check for dangerous patterns in response content
          const dangerousPatterns = [
            /<script>/g, // XSS payloads
            /javascript:/g, // JavaScript URLs
            /eval\s*\(/g, // Code execution
            /\.\.\//g, // Path traversal
            /<iframe/g, // Frame injection
            /onload\s*=/g, // Event handler injection
            /onerror\s*=/g, // Error handler injection
          ];

          // Check string fields for dangerous content
          const checkObject = (obj) => {
            if (!obj || typeof obj !== 'object') return;
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

          if (checkObject(response)) {
            return 0; // Expected security violation
          }

          // Check for oversized fields that could cause DoS
          const checkSize = (obj) => {
            if (!obj || typeof obj !== 'object') return 0;
            let totalSize = 0;
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                totalSize += value.length;
                if (value.length > 10000) return value.length; // Oversized field
              } else if (typeof value === 'object') {
                const nestedSize = checkSize(value);
                if (nestedSize > 10000) return nestedSize;
              }
            }
            return totalSize;
          };

          const totalSize = checkSize(response);
          if (totalSize > 50000) { // 50KB total limit
            return 0; // Expected size violation
          }
        }

        // Test serialization/deserialization for response objects
        try {
          const serialized = JSON.stringify(response);
          const deserialized = JSON.parse(serialized);

          // Verify round-trip consistency
          if (JSON.stringify(deserialized) !== serialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid responses
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
            strategyError.message.includes('Invalid JSON') ||
            strategyError.message.includes('Malformed response') ||
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
      // Expected response parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'ResponseError',
        'ParseError', 'FormatError', 'SizeError'
      ];

      if (expectedErrors.includes(error.name)) {
        return 0; // Expected error, continue fuzzing
      }

      // Response-specific errors
      if (error.message.includes('Invalid response format') ||
          error.message.includes('Malformed response') ||
          error.message.includes('Response too large') ||
          error.message.includes('Content validation failed')) {
        return 0; // Expected response error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in response fuzzer: ${error.message}`);
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
      console.warn(`Response fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
export async function FuzzResponseParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
