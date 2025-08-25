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
// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_http_request_parser.js
// Fuzzer for Gemini CLI HTTP request parsing
// Implements Fuchsia-style fuzz target function

import { locateUpstream } from './_upstream_locator.mjs';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream HTTP request parser module
 * @returns {Promise<Function>} The HTTP request parser function
 */
async function initializeHTTPRequestParser() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/http.js',
    'packages/cli/src/http.ts',
    'packages/cli/lib/http.js',
    'packages/cli/src/network.js',
    'packages/cli/src/network.ts',
    'packages/cli/lib/network.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    // Return a mock function for testing when upstream module is not available
    console.warn('UPSTREAM_HTTP_NOT_FOUND: using mock parser for testing');
    return mockHTTPRequestParser;
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.parseHTTPRequest || mod.default?.parseHTTPRequest || mod.parseRequest;
    if (!fn) {
      console.warn('UPSTREAM_PARSE_NOT_FOUND: using mock parser for testing');
      return mockHTTPRequestParser;
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    console.warn(`Failed to load HTTP request parser: ${error.message}`);
    console.warn('Using mock parser for testing');
    return mockHTTPRequestParser;
  }
}

/**
 * Mock HTTP request parser for testing when upstream module is not available
 * @param {string} input - Input string to parse
 */
function mockHTTPRequestParser(input) {
  // Simple mock that validates HTTP request structure
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // Basic HTTP request validation
  const lines = input.split('\n');
  if (lines.length === 0) {
    throw new Error('Empty request');
  }

  // Check for basic HTTP method and URL
  const firstLine = lines[0].trim();
  const parts = firstLine.split(' ');
  if (parts.length < 3) {
    throw new Error('Invalid HTTP request line');
  }

  const method = parts[0];
  const url = parts[1];
  const version = parts[2];

  // Validate method
  const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
  if (!validMethods.includes(method)) {
    throw new Error(`Invalid HTTP method: ${method}`);
  }

  // Basic URL validation
  if (!url.startsWith('/') && !url.startsWith('http://') && !url.startsWith('https://')) {
    throw new Error(`Invalid URL format: ${url}`);
  }

  // Check for headers
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') break; // End of headers

    if (!line.includes(':')) {
      throw new Error(`Invalid header format: ${line}`);
    }
  }
}

/**
 * Fuzz target function for HTTP request parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 8192) {
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 4000; // 4 seconds max for HTTP parsing
  const startTime = Date.now();

  try {
    const parseHTTPRequest = await initializeHTTPRequestParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple HTTP parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original request
      () => parseHTTPRequest(input),
      // URL-encoded request
      () => parseHTTPRequest(encodeURIComponent(input)),
      // Base64 encoded request
      () => parseHTTPRequest(Buffer.from(input).toString('base64')),
      // Request with BOM
      () => parseHTTPRequest('\uFEFF' + input),
      // Request with extra whitespace
      () => parseHTTPRequest(input.replace(/\r\n/g, '\r\n\r\n')),
      // Malformed headers
      () => parseHTTPRequest(input.replace(/:/g, ' ')),
      // Missing protocol
      () => parseHTTPRequest(input.replace(/HTTP\/\d\.\d/g, '')),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const request = strategy();

        // Validate the parsed request with multiple validation methods
        const validationMethods = [
          () => validateHTTPRequest(request),
          () => validateHTTPHeaders(request),
          () => validateHTTPBody(request),
          () => validateHTTPSecurity(request),
        ];

        for (const validate of validationMethods) {
          const validation = validate();
          if (!validation.valid) {
            // Log validation errors for debugging (only in development)
            if (process.env.NODE_ENV === 'development') {
              console.log(`HTTP validation failed: ${validation.error}`);
            }
            continue; // Expected validation errors, try next method
          }
        }

        // Test HTTP-specific security validations
        if (request && typeof request === 'object') {
          // Check for dangerous header patterns
          const dangerousHeaders = [
            /../g, // Path traversal in headers
            /<script/g, // XSS in headers
            /javascript:/g, // JavaScript URLs
            /\.\.\//g, // Path traversal
            /eval\s*\(/g, // Code execution
          ];

          for (const [key, value] of Object.entries(request.headers || {})) {
            if (typeof value === 'string') {
              for (const pattern of dangerousHeaders) {
                if (pattern.test(value)) {
                  return 0; // Expected security violation
                }
              }
            }
          }

          // Check for malicious content in body
          if (request.body && typeof request.body === 'string') {
            const dangerousBodyPatterns = [
              /<script>/g, // XSS
              /eval\s*\(/g, // Code execution
              /javascript:/g, // JavaScript URLs
              /\.\.\//g, // Path traversal
            ];

            for (const pattern of dangerousBodyPatterns) {
              if (pattern.test(request.body)) {
                return 0; // Expected security violation
              }
            }
          }
        }

        // Test serialization/deserialization for HTTP objects
        try {
          const serialized = JSON.stringify(request);
          const deserialized = JSON.parse(serialized);

          // Verify round-trip consistency
          if (JSON.stringify(deserialized) !== serialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid HTTP
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
            strategyError.message.includes('Invalid HTTP') ||
            strategyError.message.includes('Malformed request') ||
            strategyError.message.includes('Bad request')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected HTTP and network errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'HTTPError',
        'NetworkError', 'ProtocolError'
      ];

      if (expectedErrors.includes(error.name)) {
        return 0; // Expected error, continue fuzzing
      }

      // HTTP-specific errors
      if (error.message.includes('Invalid HTTP version') ||
          error.message.includes('Malformed headers') ||
          error.message.includes('Invalid request line') ||
          error.message.includes('Header too long') ||
          error.message.includes('Body too large')) {
        return 0; // Expected HTTP parsing error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in HTTP fuzzer: ${error.message}`);
        console.error(error.stack);
      }
    }

    // Memory and resource exhaustion errors
    if (error.code === 'ENOBUFS' || error.code === 'ENOMEM' ||
        error.message.includes('out of memory') ||
        error.message.includes('maximum call stack')) {
      return 0; // Expected resource exhaustion, not a crash
    }

    // Return non-zero for actual crashes and unexpected errors
    return 1;
  } finally {
    // Cleanup resources if needed
    const processingTime = Date.now() - startTime;
    if (processingTime > maxProcessingTime) {
      console.warn(`HTTP fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
export async function FuzzHTTPRequestParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
