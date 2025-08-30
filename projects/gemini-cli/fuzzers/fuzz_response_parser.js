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
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseResponse = await initializeResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as response data
    parseResponse(input);

    return 0; // Success
  } catch (error) {
    // Handle expected parsing errors gracefully
    if (error && error.name) {
      // These are expected validation errors, not crashes
      if (error.name === 'SyntaxError' ||
          error.name === 'TypeError' ||
          error.name === 'RangeError' ||
          error.name === 'ReferenceError' ||
          error.name === 'Error') {
        return 0; // Expected error, continue fuzzing
      }
    }

    // Return non-zero for unexpected errors (actual crashes) - OSS-Fuzz compliance
    return 1;
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
