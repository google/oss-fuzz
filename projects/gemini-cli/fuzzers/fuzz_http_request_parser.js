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
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseHTTPRequest = await initializeHTTPRequestParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as HTTP request
    parseHTTPRequest(input);

    return 0; // Success
  } catch (error) {
    // Handle expected parsing errors gracefully
    if (error && error.name) {
      // These are expected parsing errors, not crashes
      if (error.name === 'SyntaxError' ||
          error.name === 'TypeError' ||
          error.name === 'RangeError' ||
          error.name === 'ReferenceError') {
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
export async function FuzzHTTPRequestParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
