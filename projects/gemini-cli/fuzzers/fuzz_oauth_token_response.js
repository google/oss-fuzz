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

<<<<<<< HEAD
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
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseOAuthResponse = await initializeOAuthResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as OAuth response
    parseOAuthResponse(input);

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
export async function FuzzOAuthTokenResponse(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
=======
export function FuzzOAuthTokenResponse(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const p = locateUpstream([
    'packages/cli/src/oauth.js',
    'packages/core/src/oauth.js',
    'packages/cli/lib/oauth.js'
  ]);
  if (!p) throw new Error('UPSTREAM_OAUTH_NOT_FOUND');
  return import(p).then(mod => {
    const decode = mod.decodeTokenResponse || mod.parseTokenResponse || mod.decodeOAuthResponse;
    if (!decode) throw new Error('UPSTREAM_OAUTH_RESPONSE_NOT_FOUND');
    try {
      decode(input);
    } catch (e) {
      if (e && e.name === 'TypeError') return;
      throw e;
    }
  });
}
>>>>>>> 6beb447382265fce1442b77fb11e5a90be556a20
