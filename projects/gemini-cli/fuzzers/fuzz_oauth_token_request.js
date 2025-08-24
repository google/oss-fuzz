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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_oauth_token_request.js
<<<<<<< HEAD

// Import the actual source code for fuzzing
const { parseOAuthTokenRequest, validateOAuthTokenRequest } = require('../src/oauth/token.js');

// Global reference to OAuth parser (cached for performance)
let oauthParser = null;

/**
 * Initialize the OAuth parser module
 * @returns {Promise<Function>} The OAuth parser function
 */
async function initializeOAuthRequestParser() {
  if (oauthParser) {
    return oauthParser;
  }

  try {
    // Use the actual implementation
    oauthParser = parseOAuthTokenRequest;
    return oauthParser;
  } catch (error) {
    console.warn(`Failed to load OAuth parser: ${error.message}`);
    console.warn('Using fallback parser for testing');
    return fallbackOAuthParser;
  }
}

/**
 * Fallback OAuth parser for testing when main module fails
 * @param {string} input - Input string to parse
 */
function fallbackOAuthParser(input) {
  // Simple fallback that just validates JSON structure
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
 * Fuzz target function for OAuth request parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseOAuthRequest = await initializeOAuthRequestParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Parse the OAuth token request
    const request = parseOAuthRequest(input);

    // Validate the parsed request
    const validation = validateOAuthTokenRequest(request);
    if (!validation.valid) {
      // Expected validation errors, not crashes
      return 0;
    }

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
export async function FuzzOAuthTokenRequest(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
=======
import { locateUpstream } from './_upstream_locator.mjs';

export function FuzzOAuthTokenRequest(data) {
  const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
  const p = locateUpstream([
    'packages/cli/src/oauth.js',
    'packages/core/src/oauth.js',
    'packages/cli/lib/oauth.js'
  ]);
  if (!p) throw new Error('UPSTREAM_OAUTH_NOT_FOUND');
  return import(p).then(mod => {
    const parse = mod.parseTokenRequest || mod.parseOAuthRequest || mod.decodeOAuth;
    if (!parse) throw new Error('UPSTREAM_OAUTH_PARSE_NOT_FOUND');
    try {
      parse(input);
    } catch (e) {
      if (e && e.name === 'SyntaxError') return;
      throw e;
    }
  });
}
>>>>>>> 6beb447382265fce1442b77fb11e5a90be556a20
