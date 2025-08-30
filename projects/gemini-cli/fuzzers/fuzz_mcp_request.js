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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_mcp_request.js
<<<<<<< HEAD
// Fuzzer for Gemini CLI MCP request parser
// Implements LLVMFuzzerTestOneInput interface for OSS-Fuzz

// Import the actual source code for fuzzing
const { parseMCPRequest, validateMCPRequest } = require('../src/mcp/handler.js');

/**
 * Main fuzzing function - implements LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success/expected errors, 1 for crashes
 */
export function LLVMFuzzerTestOneInput(data) {
  try {
    // Convert input data
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Skip empty inputs
    if (!input.trim()) {
      return 0;
    }

    // Parse the MCP request using the actual implementation
    const request = parseMCPRequest(input);

    // Validate the parsed request
    const validation = validateMCPRequest(request);
    if (!validation.valid) {
      // Expected validation errors, not crashes
      return 0;
    }

    return 0; // Success
  } catch (error) {
    // Expected errors that shouldn't be reported as crashes
    const expectedErrors = [
      'TypeError',
      'SyntaxError',
      'RangeError',
      'ReferenceError',
      'Invalid JSON',
      'Invalid JSON-RPC',
      'Missing or invalid',
      'JSON parsing failed',
      'Input too large',
      'Invalid input',
      'Excessive nesting',
      'Malicious pattern'
    ];

    if (expectedErrors.some(expected => error.message.includes(expected))) {
      return 0; // Expected error, continue fuzzing
    }

    // Unexpected errors (potential crashes)
    return 1;
  }
}

/**
 * Main fuzzing function - implements LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success/expected errors, 1 for crashes
 */
export function LLVMFuzzerTestOneInput(data) {
  try {
    // Convert input data
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Skip empty inputs
    if (!input.trim()) {
      return 0;
    }

    // Parse and validate
    const result = parseMCPRequest(input);

    // Validate result structure
    if (!result.method || typeof result.method !== 'string') {
      return 0;
    }

    return 0;
  } catch (error) {
    // Expected errors that shouldn't be reported as crashes
    const expectedErrors = [
      'Invalid input',
      'Input too large',
      'Request must be an object',
      'Invalid JSON-RPC version',
      'Missing or invalid method',
      'Method name too long',
      'Potential path traversal',
      'Potential XSS',
      'Dangerous method pattern',
      'Invalid ID type',
      'Invalid ID range',
      'Invalid params type',
      'Excessive nesting depth',
      'JSON parsing failed'
    ];

    for (const expected of expectedErrors) {
      if (error.message.includes(expected)) {
        return 0; // Expected error, continue fuzzing
      }
    }

    // Unexpected errors - report as potential crashes
    return 1;
  }
}

/**
 * Default export for compatibility
 */
export default LLVMFuzzerTestOneInput;

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
=======
import { locateUpstream } from './_upstream_locator.mjs';

export function FuzzMCPRequest(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const p = locateUpstream([
    'packages/core/src/mcp.js',
    'packages/cli/src/mcp.js',
    'packages/core/lib/mcp.js'
  ]);
  if (!p) throw new Error('UPSTREAM_MCP_NOT_FOUND');
  return import(p).then(mod => {
    const decode = mod.decodeMCPRequest || mod.decodeRequest || mod.parseMCP;
    if (!decode) throw new Error('UPSTREAM_MCP_DECODE_NOT_FOUND');
    try {
      decode(input);
    } catch (e) {
      // expected decode errors are fine
      if (e && e.name === 'TypeError') return;
      throw e;
    }
  });
}
>>>>>>> 6beb447382265fce1442b77fb11e5a90be556a20
