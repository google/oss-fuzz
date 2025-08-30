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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_mcp_response.js
<<<<<<< HEAD
// Fuzzer for Gemini CLI MCP response parser
// Implements Fuchsia-style fuzz target function

import { locateUpstream } from './_upstream_locator.mjs';
import fuzzerRunner from './fuzzer_runner.js';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream MCP response parser module
 * @returns {Promise<Function>} The MCP response parser function
 */
async function initializeMCPResponseParser() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/mcp.js',
    'packages/cli/src/mcp.ts',
    'packages/cli/lib/mcp.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    throw new Error('UPSTREAM_MCP_NOT_FOUND: adjust import path to upstream MCP module');
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.parseMCPResponse || mod.default?.parseMCPResponse || mod.parse;
    if (!fn) {
      throw new Error('UPSTREAM_PARSE_NOT_FOUND: could not find parseMCPResponse function');
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    throw new Error(`Failed to load MCP response parser: ${error.message}`);
  }
}

/**
 * Fuzz target function for MCP response parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseMCPResponse = await initializeMCPResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as MCP response
    parseMCPResponse(input);

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
export async function FuzzMCPResponse(data) {
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

export function FuzzMCPResponse(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const p = locateUpstream([
    'packages/core/src/mcp.js',
    'packages/cli/src/mcp.js',
    'packages/core/lib/mcp.js'
  ]);
  if (!p) throw new Error('UPSTREAM_MCP_NOT_FOUND');
  return import(p).then(mod => {
    const decode = mod.decodeMCPResponse || mod.decodeResponse || mod.parseMCPResponse;
    if (!decode) throw new Error('UPSTREAM_MCP_DECODE_NOT_FOUND');
    try {
      decode(input);
    } catch (e) {
      if (e && e.name === 'TypeError') return;
      throw e;
    }
  });
}
>>>>>>> 6beb447382265fce1442b77fb11e5a90be556a20
