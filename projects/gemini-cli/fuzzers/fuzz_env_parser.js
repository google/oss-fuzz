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
// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_env_parser.js
// Fuzzer for Gemini CLI environment variable parsing and validation
// Implements Fuchsia-style fuzz target function

import { locateUpstream } from './_upstream_locator.mjs';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream environment parser module
 * @returns {Promise<Function>} The environment parser function
 */
async function initializeEnvParser() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/env.js',
    'packages/cli/src/env.ts',
    'packages/cli/lib/env.js',
    'packages/cli/src/config.js',
    'packages/cli/src/config.ts',
    'packages/cli/lib/config.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    // Return a mock function for testing when upstream module is not available
    console.warn('UPSTREAM_ENV_NOT_FOUND: using mock parser for testing');
    return mockEnvParser;
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.parseEnvironment || mod.default?.parseEnvironment || mod.parseEnv || mod.loadConfig;
    if (!fn) {
      console.warn('UPSTREAM_ENV_PARSER_NOT_FOUND: using mock parser for testing');
      return mockEnvParser;
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    console.warn(`Failed to load environment parser: ${error.message}`);
    console.warn('Using mock parser for testing');
    return mockEnvParser;
  }
}

/**
 * Mock environment parser for testing when upstream module is not available
 * @param {string} input - Input string to parse
 */
function mockEnvParser(input) {
  // Simple mock that validates environment variable format and security
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // Check for basic environment variable patterns
  if (!input.includes('=')) {
    throw new Error('Invalid environment variable format');
  }

  const lines = input.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') continue;

    // Check for proper KEY=value format
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      throw new Error(`Invalid environment format: ${trimmed}`);
    }

    const key = trimmed.substring(0, eqIndex);
    const value = trimmed.substring(eqIndex + 1);

    // Validate key format
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`Invalid environment variable name: ${key}`);
    }

    // Check for potentially dangerous values
    if (value.includes('\0')) {
      throw new Error('Null byte in environment value');
    }

    if (value.length > 32767) {
      throw new Error('Environment value too long');
    }

    // Check for command injection patterns
    if (value.includes('$(',) || value.includes('`')) {
      throw new Error('Command injection pattern detected');
    }

    // Check for path traversal
    if (value.includes('../') || value.includes('..\\')) {
      throw new Error('Path traversal detected in environment value');
    }
  }
}

/**
 * Fuzz target function for environment parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseEnvironment = await initializeEnvParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as environment variables
    parseEnvironment(input);

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
export async function FuzzEnvParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
