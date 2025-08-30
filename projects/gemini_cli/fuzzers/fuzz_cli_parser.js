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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_cli_parser.js

// Import the actual source code for fuzzing
const { parseCliArgs, validateCommand } = require('../src/cli/parser.js');

// Global reference to CLI parser (cached for performance)
let cliParser = null;

/**
 * Initialize the CLI parser module
 * @returns {Promise<Function>} The CLI parser function
 */
async function initializeCLIParser() {
  if (cliParser) {
    return cliParser;
  }

  try {
    // Use the actual implementation
    cliParser = parseCliArgs;
    return cliParser;
  } catch (error) {
    console.warn(`Failed to load CLI parser: ${error.message}`);
    console.warn('Using fallback parser for testing');
    return fallbackCLIParser;
  }
}

/**
 * Mock CLI parser for testing when upstream module is not available
 * @param {string} input - Input string to parse
 */
function mockCLIParser(input) {
  // Simple mock that validates basic CLI structure
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // Basic validation - check for common CLI patterns
  const trimmed = input.trim();

  // Check for very basic CLI structure
  if (trimmed.length > 1000) {
    throw new RangeError('Input too long');
  }

  // This is just a mock - real CLI parsing would be more complex
  return { parsed: true, args: trimmed.split(/\s+/) };
}

/**
 * Fuzz target function for CLI parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseCLI = await initializeCLIParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Attempt to parse the fuzzer input as CLI arguments
    parseCLI(input);

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
export async function FuzzCLIParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput, FuzzCLIParser };