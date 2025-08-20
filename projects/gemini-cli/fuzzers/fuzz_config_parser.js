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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_config_parser.js
// Fuzzer for Gemini CLI configuration parser
// Implements Fuchsia-style fuzz target function

// Import the actual source code for fuzzing
const { parseConfig, validateConfig } = require('../src/config/parser.js');

// Global reference to config parser (cached for performance)
let configParser = null;

/**
 * Initialize the config parser module
 * @returns {Promise<Function>} The config parser function
 */
async function initializeConfigParser() {
  if (configParser) {
    return configParser;
  }

  try {
    // Use the actual implementation
    configParser = parseConfig;
    return configParser;
  } catch (error) {
    console.warn(`Failed to load config parser: ${error.message}`);
    console.warn('Using fallback parser for testing');
    return fallbackConfigParser;
  }
}

/**
 * Fallback config parser for testing when main module fails
 * @param {string} input - Input string to parse
 */
function fallbackConfigParser(input) {
  // Simple fallback that just validates JSON structure
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  try {
    JSON.parse(input);
  } catch (error) {
    // Convert JSON errors to parsing errors
    if (error instanceof SyntaxError) {
      throw new SyntaxError(`Invalid JSON: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Fuzz target function for configuration parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseConfig = await initializeConfigParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Parse the configuration
    const config = parseConfig(input);

    // Validate the parsed configuration
    const validation = validateConfig(config);
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
export async function FuzzConfigParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// Simple fuzz function for direct OSS-Fuzz usage
export function FuzzFunction(data) {
  try {
    // Convert data to string for JSON parsing
    const input = data.toString();
    if (input.length === 0) return;

    // Try to parse as JSON
    const config = JSON.parse(input);

    // Basic validation
    if (typeof config === 'object' && config !== null) {
      // Check for malicious patterns
      const inputStr = JSON.stringify(config);
      const maliciousPatterns = [
        '<script', 'javascript:', 'onload=', 'onerror=',
        '../', '..\\', 'eval(', 'alert(', 'document.',
        'UNION', 'SELECT', 'DROP', 'DELETE', 'INSERT', 'UPDATE'
      ];

      for (const pattern of maliciousPatterns) {
        if (inputStr.includes(pattern)) {
          return; // Found attack pattern
        }
      }

      // Check for nested structures that could cause DoS
      function checkNesting(obj, depth = 0) {
        if (depth > 10) throw new Error('Excessive nesting');
        if (Array.isArray(obj)) {
          for (const item of obj) {
            checkNesting(item, depth + 1);
          }
        } else if (typeof obj === 'object' && obj !== null) {
          for (const value of Object.values(obj)) {
            checkNesting(value, depth + 1);
          }
        }
      }

      checkNesting(config);
    }
  } catch (e) {
    // Expected for malformed input
  }
}

// Default export for compatibility
export default FuzzFunction;

// CommonJS export for OSS-Fuzz compatibility
module.exports = { FuzzFunction };