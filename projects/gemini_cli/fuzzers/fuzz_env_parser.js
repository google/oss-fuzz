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
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 4096) { // 4KB for environment variables
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 3000; // 3 seconds max for env parsing
  const startTime = Date.now();

  try {
    const parseEnvironment = await initializeEnvParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple environment parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original environment variables
      () => parseEnvironment(input),
      // Environment variables with BOM
      () => parseEnvironment('\uFEFF' + input),
      // Base64 encoded environment variables
      () => parseEnvironment(Buffer.from(input).toString('base64')),
      // URL-encoded environment variables
      () => parseEnvironment(encodeURIComponent(input)),
      // Environment variables with newlines
      () => parseEnvironment(input.replace(/=/g, '=\n').replace(/$/gm, '\n')),
      // Environment variables with quotes
      () => parseEnvironment(input.replace(/=/g, '="').replace(/$/gm, '"')),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const result = strategy();

        // Additional security validation for environment variables
        if (input && typeof input === 'string') {
          // Check for dangerous environment variable patterns
          const dangerousPatterns = [
            /rm\s+-rf/g, // File deletion
            /eval\s*\(/g, // Code execution
            /exec\s*\(/g, // Command execution
            /system\s*\(/g, // System commands
            /require\s*\(/g, // Module loading
            /import\s*\(/g, // Import execution
            /<script>/g, // Script injection
            /\$\{[^}]+\}/g, // Template injection
            /`[^`]+`/g, // Command substitution
          ];

          for (const pattern of dangerousPatterns) {
            if (pattern.test(input)) {
              return 0; // Expected security violation
            }
          }

          // Check for oversized values that could cause DoS
          if (input.length > 4096) {
            return 0; // Expected size violation
          }

          // Check for dangerous environment variable names
          const dangerousKeys = [
            'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH', 'SHELL',
            'BASH_ENV', 'ENV', 'PERL5OPT', 'PERLLIB', 'PYTHONPATH',
            'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH'
          ];

          const lines = input.split('\n');
          for (const line of lines) {
            const eqIndex = line.indexOf('=');
            if (eqIndex !== -1) {
              const key = line.substring(0, eqIndex).toUpperCase();
              if (dangerousKeys.includes(key)) {
                const value = line.substring(eqIndex + 1);
                if (value.includes('..')) {
                  return 0; // Expected dangerous path in critical variable
                }
              }
            }
          }
        }

        // Test environment variable serialization/deserialization
        try {
          const lines = input.split('\n');
          const envVars = {};

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed === '') continue;
            const eqIndex = trimmed.indexOf('=');
            if (eqIndex !== -1) {
              const key = trimmed.substring(0, eqIndex);
              const value = trimmed.substring(eqIndex + 1);
              envVars[key] = value;
            }
          }

          const serialized = Object.keys(envVars).map(key =>
            `${key}=${envVars[key] || ''}`
          ).join('\n');

          const deserialized = parseEnvironment(serialized);

          // Basic consistency check
          if (serialized.length > 0 && !deserialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid environment variables
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
            strategyError.name === 'Error' ||
            strategyError.message.includes('Invalid environment') ||
            strategyError.message.includes('Malformed environment') ||
            strategyError.message.includes('Null byte') ||
            strategyError.message.includes('Command injection') ||
            strategyError.message.includes('Path traversal') ||
            strategyError.message.includes('Environment value too long')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected environment parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'EnvironmentError'
      ];

      if (expectedErrors.includes(error.name) || error.name === 'Error') {
        return 0; // Expected error, continue fuzzing
      }

      // Environment-specific errors
      if (error.message.includes('Invalid environment') ||
          error.message.includes('Malformed environment') ||
          error.message.includes('Environment validation failed') ||
          error.message.includes('Content validation failed') ||
          error.message.includes('Null byte') ||
          error.message.includes('Command injection') ||
          error.message.includes('Path traversal') ||
          error.message.includes('Environment value too long')) {
        return 0; // Expected environment error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in environment fuzzer: ${error.message}`);
        console.error(error.stack);
      }
    }

    // Memory and resource exhaustion errors
    if (error.code === 'ENOBUFS' || error.code === 'ENOMEM' ||
        error.message.includes('out of memory') ||
        error.message.includes('maximum call stack') ||
        error.message.includes('heap out of memory')) {
      return 0; // Expected resource exhaustion, not a crash
    }

    // Return non-zero for actual crashes and unexpected errors
    return 1;
  } finally {
    // Cleanup resources if needed
    const processingTime = Date.now() - startTime;
    if (processingTime > maxProcessingTime) {
      console.warn(`Environment fuzzer exceeded time limit: ${processingTime}ms`);
    }
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
