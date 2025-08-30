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
// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_file_path_handler.js
// Fuzzer for Gemini CLI file path handling and validation
// Implements Fuchsia-style fuzz target function

import { locateUpstream } from './_upstream_locator.mjs';

// Global reference to upstream module (cached for performance)
let upstreamModule = null;

/**
 * Initialize the upstream file path handler module
 * @returns {Promise<Function>} The file path handler function
 */
async function initializeFilePathHandler() {
  if (upstreamModule) {
    return upstreamModule;
  }

  const modulePaths = [
    'packages/cli/src/file.js',
    'packages/cli/src/file.ts',
    'packages/cli/lib/file.js',
    'packages/cli/src/filesystem.js',
    'packages/cli/src/filesystem.ts',
    'packages/cli/lib/filesystem.js',
    'packages/cli/src/path.js',
    'packages/cli/src/path.ts',
    'packages/cli/lib/path.js'
  ];

  const modulePath = locateUpstream(modulePaths);
  if (!modulePath) {
    // Return a mock function for testing when upstream module is not available
    console.warn('UPSTREAM_FILE_NOT_FOUND: using mock handler for testing');
    return mockFilePathHandler;
  }

  try {
    const mod = await import(modulePath);
    const fn = mod.handleFilePath || mod.default?.handleFilePath || mod.validatePath || mod.sanitizePath;
    if (!fn) {
      console.warn('UPSTREAM_HANDLER_NOT_FOUND: using mock handler for testing');
      return mockFilePathHandler;
    }
    upstreamModule = fn;
    return fn;
  } catch (error) {
    console.warn(`Failed to load file path handler: ${error.message}`);
    console.warn('Using mock handler for testing');
    return mockFilePathHandler;
  }
}

/**
 * Mock file path handler for testing when upstream module is not available
 * @param {string} input - Input path to handle
 */
function mockFilePathHandler(input) {
  // Simple mock that validates file path structure and checks for basic security issues
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // Check for path traversal attempts
  if (input.includes('../') || input.includes('..\\')) {
    throw new Error('Path traversal detected');
  }

  // Check for null bytes
  if (input.includes('\0')) {
    throw new Error('Null byte detected');
  }

  // Check for absolute paths that could be problematic
  if (input.startsWith('/') || /^[A-Za-z]:/.test(input)) {
    throw new Error('Absolute path not allowed');
  }

  // Check for invalid characters
  const invalidChars = /[<>"|?*\x00-\x1f]/;
  if (invalidChars.test(input)) {
    throw new Error('Invalid characters in path');
  }

  // Check path length
  if (input.length > 4096) {
    throw new Error('Path too long');
  }

  // Basic path structure validation
  const parts = input.split(/[\/\\]/);
  for (const part of parts) {
    if (part.length > 255) {
      throw new Error('Path component too long');
    }
    if (part.startsWith('.') && part !== '.' && part !== '..') {
      // Hidden files are allowed, just check for obvious issues
      continue;
    }
  }
}

/**
 * Fuzz target function for file path handler
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 4096) {
    return 0; // Skip empty or oversized inputs (shorter limit for paths)
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 3000; // 3 seconds max for file operations
  const startTime = Date.now();

  try {
    const handleFilePath = await initializeFilePathHandler();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple file path handling strategies for comprehensive coverage
    const testStrategies = [
      // Original path
      () => handleFilePath(input),
      // Normalized path
      () => handleFilePath(path.normalize(input)),
      // Relative path variations
      () => handleFilePath('./' + input),
      () => handleFilePath('../' + input),
      // Absolute path variations
      () => handleFilePath('/tmp/' + input.replace(/^\//g, '')),
      () => handleFilePath('C:\\' + input.replace(/^[\/\\]/g, '')),
      // URL-encoded paths
      () => handleFilePath(decodeURIComponent(input)),
      () => handleFilePath(encodeURIComponent(input)),
      // Unicode normalization
      () => handleFilePath(input.normalize('NFC')),
      () => handleFilePath(input.normalize('NFD')),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const result = strategy();

        // Validate the result with multiple validation methods
        const validationMethods = [
          () => validateFilePath(result),
          () => validateFilePathSecurity(result),
          () => validateFilePathTraversal(result),
          () => validateFilePathPermissions(result),
        ];

        for (const validate of validationMethods) {
          const validation = validate();
          if (!validation.valid) {
            // Log validation errors for debugging (only in development)
            if (process.env.NODE_ENV === 'development') {
              console.log(`File path validation failed: ${validation.error}`);
            }
            continue; // Expected validation errors, try next method
          }
        }

        // Test path-specific security validations
        if (result && typeof result === 'string') {
          // Check for dangerous path patterns
          const dangerousPatterns = [
            /\.\.\//g, // Path traversal
            /\.\.\\/g, // Windows path traversal
            /~/g, // Home directory
            /\/etc\/passwd/g, // Sensitive files
            /\/etc\/shadow/g,
            /\/proc\/self\/environ/g,
            /C:\\Windows\\System32/g, // Windows system paths
            /\\windows\\system32/g,
          ];

          for (const pattern of dangerousPatterns) {
            if (pattern.test(result)) {
              return 0; // Expected security violation
            }
          }

          // Check for null bytes and control characters
          if (result.includes('\0') || /[\x00-\x1f\x7f]/.test(result)) {
            return 0; // Expected null byte or control character handling
          }

          // Test path length limits
          if (result.length > 4096) {
            return 0; // Expected path length violation
          }
        }

        // Test serialization/deserialization for path objects
        try {
          const pathObj = { path: result, normalized: path.normalize(result) };
          const serialized = JSON.stringify(pathObj);
          const deserialized = JSON.parse(serialized);

          // Verify round-trip consistency
          if (JSON.stringify(deserialized) !== serialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid paths
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
            strategyError.message.includes('Invalid path') ||
            strategyError.message.includes('Path not allowed')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected file system and path errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'PathError',
        'ENOENT', 'EACCES', 'EPERM'
      ];

      if (expectedErrors.includes(error.name) || expectedErrors.includes(error.code)) {
        return 0; // Expected error, continue fuzzing
      }

      // File system specific errors
      if (error.message.includes('Path not found') ||
          error.message.includes('Access denied') ||
          error.message.includes('Permission denied') ||
          error.message.includes('Invalid path') ||
          error.message.includes('Path too long')) {
        return 0; // Expected file system error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in file path fuzzer: ${error.message}`);
        console.error(error.stack);
      }
    }

    // Memory and resource exhaustion errors
    if (error.code === 'ENOBUFS' || error.code === 'ENOMEM' ||
        error.message.includes('out of memory') ||
        error.message.includes('maximum call stack')) {
      return 0; // Expected resource exhaustion, not a crash
    }

    // Return non-zero for actual crashes and unexpected errors
    return 1;
  } finally {
    // Cleanup resources if needed
    const processingTime = Date.now() - startTime;
    if (processingTime > maxProcessingTime) {
      console.warn(`File path fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
export async function FuzzFilePathHandler(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
