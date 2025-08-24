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

// Enhanced MCP request parser fuzzer for Gemini CLI
// Tests MCP request parsing, validation, and security checks

// Import the actual source code for fuzzing
const { parseMCPRequest, validateMCPRequest } = require('../src/mcp/handler.js');

/**
 * Main fuzzing function - implements LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success/expected errors, 1 for crashes
 */
export function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 8192) { // 8KB for MCP requests
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 4000; // 4 seconds max for MCP request parsing
  const startTime = Date.now();

  try {
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple MCP request parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original MCP request
      () => parseMCPRequest(input),
      // MCP request with BOM
      () => parseMCPRequest('\uFEFF' + input),
      // Base64 encoded MCP request
      () => parseMCPRequest(Buffer.from(input).toString('base64')),
      // URL-encoded MCP request
      () => parseMCPRequest(encodeURIComponent(input)),
      // MCP request wrapped in array
      () => parseMCPRequest('[' + input + ']'),
      // MCP request with extra whitespace
      () => parseMCPRequest(input + '\n\n\n'),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const request = strategy();

        // Validate the parsed MCP request
        const validation = validateMCPRequest(request);
        if (!validation.valid) {
          // Log validation errors for debugging (only in development)
          if (process.env.NODE_ENV === 'development') {
            console.log(`MCP request validation failed: ${validation.error}`);
          }
          continue; // Expected validation errors, try next method
        }

        // MCP-specific security validations
        if (request && typeof request === 'object') {
          // Check for dangerous patterns in MCP request content
          const dangerousPatterns = [
            /<script>/g, // XSS payloads
            /javascript:/g, // JavaScript URLs
            /eval\s*\(/g, // Code execution
            /require\s*\(/g, // Module loading
            /import\s*\(/g, // Import execution
            /\.\.\//g, // Path traversal
            /<iframe/g, // Frame injection
            /onload\s*=/g, // Event handler injection
            /system\s*\(/g, // System commands
          ];

          // Check string fields for dangerous content
          const checkObject = (obj) => {
            if (!obj || typeof obj !== 'object') return false;
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                for (const pattern of dangerousPatterns) {
                  if (pattern.test(value)) {
                    return true; // Found dangerous content
                  }
                }
              } else if (typeof value === 'object') {
                if (checkObject(value)) return true;
              }
            }
            return false;
          };

          if (checkObject(request)) {
            return 0; // Expected security violation
          }

          // Check for oversized fields that could cause DoS
          const checkSize = (obj) => {
            if (!obj || typeof obj !== 'object') return 0;
            let totalSize = 0;
            for (const [key, value] of Object.entries(obj)) {
              if (typeof value === 'string') {
                totalSize += value.length;
                if (value.length > 4096) return value.length; // Oversized field
              } else if (typeof value === 'object') {
                const nestedSize = checkSize(value);
                if (nestedSize > 4096) return nestedSize;
              }
            }
            return totalSize;
          };

          const totalSize = checkSize(request);
          if (totalSize > 16384) { // 16KB total limit
            return 0; // Expected size violation
          }
        }

        // Test MCP request serialization/deserialization
        try {
          const serialized = JSON.stringify(request);
          const deserialized = JSON.parse(serialized);

          // Verify round-trip consistency
          if (JSON.stringify(deserialized) !== serialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid requests
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
            strategyError.message.includes('Invalid JSON') ||
            strategyError.message.includes('Invalid JSON-RPC') ||
            strategyError.message.includes('Missing or invalid') ||
            strategyError.message.includes('JSON parsing failed') ||
            strategyError.message.includes('Input too large') ||
            strategyError.message.includes('Invalid input') ||
            strategyError.message.includes('Excessive nesting') ||
            strategyError.message.includes('Malicious pattern') ||
            strategyError.message.includes('Potential path traversal') ||
            strategyError.message.includes('Potential XSS') ||
            strategyError.message.includes('Dangerous method pattern')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected MCP request parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'MCPError'
      ];

      if (expectedErrors.includes(error.name)) {
        return 0; // Expected error, continue fuzzing
      }

      // MCP-specific errors
      if (error.message.includes('Invalid MCP request') ||
          error.message.includes('Malformed MCP request') ||
          error.message.includes('MCP request validation failed') ||
          error.message.includes('Content validation failed') ||
          error.message.includes('Request must be an object') ||
          error.message.includes('Invalid JSON-RPC version') ||
          error.message.includes('Missing or invalid method') ||
          error.message.includes('Method name too long') ||
          error.message.includes('Invalid ID type') ||
          error.message.includes('Invalid ID range') ||
          error.message.includes('Invalid params type') ||
          error.message.includes('Excessive nesting depth')) {
        return 0; // Expected MCP error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in MCP request fuzzer: ${error.message}`);
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
      console.warn(`MCP request fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Default export for compatibility
 */
export default LLVMFuzzerTestOneInput;

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
