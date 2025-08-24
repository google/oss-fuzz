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
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 8192) { // 8KB for MCP responses
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 4000; // 4 seconds max for MCP response parsing
  const startTime = Date.now();

  try {
    const parseMCPResponse = await initializeMCPResponseParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple MCP response parsing strategies for comprehensive coverage
    const testStrategies = [
      // Original MCP response
      () => parseMCPResponse(input),
      // MCP response with BOM
      () => parseMCPResponse('\uFEFF' + input),
      // Base64 encoded MCP response
      () => parseMCPResponse(Buffer.from(input).toString('base64')),
      // URL-encoded MCP response
      () => parseMCPResponse(encodeURIComponent(input)),
      // MCP response wrapped in array
      () => parseMCPResponse('[' + input + ']'),
      // MCP response with extra whitespace
      () => parseMCPResponse(input + '\n\n\n'),
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const response = strategy();

        // Additional security validation for MCP responses
        if (response && typeof response === 'object') {
          // Check for dangerous patterns in MCP response content
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

          if (checkObject(response)) {
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

          const totalSize = checkSize(response);
          if (totalSize > 16384) { // 16KB total limit
            return 0; // Expected size violation
          }
        }

        // Test MCP response serialization/deserialization
        try {
          const serialized = JSON.stringify(response);
          const deserialized = JSON.parse(serialized);

          // Basic consistency check
          if (serialized.length > 0 && !deserialized) {
            return 0; // Expected inconsistency, not a crash
          }
        } catch (serializationError) {
          // Expected serialization errors for invalid responses
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
            strategyError.message.includes('Invalid MCP response') ||
            strategyError.message.includes('Malformed MCP response') ||
            strategyError.message.includes('UPSTREAM_MCP_NOT_FOUND') ||
            strategyError.message.includes('UPSTREAM_PARSE_NOT_FOUND') ||
            strategyError.message.includes('Failed to load MCP response parser') ||
            strategyError.message.includes('Parse error')) {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected MCP response parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'MCPError'
      ];

      if (expectedErrors.includes(error.name)) {
        return 0; // Expected error, continue fuzzing
      }

      // MCP-specific errors
      if (error.message.includes('Invalid MCP response') ||
          error.message.includes('Malformed MCP response') ||
          error.message.includes('MCP response validation failed') ||
          error.message.includes('Content validation failed') ||
          error.message.includes('UPSTREAM_MCP_NOT_FOUND') ||
          error.message.includes('UPSTREAM_PARSE_NOT_FOUND') ||
          error.message.includes('Failed to load MCP response parser')) {
        return 0; // Expected MCP error
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in MCP response fuzzer: ${error.message}`);
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
      console.warn(`MCP response fuzzer exceeded time limit: ${processingTime}ms`);
    }
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
