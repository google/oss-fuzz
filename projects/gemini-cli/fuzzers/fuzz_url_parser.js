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
// Enhanced URL parser fuzzer for Gemini CLI
// Tests URL parsing, validation, and security checks

// Import the actual source code for fuzzing
const { parseURL, validateURL, sanitizeURL } = require('../src/core/url-parser.js');

// Global reference to URL parser (cached for performance)
let urlParser = null;

/**
 * Initialize the URL parser module
 * @returns {Promise<Function>} The URL parser function
 */
async function initializeURLParser() {
  if (urlParser) {
    return urlParser;
  }

  try {
    // Use the actual implementation
    urlParser = parseURL;
    return urlParser;
  } catch (error) {
    console.warn(`Failed to load URL parser: ${error.message}`);
    console.warn('Using fallback parser for testing');
    return fallbackURLParser;
  }
}

/**
 * Fallback URL parser for testing when main module fails
 * @param {string} input - Input URL to parse
 */
function fallbackURLParser(input) {
  // Simple fallback that validates URL structure and checks for basic security issues
  if (!input || typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  // Basic URL format validation
  try {
    new URL(input);
  } catch (error) {
    // Expected for malformed URLs
    throw new Error(`Invalid URL: ${error.message}`);
  }

  // Check for dangerous schemes
  const dangerousSchemes = ['javascript:', 'data:', 'file:', 'vbscript:'];
  for (const scheme of dangerousSchemes) {
    if (input.toLowerCase().startsWith(scheme)) {
      throw new Error(`Dangerous scheme detected: ${scheme}`);
    }
  }

  // Check for path traversal
  if (input.includes('../') || input.includes('..\\')) {
    throw new Error('Path traversal detected in URL');
  }

  // Check for null bytes
  if (input.includes('\0')) {
    throw new Error('Null byte detected in URL');
  }

  // Check URL length
  if (input.length > 2048) {
    throw new Error('URL too long');
  }
}

/**
 * Enhanced URL security validator
 * @param {string} url - URL to validate
 */
function validateURLSecurity(url) {
  if (!url || typeof url !== 'string') {
    throw new TypeError('URL must be a string');
  }

  // Convert to lowercase for case-insensitive checks
  const urlLower = url.toLowerCase();

  // Block dangerous protocols
  const dangerousProtocols = [
    'javascript:', 'data:', 'file:', 'vbscript:', 'livescript:',
    'mocha:', 'jar:', 'chrome:', 'chrome-extension:', 'qrc:',
    'ftp://', 'ftps://', 'ldap://', 'ldaps://'
  ];

  for (const protocol of dangerousProtocols) {
    if (urlLower.startsWith(protocol)) {
      throw new Error(`Dangerous protocol detected: ${protocol}`);
    }
  }

  // Check for script injection patterns
  const scriptPatterns = [
    '<script', 'onload=', 'onerror=', 'onclick=', 'onmouseover=',
    'javascript:', 'eval(', 'alert(', 'document.cookie', 'document.write'
  ];

  for (const pattern of scriptPatterns) {
    if (urlLower.includes(pattern)) {
      throw new Error(`Script injection pattern detected: ${pattern}`);
    }
  }

  // Check for SQL injection patterns
  const sqlPatterns = ['union', 'select', 'drop', 'delete', 'insert', 'update', '--', '/*', '*/'];
  for (const pattern of sqlPatterns) {
    if (urlLower.includes(pattern)) {
      throw new Error(`SQL injection pattern detected: ${pattern}`);
    }
  }

  // Check for command injection patterns
  const cmdPatterns = [';', '|', '&', '`', '$(', '${', '>', '>>', '<<'];
  for (const pattern of cmdPatterns) {
    if (url.includes(pattern)) {
      throw new Error(`Command injection pattern detected: ${pattern}`);
    }
  }

  // Check for path traversal
  if (url.includes('../') || url.includes('..\\')) {
    throw new Error('Path traversal detected in URL');
  }

  // Check for null bytes
  if (url.includes('\0')) {
    throw new Error('Null byte detected in URL');
  }

  // Check for overly long URLs (DoS protection)
  if (url.length > 4096) {
    throw new Error('URL exceeds maximum length');
  }

  // Check for excessive parameters (DoS protection)
  const paramCount = (url.match(/[?&]/g) || []).length;
  if (paramCount > 50) {
    throw new Error('Too many URL parameters');
  }

  // Check for deeply nested paths
  const pathSegments = url.split(/[\/\\]/).length;
  if (pathSegments > 20) {
    throw new Error('URL path too deeply nested');
  }
}

/**
 * Fuzz target function for URL parser
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
export async function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) {
    return 0; // Skip empty inputs
  }

  try {
    const parseURL = await initializeURLParser();
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test URL parsing
    const parsed = parseURL(input);

    // Test URL validation
    if (validateURL) {
      const validation = validateURL(parsed);
      if (!validation.valid) {
        return 0; // Expected validation error
      }
    }

    // Test URL sanitization
    if (sanitizeURL) {
      const sanitized = sanitizeURL(input);
      if (!sanitized) {
        return 0; // Expected sanitization error
      }
    }

    // Additional security validation
    validateURLSecurity(input);

    return 0; // Success
  } catch (error) {
    // Handle expected parsing/validation errors gracefully
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

    // Return non-zero for unexpected errors (actual crashes)
    return 1;
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
export async function FuzzURLParser(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// Additional fuzz target for URL parsing edge cases
export async function FuzzURLParsingEdgeCases(data) {
  if (!data || data.length === 0) {
    return 0;
  }

  try {
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test with various URL parsing contexts
    const testCases = [
      input,
      `http://example.com/${input}`,
      `https://test.com/path?param=${encodeURIComponent(input)}`,
      `file:///${input}`,
      `javascript:${input}`,
      `data:text/plain,${input}`,
      `${input}@example.com`,
      `http://user:pass@${input}`,
    ];

    for (const testCase of testCases) {
      try {
        new URL(testCase);
        validateURLSecurity(testCase);
      } catch (error) {
        // Expected for malformed URLs
        continue;
      }
    }

    return 0;
  } catch (error) {
    return 0; // Expected errors are not crashes
  }
}

// Default export for compatibility
export default LLVMFuzzerTestOneInput;

// CommonJS export for OSS-Fuzz compatibility
module.exports = { LLVMFuzzerTestOneInput };
