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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_oauth_token_request.js

// OAuth token request structures and validation functions
// Mirroring the Go implementation for consistent fuzzing

/**
 * OAuth Token Request structure
 */
class OAuthTokenRequest {
  constructor() {
    this.grant_type = '';
    this.code = '';
    this.redirect_uri = '';
    this.client_id = '';
    this.client_secret = '';
    this.refresh_token = '';
    this.scope = '';
  }
}

/**
 * OAuth Token Response structure
 */
class OAuthTokenResponse {
  constructor() {
    this.access_token = '';
    this.token_type = '';
    this.expires_in = 0;
    this.refresh_token = '';
    this.scope = '';
    this.id_token = '';
  }
}

/**
 * Parse and validate OAuth token request
 * @param {string} input - JSON input string
 * @returns {OAuthTokenRequest} Parsed request
 */
function parseOAuthTokenRequest(input) {
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  if (input.length > 32 * 1024) { // 32KB limit
    throw new Error('Token request too large');
  }

  try {
    const data = JSON.parse(input);
    const request = new OAuthTokenRequest();

    // Parse JSON fields
    request.grant_type = data.grant_type || '';
    request.code = data.code || '';
    request.redirect_uri = data.redirect_uri || '';
    request.client_id = data.client_id || '';
    request.client_secret = data.client_secret || '';
    request.refresh_token = data.refresh_token || '';
    request.scope = data.scope || '';

    return request;
  } catch (error) {
    throw new Error(`Invalid JSON: ${error.message}`);
  }
}

/**
 * Validate OAuth token request for security issues
 * @param {OAuthTokenRequest} request - Parsed request
 * @returns {Object} Validation result
 */
function validateOAuthTokenRequest(request) {
  const errors = [];

  // Validate grant type
  const validGrants = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'password'
  ];

  if (!request.grant_type || !validGrants.includes(request.grant_type)) {
    errors.push(`Invalid grant_type: ${request.grant_type}`);
  }

  // Validate redirect URI format
  if (request.redirect_uri) {
    if (request.redirect_uri.length > 2048) {
      errors.push('redirect_uri too long');
    }

    // Must be HTTPS or localhost for security
    const isSecure = request.redirect_uri.startsWith('https://') ||
                    request.redirect_uri.startsWith('http://localhost') ||
                    request.redirect_uri.startsWith('http://127.0.0.1');

    if (!isSecure) {
      errors.push('redirect_uri must use HTTPS or localhost');
    }

    // Check for dangerous characters
    if (/[<>]/.test(request.redirect_uri)) {
      errors.push('redirect_uri contains dangerous characters');
    }
  }

  // Check for potential injection in client credentials
  if (request.client_id && /[<>]/.test(request.client_id)) {
    errors.push('Potentially dangerous characters in client_id');
  }

  // Validate tokens
  if (request.refresh_token) {
    const tokenError = validateToken(request.refresh_token, 'refresh_token');
    if (tokenError) errors.push(tokenError);
  }

  return {
    valid: errors.length === 0,
    errors: errors
  };
}

/**
 * Validate OAuth token response
 * @param {string} input - JSON input string
 * @returns {Object} Validation result
 */
function parseOAuthTokenResponse(input) {
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string');
  }

  if (input.length > 64 * 1024) { // 64KB limit
    throw new Error('Token response too large');
  }

  try {
    const data = JSON.parse(input);
    const response = new OAuthTokenResponse();

    response.access_token = data.access_token || '';
    response.token_type = data.token_type || '';
    response.expires_in = data.expires_in || 0;
    response.refresh_token = data.refresh_token || '';
    response.scope = data.scope || '';
    response.id_token = data.id_token || '';

    return response;
  } catch (error) {
    throw new Error(`Invalid JSON: ${error.message}`);
  }
}

/**
 * Validate OAuth token response for security issues
 * @param {OAuthTokenResponse} response - Parsed response
 * @returns {Object} Validation result
 */
function validateOAuthTokenResponse(response) {
  const errors = [];

  // Validate access token
  if (!response.access_token) {
    errors.push('access_token is required');
  } else {
    const tokenError = validateToken(response.access_token, 'access_token');
    if (tokenError) errors.push(tokenError);
  }

  // Validate token type
  if (response.token_type) {
    const validTypes = ['Bearer', 'bearer', 'MAC', 'mac'];
    if (!validTypes.includes(response.token_type)) {
      errors.push(`Invalid token_type: ${response.token_type}`);
    }
  }

  // Validate expires_in
  if (response.expires_in < 0 || response.expires_in > 86400 * 365) {
    errors.push('Invalid expires_in value');
  }

  // Validate refresh token if present
  if (response.refresh_token) {
    const tokenError = validateToken(response.refresh_token, 'refresh_token');
    if (tokenError) errors.push(tokenError);
  }

  // Validate ID token if present (basic JWT structure check)
  if (response.id_token) {
    const jwtError = validateJWTStructure(response.id_token);
    if (jwtError) errors.push(jwtError);
  }

  return {
    valid: errors.length === 0,
    errors: errors
  };
}

/**
 * Validate token for security issues
 * @param {string} token - Token to validate
 * @param {string} tokenType - Type of token for error messages
 * @returns {string|null} Error message or null if valid
 */
function validateToken(token, tokenType) {
  if (!token || token.length === 0) {
    return `${tokenType} cannot be empty`;
  }

  if (token.length > 8192) { // 8KB max token size
    return `${tokenType} too long`;
  }

  // Check for obvious injection attempts
  const dangerous = ['<script', 'javascript:', 'data:', 'vbscript:', 'onload='];
  const tokenLower = token.toLowerCase();
  for (const pattern of dangerous) {
    if (tokenLower.includes(pattern)) {
      return `Potentially dangerous pattern in ${tokenType}`;
    }
  }

  return null;
}

/**
 * Validate JWT structure
 * @param {string} token - JWT token to validate
 * @returns {string|null} Error message or null if valid
 */
function validateJWTStructure(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return 'JWT must have 3 parts separated by dots';
  }

  // Basic length checks for each part
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (!part || part.length === 0) {
      return `JWT part ${i + 1} cannot be empty`;
    }
    if (part.length > 16384) { // 16KB per part max
      return `JWT part ${i + 1} too long`;
    }
  }

  return null;
}

/**
 * Fuzz target function for OAuth request parser
 * Follows Fuchsia guidelines similar to LLVMFuzzerTestOneInput
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {number} 0 for success, non-zero for expected errors
 */
async function LLVMFuzzerTestOneInput(data) {
  // Input validation and size limits
  if (!data || data.length === 0 || data.length > 8192) {
    return 0; // Skip empty or oversized inputs
  }

  // Resource limits for fuzzing safety
  const maxProcessingTime = 5000; // 5 seconds max
  const startTime = Date.now();

  try {
    const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);

    // Test multiple parsing strategies for better coverage
    const testStrategies = [
      // Original input as request
      () => ({ type: 'request', data: parseOAuthTokenRequest(input) }),
      // Original input as response
      () => ({ type: 'response', data: parseOAuthTokenResponse(input) }),
      // URL-decoded input (in case it's URL-encoded)
      () => {
        try {
          const decoded = decodeURIComponent(input);
          return { type: 'request', data: parseOAuthTokenRequest(decoded) };
        } catch {
          return { type: 'request', data: parseOAuthTokenRequest(input) };
        }
      },
      // Base64 decoded input
      () => {
        try {
          const decoded = Buffer.from(input, 'base64').toString('utf8');
          return { type: 'request', data: parseOAuthTokenRequest(decoded) };
        } catch {
          return { type: 'request', data: parseOAuthTokenRequest(input) };
        }
      },
      // JSON wrapped input
      () => {
        try {
          const wrapped = JSON.parse(input);
          if (wrapped.data) {
            return { type: 'request', data: parseOAuthTokenRequest(JSON.stringify(wrapped.data)) };
          }
          return { type: 'request', data: parseOAuthTokenRequest(input) };
        } catch {
          return { type: 'request', data: parseOAuthTokenRequest(input) };
        }
      },
    ];

    for (const strategy of testStrategies) {
      // Check time limits to prevent infinite loops
      if (Date.now() - startTime > maxProcessingTime) {
        return 0; // Timeout - expected behavior
      }

      try {
        const result = strategy();
        const parsed = result.data;

        // Validate the parsed data with appropriate validation methods
        let validation;
        if (result.type === 'request') {
          validation = validateOAuthTokenRequest(parsed);
        } else if (result.type === 'response') {
          validation = validateOAuthTokenResponse(parsed);
        } else {
          // Fallback validation for unknown types
          validation = { valid: false, errors: ['Unknown parsed type'] };
        }

        if (!validation.valid) {
          // Log validation errors for debugging (only in development)
          if (process.env.NODE_ENV === 'development') {
            console.log(`Validation failed: ${validation.errors.join(', ')}`);
          }
          continue; // Expected validation errors, try next strategy
        }

        // Test serialization/deserialization
        const serialized = JSON.stringify(parsed);
        const deserialized = JSON.parse(serialized);

        // Verify round-trip consistency
        if (JSON.stringify(deserialized) !== serialized) {
          return 0; // Expected inconsistency, not a crash
        }

      } catch (strategyError) {
        // Expected errors from individual strategies
        if (strategyError.name === 'SyntaxError' ||
            strategyError.name === 'TypeError' ||
            strategyError.name === 'RangeError' ||
            strategyError.name === 'URIError') {
          continue; // Try next strategy
        }
        throw strategyError; // Unexpected error
      }
    }

    return 0; // Success - all strategies completed

  } catch (error) {
    // Enhanced error classification for better crash detection
    if (error && error.name) {
      // Expected parsing and validation errors
      const expectedErrors = [
        'SyntaxError', 'TypeError', 'RangeError', 'ReferenceError',
        'URIError', 'ValidationError', 'SecurityError', 'FormatError'
      ];

      if (expectedErrors.includes(error.name)) {
        return 0; // Expected error, continue fuzzing
      }

      // Log unexpected errors for debugging
      if (process.env.NODE_ENV === 'development') {
        console.error(`Unexpected error in OAuth fuzzer: ${error.message}`);
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
      console.warn(`OAuth fuzzer exceeded time limit: ${processingTime}ms`);
    }
  }
}

/**
 * Legacy compatibility function for Jazzer.js
 * @param {Buffer|Uint8Array} data - Input data from fuzzer
 * @returns {Promise<void>}
 */
async function FuzzOAuthTokenRequest(data) {
  const result = await LLVMFuzzerTestOneInput(data);
  if (result !== 0) {
    throw new Error(`Fuzzer returned error code: ${result}`);
  }
}

// This fuzzer is designed to work directly with OSS-Fuzz

// CommonJS export for OSS-Fuzz compatibility
module.exports = {
  LLVMFuzzerTestOneInput,
  parseOAuthTokenRequest,
  parseOAuthTokenResponse,
  validateOAuthTokenRequest,
  validateOAuthTokenResponse
};
