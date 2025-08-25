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

/**
 * OAuth Token Handler
 * Handles OAuth token requests and responses
 */

/**
 * Parse OAuth token request
 * @param {string} requestStr - Token request string
 * @returns {object} Parsed token request
 */
export function parseOAuthTokenRequest(requestStr) {
  if (typeof requestStr !== 'string') {
    throw new TypeError('Request must be a string');
  }

  if (!requestStr.trim()) {
    throw new Error('Request cannot be empty');
  }

  try {
    // Try JSON first
    const request = JSON.parse(requestStr);

    // Validate OAuth 2.0 format
    if (!request.grant_type) {
      throw new Error('Missing grant_type parameter');
    }

    return request;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Validate OAuth token request
 * @param {object} request - Parsed token request
 * @returns {object} Validation result
 */
export function validateOAuthTokenRequest(request) {
  const errors = [];

  if (!request || typeof request !== 'object') {
    errors.push('Request must be an object');
    return { valid: false, errors };
  }

  // Validate grant type
  if (!request.grant_type) {
    errors.push('grant_type is required');
  } else {
    const validGrantTypes = [
      'authorization_code',
      'refresh_token',
      'client_credentials',
      'password'
    ];

    if (!validGrantTypes.includes(request.grant_type)) {
      errors.push(`Invalid grant_type: ${request.grant_type}`);
    }
  }

  // Validate based on grant type
  switch (request.grant_type) {
    case 'authorization_code':
      if (!request.code) {
        errors.push('authorization_code grant requires code parameter');
      }
      if (!request.redirect_uri) {
        errors.push('authorization_code grant requires redirect_uri parameter');
      }
      break;

    case 'refresh_token':
      if (!request.refresh_token) {
        errors.push('refresh_token grant requires refresh_token parameter');
      }
      break;

    case 'client_credentials':
      // Client credentials may not need additional parameters
      break;

    case 'password':
      if (!request.username) {
        errors.push('password grant requires username parameter');
      }
      if (!request.password) {
        errors.push('password grant requires password parameter');
      }
      break;
  }

  // Validate client credentials
  if (request.client_id && typeof request.client_id !== 'string') {
    errors.push('client_id must be a string');
  }

  if (request.client_secret && typeof request.client_secret !== 'string') {
    errors.push('client_secret must be a string');
  }

  // Check for malicious patterns in all string fields
  function checkMaliciousPatterns(obj, path = '') {
    if (typeof obj === 'string') {
      const maliciousPatterns = [
        '<script',
        'javascript:',
        'eval(',
        '../',
        '..\\',
        'UNION',
        'SELECT',
        'DROP',
        'DELETE',
        'INSERT',
        'UPDATE'
      ];

      for (const pattern of maliciousPatterns) {
        if (obj.includes(pattern)) {
          errors.push(`Malicious pattern "${pattern}" found in ${path || 'field'}`);
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const [key, value] of Object.entries(obj)) {
        const newPath = path ? `${path}.${key}` : key;
        checkMaliciousPatterns(value, newPath);
      }
    }
  }

  checkMaliciousPatterns(request);

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Parse OAuth token response
 * @param {string} responseStr - Token response string
 * @returns {object} Parsed token response
 */
export function parseOAuthTokenResponse(responseStr) {
  if (typeof responseStr !== 'string') {
    throw new TypeError('Response must be a string');
  }

  if (!responseStr.trim()) {
    throw new Error('Response cannot be empty');
  }

  try {
    const response = JSON.parse(responseStr);

    // Validate OAuth 2.0 response format
    if (response.error) {
      // Error response
      if (!response.error_description && !response.error_uri) {
        // At least one of these should be present
      }
    } else {
      // Success response should have access_token
      if (!response.access_token) {
        throw new Error('Success response must contain access_token');
      }
    }

    return response;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Validate OAuth token response
 * @param {object} response - Parsed token response
 * @returns {object} Validation result
 */
export function validateOAuthTokenResponse(response) {
  const errors = [];

  if (!response || typeof response !== 'object') {
    errors.push('Response must be an object');
    return { valid: false, errors };
  }

  if (response.error) {
    // Error response validation
    if (typeof response.error !== 'string') {
      errors.push('error must be a string');
    }

    if (response.error_description && typeof response.error_description !== 'string') {
      errors.push('error_description must be a string');
    }

    if (response.error_uri && typeof response.error_uri !== 'string') {
      errors.push('error_uri must be a string');
    }
  } else {
    // Success response validation
    if (!response.access_token || typeof response.access_token !== 'string') {
      errors.push('access_token is required and must be a string');
    }

    if (!response.token_type || typeof response.token_type !== 'string') {
      errors.push('token_type is required and must be a string');
    }

    if (response.expires_in !== undefined) {
      if (typeof response.expires_in !== 'number' || response.expires_in <= 0) {
        errors.push('expires_in must be a positive number');
      }
    }

    if (response.refresh_token && typeof response.refresh_token !== 'string') {
      errors.push('refresh_token must be a string');
    }

    if (response.scope && typeof response.scope !== 'string') {
      errors.push('scope must be a string');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create OAuth token request
 * @param {object} params - Request parameters
 * @returns {object} OAuth token request
 */
export function createOAuthTokenRequest(params) {
  if (!params || typeof params !== 'object') {
    throw new Error('Parameters are required');
  }

  if (!params.grant_type) {
    throw new Error('grant_type is required');
  }

  const request = {
    grant_type: params.grant_type
  };

  // Add optional parameters
  if (params.code) request.code = params.code;
  if (params.redirect_uri) request.redirect_uri = params.redirect_uri;
  if (params.refresh_token) request.refresh_token = params.refresh_token;
  if (params.client_id) request.client_id = params.client_id;
  if (params.client_secret) request.client_secret = params.client_secret;
  if (params.username) request.username = params.username;
  if (params.password) request.password = params.password;
  if (params.scope) request.scope = params.scope;

  return request;
}

/**
 * Create OAuth token response
 * @param {string} accessToken - Access token
 * @param {string} tokenType - Token type
 * @param {object} options - Additional options
 * @returns {object} OAuth token response
 */
export function createOAuthTokenResponse(accessToken, tokenType, options = {}) {
  if (!accessToken || typeof accessToken !== 'string') {
    throw new Error('access_token is required and must be a string');
  }

  if (!tokenType || typeof tokenType !== 'string') {
    throw new Error('token_type is required and must be a string');
  }

  const response = {
    access_token: accessToken,
    token_type: tokenType
  };

  // Add optional parameters
  if (options.expires_in !== undefined) {
    if (typeof options.expires_in === 'number' && options.expires_in > 0) {
      response.expires_in = options.expires_in;
    }
  }

  if (options.refresh_token) {
    response.refresh_token = options.refresh_token;
  }

  if (options.scope) {
    response.scope = options.scope;
  }

  return response;
}
