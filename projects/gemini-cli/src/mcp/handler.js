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
 * MCP (Model Control Protocol) Handler
 * Handles MCP protocol requests and responses
 */

/**
 * Parse MCP request
 * @param {string} requestStr - JSON-RPC request string
 * @returns {object} Parsed MCP request
 */
function parseMCPRequest(requestStr) {
  if (typeof requestStr !== 'string') {
    throw new TypeError('Request must be a string');
  }

  if (!requestStr.trim()) {
    throw new Error('Request cannot be empty');
  }

  try {
    const request = JSON.parse(requestStr);

    // Validate JSON-RPC 2.0 format
    if (!request.jsonrpc || request.jsonrpc !== '2.0') {
      throw new Error('Invalid JSON-RPC version');
    }

    if (!request.method || typeof request.method !== 'string') {
      throw new Error('Missing or invalid method');
    }

    if (request.id === undefined || request.id === null) {
      throw new Error('Missing request ID');
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
 * Validate MCP request
 * @param {object} request - Parsed MCP request
 * @returns {object} Validation result
 */
function validateMCPRequest(request) {
  const errors = [];

  if (!request || typeof request !== 'object') {
    errors.push('Request must be an object');
    return { valid: false, errors };
  }

  // Validate method
  if (!request.method) {
    errors.push('Method is required');
  } else if (typeof request.method !== 'string') {
    errors.push('Method must be a string');
  } else {
    const validMethods = [
      'tools/call',
      'tools/list',
      'resources/list',
      'resources/read',
      'prompts/list',
      'prompts/get'
    ];

    if (!validMethods.includes(request.method)) {
      errors.push(`Unknown method: ${request.method}`);
    }
  }

  // Validate ID
  if (request.id === undefined || request.id === null) {
    errors.push('ID is required');
  } else if (typeof request.id !== 'string' && typeof request.id !== 'number') {
    errors.push('ID must be a string or number');
  }

  // Validate params based on method
  if (request.params) {
    if (typeof request.params !== 'object') {
      errors.push('Params must be an object');
    } else {
      validateMethodParams(request.method, request.params, errors);
    }
  }

  // Check for malicious patterns
  const requestStr = JSON.stringify(request);
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
    if (requestStr.includes(pattern)) {
      errors.push(`Malicious pattern detected: ${pattern}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate method-specific parameters
 * @param {string} method - RPC method
 * @param {object} params - Parameters object
 * @param {string[]} errors - Error array to populate
 */
function validateMethodParams(method, params, errors) {
  switch (method) {
    case 'tools/call':
      if (!params.name || typeof params.name !== 'string') {
        errors.push('tools/call requires a name parameter');
      }
      if (params.arguments && typeof params.arguments !== 'object') {
        errors.push('tools/call arguments must be an object');
      }
      break;

    case 'resources/read':
      if (!params.uri || typeof params.uri !== 'string') {
        errors.push('resources/read requires a uri parameter');
      }
      // Check for path traversal in URI
      if (params.uri.includes('../') || params.uri.includes('..\\')) {
        errors.push('URI contains directory traversal');
      }
      break;

    case 'prompts/get':
      if (!params.name || typeof params.name !== 'string') {
        errors.push('prompts/get requires a name parameter');
      }
      break;
  }
}

/**
 * Create MCP response
 * @param {string|number} id - Request ID
 * @param {any} result - Result object
 * @param {object} error - Error object (optional)
 * @returns {object} MCP response
 */
function createMCPResponse(id, result, error = null) {
  const response = {
    jsonrpc: '2.0',
    id: id
  };

  if (error) {
    response.error = {
      code: error.code || -32603,
      message: error.message || 'Internal error',
      data: error.data
    };
  } else {
    response.result = result;
  }

  return response;
}

/**
 * Parse MCP response
 * @param {string} responseStr - JSON-RPC response string
 * @returns {object} Parsed MCP response
 */
function parseMCPResponse(responseStr) {
  if (typeof responseStr !== 'string') {
    throw new TypeError('Response must be a string');
  }

  if (!responseStr.trim()) {
    throw new Error('Response cannot be empty');
  }

  try {
    const response = JSON.parse(responseStr);

    // Validate JSON-RPC 2.0 format
    if (!response.jsonrpc || response.jsonrpc !== '2.0') {
      throw new Error('Invalid JSON-RPC version');
    }

    if (response.id === undefined || response.id === null) {
      throw new Error('Missing response ID');
    }

    if (response.result === undefined && response.error === undefined) {
      throw new Error('Response must have result or error');
    }

    if (response.result !== undefined && response.error !== undefined) {
      throw new Error('Response cannot have both result and error');
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
 * Validate MCP response
 * @param {object} response - Parsed MCP response
 * @returns {object} Validation result
 */
function validateMCPResponse(response) {
  const errors = [];

  if (!response || typeof response !== 'object') {
    errors.push('Response must be an object');
    return { valid: false, errors };
  }

  // Validate ID
  if (response.id === undefined || response.id === null) {
    errors.push('ID is required');
  }

  // Validate result or error
  if (response.result === undefined && response.error === undefined) {
    errors.push('Response must have result or error');
  }

  if (response.result !== undefined && response.error !== undefined) {
    errors.push('Response cannot have both result and error');
  }

  // Validate error format
  if (response.error) {
    if (typeof response.error !== 'object') {
      errors.push('Error must be an object');
    } else {
      if (typeof response.error.code !== 'number') {
        errors.push('Error code must be a number');
      }
      if (typeof response.error.message !== 'string') {
        errors.push('Error message must be a string');
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

module.exports = {
  parseMCPRequest,
  validateMCPRequest,
  createMCPResponse,
  parseMCPResponse,
  validateMCPResponse
};
