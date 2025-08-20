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
 * Gemini CLI Configuration Parser
 * Parses configuration files in JSON/TOML format
 */

/**
 * Parse configuration from string
 * @param {string} configStr - Configuration string
 * @returns {object} Parsed configuration object
 */
function parseConfig(configStr) {
  if (typeof configStr !== 'string') {
    throw new TypeError('Configuration must be a string');
  }

  if (!configStr.trim()) {
    throw new Error('Configuration string cannot be empty');
  }

  try {
    // Try JSON first
    return JSON.parse(configStr);
  } catch (jsonError) {
    // If JSON fails, try basic TOML-like parsing
    return parseTomlConfig(configStr);
  }
}

/**
 * Parse TOML-like configuration
 * @param {string} configStr - Configuration string
 * @returns {object} Parsed configuration object
 */
function parseTomlConfig(configStr) {
  const config = {};
  const lines = configStr.split('\n');
  let currentSection = config;

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      continue; // Skip empty lines and comments
    }

    // Section header
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const sectionName = trimmed.slice(1, -1);
      config[sectionName] = config[sectionName] || {};
      currentSection = config[sectionName];
      continue;
    }

    // Key-value pair
    const equalsIndex = trimmed.indexOf('=');
    if (equalsIndex > 0) {
      const key = trimmed.substring(0, equalsIndex).trim();
      const value = trimmed.substring(equalsIndex + 1).trim();

      if (key && value !== undefined) {
        currentSection[key] = parseValue(value);
      }
    }
  }

  return config;
}

/**
 * Parse configuration value
 * @param {string} value - Value string
 * @returns {any} Parsed value
 */
function parseValue(value) {
  // Remove quotes
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }

  // Try to parse as number
  if (/^-?\d+(\.\d+)?$/.test(value)) {
    const num = parseFloat(value);
    return isNaN(num) ? value : num;
  }

  // Try to parse as boolean
  if (value.toLowerCase() === 'true') return true;
  if (value.toLowerCase() === 'false') return false;

  // Try to parse as array
  if (value.startsWith('[') && value.endsWith(']')) {
    const arrayContent = value.slice(1, -1);
    return arrayContent.split(',')
      .map(item => parseValue(item.trim()))
      .filter(item => item !== '');
  }

  return value;
}

/**
 * Validate parsed configuration
 * @param {object} config - Parsed configuration
 * @returns {object} Validation result
 */
function validateConfig(config) {
  const errors = [];

  if (!config || typeof config !== 'object') {
    errors.push('Configuration must be an object');
    return { valid: false, errors };
  }

  // Validate API key
  if (config.apiKey) {
    if (typeof config.apiKey !== 'string' || config.apiKey.length < 32) {
      errors.push('API key must be a string of at least 32 characters');
    }
  }

  // Validate model
  if (config.model) {
    const validModels = [
      'gemini-pro',
      'gemini-pro-vision',
      'gemini-1.5-pro',
      'gemini-1.5-flash'
    ];

    if (!validModels.includes(config.model)) {
      errors.push(`Invalid model: ${config.model}`);
    }
  }

  // Validate temperature
  if (config.temperature !== undefined) {
    const temp = parseFloat(config.temperature);
    if (isNaN(temp) || temp < 0 || temp > 2.0) {
      errors.push('Temperature must be a number between 0 and 2.0');
    }
  }

  // Validate max tokens
  if (config.maxTokens !== undefined) {
    const tokens = parseInt(config.maxTokens, 10);
    if (isNaN(tokens) || tokens <= 0 || tokens > 100000) {
      errors.push('Max tokens must be a positive integer up to 100000');
    }
  }

  // Validate tools array
  if (config.tools) {
    if (!Array.isArray(config.tools)) {
      errors.push('Tools must be an array');
    } else {
      config.tools.forEach((tool, index) => {
        if (!tool.name || typeof tool.name !== 'string') {
          errors.push(`Tool at index ${index} must have a name`);
        }
        if (!tool.type || !['function', 'shell', 'file'].includes(tool.type)) {
          errors.push(`Tool at index ${index} must have a valid type`);
        }
      });
    }
  }

  // Check for malicious patterns in string values
  function checkForMaliciousPatterns(obj, path = '') {
    if (typeof obj === 'string') {
      const maliciousPatterns = [
        '<script',
        'javascript:',
        'eval(',
        'document.',
        '../',
        '..\\',
        'UNION SELECT',
        'DROP TABLE',
        'DELETE FROM',
        'INSERT INTO',
        'UPDATE '
      ];

      for (const pattern of maliciousPatterns) {
        if (obj.includes(pattern)) {
          errors.push(`Malicious pattern "${pattern}" found at ${path || 'root'}`);
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const [key, value] of Object.entries(obj)) {
        const newPath = path ? `${path}.${key}` : key;
        checkForMaliciousPatterns(value, newPath);
      }
    }
  }

  checkForMaliciousPatterns(config);

  return {
    valid: errors.length === 0,
    errors
  };
}

module.exports = {
  parseConfig,
  validateConfig
};
