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
 * URL Parser for Gemini CLI
 * Handles URL parsing, validation, and security checks
 */

/**
 * Parse URL string into components
 * @param {string} urlStr - URL string to parse
 * @returns {object} Parsed URL components
 */
function parseURL(urlStr) {
    if (typeof urlStr !== 'string') {
        throw new TypeError('URL must be a string');
    }

    if (!urlStr.trim()) {
        throw new Error('URL cannot be empty');
    }

    try {
        const url = new URL(urlStr);
        return {
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port,
            pathname: url.pathname,
            search: url.search,
            hash: url.hash,
            host: url.host,
            origin: url.origin,
            href: url.href
        };
    } catch (error) {
        throw new Error(`Invalid URL: ${error.message}`);
    }
}

/**
 * Validate URL for security and correctness
 * @param {string} urlStr - URL string to validate
 * @returns {boolean} True if URL is valid and safe
 */
function validateURL(urlStr) {
    if (typeof urlStr !== 'string') {
        return false;
    }

    if (!urlStr.trim()) {
        return false;
    }

    try {
        const url = new URL(urlStr);

        // Check for suspicious protocols
        const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
        if (dangerousProtocols.some(protocol => urlStr.toLowerCase().startsWith(protocol))) {
            return false;
        }

        // Check for suspicious hostnames
        const suspiciousHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
        if (suspiciousHosts.includes(url.hostname.toLowerCase())) {
            return false;
        }

        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Sanitize URL to prevent malicious content
 * @param {string} urlStr - URL string to sanitize
 * @returns {string} Sanitized URL string
 */
function sanitizeURL(urlStr) {
    if (typeof urlStr !== 'string') {
        throw new TypeError('URL must be a string');
    }

    if (!urlStr.trim()) {
        throw new Error('URL cannot be empty');
    }

    try {
        // Remove potential script tags and dangerous content
        let sanitized = urlStr
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/data:/gi, '')
            .replace(/vbscript:/gi, '')
            .replace(/onload=/gi, '')
            .replace(/onerror=/gi, '');

        // Ensure the URL is valid after sanitization
        new URL(sanitized);

        return sanitized;
    } catch (error) {
        throw new Error(`Cannot sanitize URL: ${error.message}`);
    }
}

module.exports = {
    parseURL,
    validateURL,
    sanitizeURL
};
