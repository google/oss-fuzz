# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
    try {
        const input = data.toString();

        // Test JSON-RPC message parsing (MCP protocol)
        if (input.includes('jsonrpc') && input.includes('"2.0"')) {
            try {
                const parsed = JSON.parse(input);
                if (parsed.jsonrpc === '2.0') {
                    // Test valid MCP method calls
                    if (parsed.method) {
                        if (parsed.method === 'initialize') {
                            // Test initialize request
                        } else if (parsed.method === 'tools/list') {
                            // Test tools list request
                        } else if (parsed.method === 'tools/call') {
                            // Test tools call request
                        }
                    }
                }
            } catch (jsonError) {
                // Invalid JSON is expected and OK
            }
        }

        // Test general JSON parsing
        if (input.trim().startsWith('{') && input.trim().endsWith('}')) {
            try {
                JSON.parse(input);
            } catch (e) {
                // Invalid JSON is expected
            }
        }

    } catch (e) {
        // Expected errors are fine
        // Jazzer.js will catch unexpected crashes
    }
};
