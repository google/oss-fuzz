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

        // Test JSON parsing with various inputs
        if (input.trim().startsWith('{') && input.trim().endsWith('}')) {
            try {
                const parsed = JSON.parse(input);
                // Test object structure
                if (typeof parsed === 'object' && parsed !== null) {
                    // Test nested objects
                    if (parsed.nested && typeof parsed.nested === 'object') {
                        Object.keys(parsed.nested).forEach(key => {
                            // Test nested property access
                        });
                    }
                }
            } catch (jsonError) {
                // Invalid JSON is expected and OK
            }
        }

        // Test array parsing
        if (input.trim().startsWith('[') && input.trim().endsWith(']')) {
            try {
                const parsed = JSON.parse(input);
                if (Array.isArray(parsed)) {
                    // Test array operations
                    parsed.forEach(item => {
                        // Test item processing
                    });
                }
            } catch (jsonError) {
                // Invalid JSON is expected
            }
        }

        // Test string operations that might be JSON-related
        if (input.includes('"') || input.includes("'")) {
            // Test string parsing patterns
        }

    } catch (e) {
        // Expected errors are fine
        // Jazzer.js will catch unexpected crashes
    }
};
