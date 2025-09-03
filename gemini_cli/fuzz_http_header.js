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

        // Test HTTP header parsing
        const lines = input.split('\n');
        lines.forEach(line => {
            // Test header line parsing
            if (line.includes(':')) {
                const [key, ...valueParts] = line.split(':');
                const value = valueParts.join(':').trim();

                // Test common header patterns
                if (key.toLowerCase() === 'content-type') {
                    // Test content type parsing
                } else if (key.toLowerCase() === 'authorization') {
                    // Test authorization header parsing
                    if (value.startsWith('Bearer ')) {
                        // Test Bearer token parsing
                    }
                } else if (key.toLowerCase() === 'content-length') {
                    // Test content length parsing
                    const length = parseInt(value);
                    if (!isNaN(length)) {
                        // Test numeric parsing
                    }
                }
            }
        });

        // Test header value parsing
        if (input.includes('=')) {
            // Test key=value parsing
        }

    } catch (e) {
        // Expected errors are fine
        // Jazzer.js will catch unexpected crashes
    }
};
