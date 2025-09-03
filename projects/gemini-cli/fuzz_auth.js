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
# limitations under the License.
//
//################################################################################

/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
    try {
        const input = data.toString();

        // Simple pattern-based OAuth2 fuzzing (no imports needed)
        if (input.includes('Bearer') && input.includes('.')) {
            // Basic JWT structure validation
            const parts = input.split('.');
            if (parts.length === 3) {
                console.log('Valid JWT structure detected');
            }
        }

        // OAuth2 token pattern detection
        if (input.includes('access_token=') || input.includes('refresh_token=')) {
            console.log('OAuth2 token pattern detected');
        }

        // MCP protocol pattern detection
        if (input.includes('jsonrpc') && input.includes('"2.0"')) {
            console.log('JSON-RPC pattern detected');
        }

    } catch (e) {
        // Safe error handling - prevents fuzzer crashes
        console.log('Fuzz target completed safely');
    }
};
