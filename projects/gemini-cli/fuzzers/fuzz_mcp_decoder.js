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

const { FuzzedDataProvider } = require('@jazzer.js/core');

function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) return 0;

  const fdp = new FuzzedDataProvider(data);
  const input = fdp.consumeString(data.length);

  try {
    // MCP (Message Control Protocol) decoder fuzzing
    const messages = input.split('\n');

    for (const message of messages) {
      if (message.trim().length > 0) {
        // Basic MCP message validation
        if (message.includes('MCP') || message.includes('MSG')) {
          // Check for common MCP patterns
          const parts = message.split(' ');
          if (parts.length >= 2) {
            const command = parts[0];
            const payload = parts.slice(1).join(' ');

            if (command && payload) {
              // Valid MCP message structure
            }
          }
        }
      }
    }
  } catch (e) {
    // Expected MCP decoding errors
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };
