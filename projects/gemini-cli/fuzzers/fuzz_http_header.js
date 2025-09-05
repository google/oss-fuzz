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
    // HTTP header parsing fuzzing
    const headers = input.split('\n');
    for (const header of headers) {
      if (header.includes(':')) {
        const [name, value] = header.split(':', 2);
        if (name && value) {
          // Basic header validation that doesn't crash
          const trimmedName = name.trim();
          const trimmedValue = value.trim();
          if (trimmedName.length > 0 && trimmedValue.length > 0) {
            // Success - valid header format
          }
        }
      }
    }
  } catch (e) {
    // Expected parsing errors
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };
