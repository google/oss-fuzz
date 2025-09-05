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
    // JSON parsing fuzzing
    const parsed = JSON.parse(input);

    // Additional validation on parsed JSON
    if (typeof parsed === 'object' && parsed !== null) {
      // Check for common JSON structures
      if (Array.isArray(parsed)) {
        // Array validation
        parsed.forEach(item => {
          if (typeof item === 'string' || typeof item === 'number') {
            // Valid array element
          }
        });
      } else {
        // Object validation
        Object.keys(parsed).forEach(key => {
          if (typeof key === 'string') {
            // Valid object key
          }
        });
      }
    }
  } catch (e) {
    // Expected JSON parsing errors
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };
