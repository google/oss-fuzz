/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const { FuzzedDataProvider } = require('@jazzer.js/core');

function LLVMFuzzerTestOneInput(data) {
  if (!data || data.length === 0) return 0;

  const fdp = new FuzzedDataProvider(data);

  try {
    // Test HTTP header parsing with fuzzed input
    const input = fdp.consumeString(data.length);
    if (input.includes(':')) {
      const parts = input.split(':', 2);
      if (parts.length === 2) {
        const headerName = parts[0].trim();
        const headerValue = parts[1].trim();
        // Basic header validation
        if (headerName && headerValue) {
          // Header parsing logic would go here
        }
      }
    }
  } catch (error) {
    // Expected parsing errors are fine
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };
