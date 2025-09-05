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
    // URL parsing fuzzing
    if (input.includes('://') || input.startsWith('http')) {
      const url = new URL(input);

      // Validate URL components
      if (url.protocol) {
        // Valid protocol
      }
      if (url.hostname) {
        // Valid hostname
      }
      if (url.pathname) {
        // Valid pathname
      }
      if (url.search) {
        // Valid query string
      }
      if (url.hash) {
        // Valid hash fragment
      }
    }
  } catch (e) {
    // Expected URL parsing errors
  }

  return 0;
}

module.exports = { LLVMFuzzerTestOneInput };
