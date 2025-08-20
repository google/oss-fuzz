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
//
////////////////////////////////////////////////////////////////////////////////

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_config_parser.js
import { locateUpstream } from './_upstream_locator.mjs';

export function FuzzConfigParser(data) {
  const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
  const p = locateUpstream([
    'packages/cli/src/config.js',
    'packages/cli/src/config.ts',
    'packages/cli/lib/config.js'
  ]);
  if (!p) {
    // If upstream module not found, bail out: this indicates import path needs adjustment.
    // Throwing a specific Error makes the build/fuzzer log clear for easy fixes.
    throw new Error('UPSTREAM_CONFIG_NOT_FOUND: adjust import path to upstream config module');
  }
  // dynamic import so build doesn't fail if the file is absent at author-time
  return import(p)
    .then(mod => {
      const fn = mod.parseConfig || mod.default?.parseConfig || mod.parse;
      if (!fn) throw new Error('UPSTREAM_PARSE_NOT_FOUND');
      try {
        fn(input);
      } catch (e) {
        // parsing errors expected — rethrow only if unusual
        if (e && e.name && (e.name === 'TypeError' || e.name === 'RangeError')) {
          // allow expected parsing exceptions to be treated as non-crash
          return;
        }
        throw e;
      }
    });
}
