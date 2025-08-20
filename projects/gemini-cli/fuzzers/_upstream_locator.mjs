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

// oss-fuzz/projects/gemini-cli/fuzzers/_upstream_locator.mjs
import fs from 'fs';
import path from 'path';

export function locateUpstream(modulePaths=[]) {
  // try a list of plausible JS/TS paths relative to /src/gemini-cli
  const base = '/src/gemini-cli';
  const candidates = modulePaths.length ? modulePaths : [
    'packages/cli/src/index.js',
    'packages/cli/src/config.js',
    'packages/cli/lib/index.js',
    'packages/cli/dist/index.js',
    'packages/cli/index.js',
    'packages/cli/src/cli.js'
  ];
  for (const rel of candidates) {
    const p = path.join(base, rel);
    if (fs.existsSync(p)) return p;
  }
  // not found — return null to let the caller handle gracefully
  return null;
}
