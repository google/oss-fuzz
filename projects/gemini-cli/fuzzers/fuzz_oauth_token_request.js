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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_oauth_token_request.js
import { locateUpstream } from './_upstream_locator.mjs';

export function FuzzOAuthTokenRequest(data) {
  const input = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
  const p = locateUpstream([
    'packages/cli/src/oauth.js',
    'packages/core/src/oauth.js',
    'packages/cli/lib/oauth.js'
  ]);
  if (!p) throw new Error('UPSTREAM_OAUTH_NOT_FOUND');
  return import(p).then(mod => {
    const parse = mod.parseTokenRequest || mod.parseOAuthRequest || mod.decodeOAuth;
    if (!parse) throw new Error('UPSTREAM_OAUTH_PARSE_NOT_FOUND');
    try {
      parse(input);
    } catch (e) {
      if (e && e.name === 'SyntaxError') return;
      throw e;
    }
  });
}
