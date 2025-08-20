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

// oss-fuzz/projects/gemini-cli/fuzzers/fuzz_mcp_request.js
import { locateUpstream } from './_upstream_locator.mjs';

export function FuzzMCPRequest(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const p = locateUpstream([
    'packages/core/src/mcp.js',
    'packages/cli/src/mcp.js',
    'packages/core/lib/mcp.js'
  ]);
  if (!p) throw new Error('UPSTREAM_MCP_NOT_FOUND');
  return import(p).then(mod => {
    const decode = mod.decodeMCPRequest || mod.decodeRequest || mod.parseMCP;
    if (!decode) throw new Error('UPSTREAM_MCP_DECODE_NOT_FOUND');
    try {
      decode(input);
    } catch (e) {
      // expected decode errors are fine
      if (e && e.name === 'TypeError') return;
      throw e;
    }
  });
}
