#!/usr/bin/env node
/**
 * reproduce-crash.js
 *
 * Usage:
 *   node reproduce-crash.js <FuzzerName> <testcase-file>
 *
 * Example:
 *   node reproduce-crash.js FuzzConfigParser /tmp/crashcase
 *
 * The script expects the fuzzer modules to live in the same directory:
 *   fuzz_config_parser.js, fuzz_cli_parser.js, fuzz_mcp_request.js, ...
 *
 * It returns exit code 0 on success (no uncaught exceptions),
 * and exit code 1 if the target throws an error (prints stack).
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const MAPPING = {
  FuzzConfigParser: './fuzz_config_parser.js',
  FuzzCLIParser: './fuzz_cli_parser.js',
  FuzzMCPRequest: './fuzz_mcp_request.js',
  FuzzMCPResponse: './fuzz_mcp_response.js',
  FuzzOAuthTokenRequest: './fuzz_oauth_token_request.js',
  FuzzOAuthTokenResponse: './fuzz_oauth_token_response.js'
};

async function main() {
  const [,, fuzzerName, testcasePath] = process.argv;
  if (!fuzzerName || !testcasePath) {
    console.error('Usage: node reproduce-crash.js <FuzzerName> <testcase-file>');
    console.error('Available fuzzers:', Object.keys(MAPPING).join(', '));
    process.exit(2);
  }

  const rel = MAPPING[fuzzerName];
  if (!rel) {
    console.error('Unknown fuzzer name:', fuzzerName);
    console.error('Available fuzzers:', Object.keys(MAPPING).join(', '));
    process.exit(2);
  }

  // Resolve path relative to this script location
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const modulePath = path.resolve(__dirname, rel);

  try {
    await fs.access(testcasePath);
  } catch (e) {
    console.error('Testcase file not found:', testcasePath);
    process.exit(2);
  }

  // read testcase as Buffer
  let data;
  try {
    data = await fs.readFile(testcasePath);
  } catch (e) {
    console.error('Failed to read testcase:', e);
    process.exit(2);
  }

  // dynamic import with file:// URL
  try {
    const mod = await import('file://' + modulePath);
    // exported function name equals the fuzzer name
    const fn = mod[fuzzerName] || mod.default?.[fuzzerName] || (typeof mod.default === 'function' ? mod.default : undefined);
    if (!fn) {
      console.error(`Fuzzer export not found in ${modulePath}. Expected export named: ${fuzzerName}`);
      process.exit(2);
    }

    // Invoke and await if it returns a Promise
    const res = fn(data);
    if (res && typeof res.then === 'function') {
      await res;
    }
    console.log('Fuzzer finished without throwing (no crash reproduced).');
    process.exit(0);
  } catch (e) {
    console.error('=== Reproduction run threw ===');
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
  }
}

main();
