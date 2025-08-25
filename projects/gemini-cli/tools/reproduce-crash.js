#!/usr/bin/env node
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

/**
 * OSS-Fuzz Crash Reproduction Script for gemini-cli
 * 
 * Usage: node reproduce-crash.js <fuzzer-name> <testcase-file>
 * Example: node reproduce-crash.js FuzzConfigParser crash-12345
 */

import fs from 'fs';
import path from 'path';

const FUZZERS = {
  'FuzzConfigParser': './fuzz_config_parser.js',
  'FuzzCLIParser': './fuzz_cli_parser.js',
  'FuzzMCPRequest': './fuzz_mcp_request.js',
  'FuzzMCPResponse': './fuzz_mcp_response.js',
  'FuzzOAuthTokenRequest': './fuzz_oauth_token_request.js',
  'FuzzOAuthTokenResponse': './fuzz_oauth_token_response.js'
};

function printUsage() {
  console.log('Usage: node reproduce-crash.js <fuzzer-name> <testcase-file>');
  console.log('Available fuzzers:', Object.keys(FUZZERS).join(', '));
  console.log('');
  console.log('Example:');
  console.log('  node reproduce-crash.js FuzzConfigParser crash-12345');
  console.log('  node reproduce-crash.js FuzzCLIParser /path/to/testcase.txt');
}

async function reproduceCrash(fuzzerName, testcaseFile) {
  if (!FUZZERS[fuzzerName]) {
    console.error(`❌ Unknown fuzzer: ${fuzzerName}`);
    printUsage();
    process.exit(1);
  }

  if (!fs.existsSync(testcaseFile)) {
    console.error(`❌ Testcase file not found: ${testcaseFile}`);
    process.exit(1);
  }

  console.log(`🔍 Reproducing crash with ${fuzzerName} using ${testcaseFile}`);
  console.log('');

  try {
    // Read the testcase
    const testcaseData = fs.readFileSync(testcaseFile);
    console.log(`📄 Testcase size: ${testcaseData.length} bytes`);
    console.log(`📄 Testcase preview: ${testcaseData.slice(0, 100).toString('utf8')}...`);
    console.log('');

    // Import the fuzzer
    console.log(`📦 Loading fuzzer: ${FUZZERS[fuzzerName]}`);
    const fuzzerModule = await import(FUZZERS[fuzzerName]);
    const fuzzerFunction = fuzzerModule[fuzzerName];

    if (!fuzzerFunction) {
      console.error(`❌ Fuzzer function ${fuzzerName} not found in module`);
      process.exit(1);
    }

    console.log('✅ Fuzzer loaded successfully');
    console.log('');

    // Run the fuzzer with the testcase
    console.log('🚀 Running fuzzer with testcase...');
    console.log('');

    try {
      await fuzzerFunction(testcaseData);
      console.log('✅ Fuzzer completed without crash');
      console.log('⚠️  This may indicate:');
      console.log('   - Testcase was minimized and no longer triggers the issue');
      console.log('   - Issue was fixed in upstream code');
      console.log('   - Different sanitizer or environment needed');
    } catch (error) {
      console.log('💥 CRASH REPRODUCED!');
      console.log('');
      console.log('📋 Crash Details:');
      console.log(`   Error Type: ${error.constructor.name}`);
      console.log(`   Message: ${error.message}`);
      console.log('');
      console.log('📋 Stack Trace:');
      console.log(error.stack);
      console.log('');
      console.log('📋 Next Steps:');
      console.log('   1. Create minimal reproducer');
      console.log('   2. Add failing test to upstream repo');
      console.log('   3. File security issue with upstream team');
      console.log('   4. Include this testcase and stack trace');
    }

  } catch (error) {
    console.error('❌ Error during reproduction:', error);
    process.exit(1);
  }
}

// Main execution
const args = process.argv.slice(2);

if (args.length !== 2) {
  printUsage();
  process.exit(1);
}

const [fuzzerName, testcaseFile] = args;
reproduceCrash(fuzzerName, testcaseFile);
