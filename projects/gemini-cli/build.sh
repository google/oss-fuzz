#!/bin/bash -eu
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd $SRC/gemini-cli

# Install Node.js dependencies
npm install

# Build the project
npm run build

# Build fuzzers for JavaScript/TypeScript
# Note: This is a placeholder - actual fuzz targets need to be implemented
# based on the TypeScript codebase structure

# For now, create minimal fuzz targets for the main packages
if [ -d "packages/cli" ]; then
    # CLI argument parsing fuzz target
    cat > $SRC/fuzz_cli_parser.js << 'EOF'
const cli = require('./packages/cli');

function fuzzCliParser(data) {
  try {
    const input = data.toString();
    // Add CLI parsing logic here
    cli.parse(input);
  } catch (e) {
    // Expected errors are fine
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = fuzzCliParser;
}
EOF

    compile_javascript_fuzzer $SRC/fuzz_cli_parser.js fuzz_cli_parser
fi

if [ -d "packages/core" ]; then
    # Core functionality fuzz target
    cat > $SRC/fuzz_core.js << 'EOF'
const core = require('./packages/core');

function fuzzCore(data) {
  try {
    const input = data.toString();
    // Add core functionality testing here
    core.process(input);
  } catch (e) {
    // Expected errors are fine
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = fuzzCore;
}
EOF

    compile_javascript_fuzzer $SRC/fuzz_core.js fuzz_core
fi

# Copy seed corpora if they exist
if [ -d "oss-fuzz/gemini_cli/corpus" ]; then
    cp -r oss-fuzz/gemini_cli/corpus/* $OUT/ 2>/dev/null || true
fi

find . -name "*.dict" -exec cp {} $OUT/ \; 2>/dev/null || true
