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

# Navigate to the project directory
cd "$SRC/gemini-cli"

# 1. Install ALL dependencies (including devDependencies) so we can build.
npm ci

# 2. Compile the fuzzers. This step needs the devDependencies.
compile_javascript_fuzzer . fuzzers/fuzz_proxy_security.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_http_header.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_json_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_mcp_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_url.js --sync

# 3. Prune all devDependencies to make node_modules smaller.
npm prune --omit=dev

# 4. Re-install @jazzer.js/core, as it is a devDependency but is
#    required by the fuzzer at runtime.
npm install @jazzer.js/core


# 5. Archive the minimal node_modules into a single .tar.gz file.
#    This is MUCH faster than copying thousands of small files.
tar -czf node_modules.tar.gz node_modules

# 6. Copy the single archive file to the output directory. This is nearly instant.
cp node_modules.tar.gz "$OUT/"

# 7. **THE FINAL FIX:** Manually prepend a robust unpack command to each fuzzer.
#    This script ensures a clean state before unpacking, preventing race conditions.
for fuzzer in $(find $OUT -maxdepth 1 -type f -name 'fuzz_*'); do
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
# Change to the fuzzer's directory to ensure paths are correct.
cd \"\$(dirname \"\$0\")\"
# Remove any pre-existing node_modules to prevent conflicts.
rm -rf node_modules
# Manually unpack the node_modules directory.
tar -xzf node_modules.tar.gz
# Execute the original fuzzer script.
$(tail -n +2 $fuzzer)" > "$fuzzer"
done
