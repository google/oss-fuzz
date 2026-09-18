#!/bin/bash -eu

# Copyright 2025 The OSS-Fuzz project authors
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

# Build script for OSS-Fuzz (Python/Atheris) project: modelcontextprotocol
# Reference: https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new-project-guide/python_lang.md

# Locate the latest MCP JSON schema within the cloned repository.
# Expected structure: $SRC/modelcontextprotocol/schema/<date>/schema.json
SCHEMA_DIR=$(ls -d $SRC/modelcontextprotocol/schema/*/ 2>/dev/null | sort | tail -n1 || true)
SCHEMA_JSON=""
if [ -n "${SCHEMA_DIR}" ] && [ -f "${SCHEMA_DIR}/schema.json" ]; then
  SCHEMA_JSON="${SCHEMA_DIR}/schema.json"
fi

# Build fuzzers into $OUT using PyInstaller for a hermetic binary.
# We assume all required Python deps were installed in the Dockerfile.
FUZZER_SRC="$SRC/mcp_schema_fuzzer.py"
FUZZER_NAME_PKG="mcp_schema_fuzzer.pkg"
FUZZER_WRAPPER_NAME="mcp_schema_fuzzer"

pyinstaller --distpath "$OUT" --onefile --name "$FUZZER_NAME_PKG" "$FUZZER_SRC"

# Provide schema.json next to the packaged binary if found; the harness prefers
# an adjacent schema.json, but also supports MCP_SCHEMA_PATH env var.
if [ -n "$SCHEMA_JSON" ]; then
  cp "$SCHEMA_JSON" "$OUT/schema.json"
fi

# Create execution wrapper used by OSS-Fuzz
# Note: Because this fuzzer is pure-Python (no native extensions), do NOT set LD_PRELOAD.
cat > "$OUT/$FUZZER_WRAPPER_NAME" << 'EOF'
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=$(dirname "$0")
export MCP_SCHEMA_PATH="$this_dir/schema.json"
"$this_dir/mcp_schema_fuzzer.pkg" "$@"
EOF
chmod +x "$OUT/$FUZZER_WRAPPER_NAME"

# Optionally copy .options or .dict files if present in repository
if ls $SRC/*.options >/dev/null 2>&1; then
  cp $SRC/*.options "$OUT/" || true
fi
if ls $SRC/*.dict >/dev/null 2>&1; then
  cp $SRC/*.dict "$OUT/" || true
fi
