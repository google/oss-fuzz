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
#
# OSS-Fuzz build script for AgentBridge (IntelliJ Copilot Plugin).
# Called inside the Docker container by OSS-Fuzz infrastructure.
# $SRC, $OUT, and $JAVA_HOME are set by the base image.

cd /src/agentbridge

# Build all test classes (fuzz targets live in the test source sets).
./gradlew :plugin-core:testClasses :mcp-server:testClasses --no-daemon --quiet

# Resolve full test runtime classpaths (includes compiled classes + all dep JARs).
CP_CORE=$(./gradlew :plugin-core:printFuzzClasspath --no-daemon -q | tail -1)
CP_MCP=$(./gradlew :mcp-server:printFuzzClasspath --no-daemon -q | tail -1)

# Copy every JAR from the classpath into $OUT/ and every class directory into
# $OUT/classes/.  The jazzer_driver wrapper uses "$this_dir/*" (Java wildcard
# classpath) and "$this_dir/classes" at fuzzing runtime.
mkdir -p "$OUT/classes"
for cp in "$CP_CORE" "$CP_MCP"; do
  IFS=':' read -ra entries <<< "$cp"
  for entry in "${entries[@]}"; do
    if [[ -f "$entry" && "$entry" == *.jar ]]; then
      cp -n "$entry" "$OUT/" 2>/dev/null || true
    elif [[ -d "$entry" ]]; then
      cp -rn "$entry/." "$OUT/classes/" 2>/dev/null || true
    fi
  done
done

# Fuzz target classes — each exposes fuzzerTestOneInput(FuzzedDataProvider).
TARGETS=(
  com.github.catatafishen.agentbridge.fuzz.AgentIdMapperFuzz
  com.github.catatafishen.agentbridge.fuzz.MarkdownRendererFuzz
  com.github.catatafishen.agentbridge.fuzz.TimeArgParserFuzz
  com.github.catatafishen.agentbridge.fuzz.AbuseDetectorFuzz
  com.github.catatafishen.agentbridge.fuzz.NewSessionResponseFuzz
  com.github.catatafishen.agentbridge.fuzz.JunitXmlParserFuzz
  com.github.copilot.mcp.McpStdioProxyFuzz
)

for target in "${TARGETS[@]}"; do
  short_name="${target##*.}"

  # Create the execution wrapper (the file OSS-Fuzz treats as the fuzzer binary).
  cat > "$OUT/${short_name}" << EOF
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
if [[ "\$@" =~ (^| )-runs=[0-9]+(\$| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH="${JVM_LD_LIBRARY_PATH}:\$this_dir" \\
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \\
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \\
--cp=\$this_dir/classes:\$this_dir/* \\
--target_class=${target} \\
--jvm_args="\$mem_settings" \\
"\$@"
EOF
  chmod +x "$OUT/${short_name}"
done
