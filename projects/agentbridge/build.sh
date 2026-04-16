#!/bin/bash -eu
#
# OSS-Fuzz build script for AgentBridge (IntelliJ Copilot Plugin).
# Called inside the Docker container by OSS-Fuzz infrastructure.
# $SRC, $OUT, and $JAVA_HOME are set by the base image.

cd /src/agentbridge

# Build all test classes (includes fuzz targets)
./gradlew :plugin-core:testClasses :mcp-server:testClasses --no-daemon --quiet

# Resolve full test runtime classpath for each module
CP_CORE=$(./gradlew :plugin-core:printFuzzClasspath --no-daemon -q | tail -1)
CP_MCP=$(./gradlew :mcp-server:printFuzzClasspath --no-daemon -q | tail -1)
FULL_CP="${CP_CORE}:${CP_MCP}"

# Fuzz target classes — each has a fuzzerTestOneInput(FuzzedDataProvider) entry point
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

  # compile_java_fuzzer is provided by the base-builder-jvm image
  compile_java_fuzzer "/src/agentbridge" "$target" "$OUT/${short_name}" "$FULL_CP"
done
