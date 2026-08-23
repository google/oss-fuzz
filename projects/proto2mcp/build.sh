#!/bin/bash -eu
# OSS-Fuzz build script for proto2mcp
# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/

compile_native_go_fuzzer github.com/protocgen/proto2mcp/pkg/mcpruntime FuzzSanitizeErrorMessage fuzz_sanitize_error_message
compile_native_go_fuzzer github.com/protocgen/proto2mcp/pkg/mcpruntime FuzzTruncateUTF8 fuzz_truncate_utf8
compile_native_go_fuzzer github.com/protocgen/proto2mcp/pkg/mcpruntime FuzzUnmarshalToolInput fuzz_unmarshal_tool_input
compile_native_go_fuzzer github.com/protocgen/proto2mcp/pkg/mcpruntime FuzzResourceKeyExtraction fuzz_resource_key_extraction
