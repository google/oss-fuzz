#!/bin/bash -eu
cd $SRC/gemini-cli

# Compile all fuzzers
compile_javascript_fuzzer . fuzzers/fuzz_proxy_security.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_http_header.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_json_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_mcp_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_url.js --sync
