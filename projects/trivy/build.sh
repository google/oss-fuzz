#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/aquasecurity/trivy FuzzPURLParse fuzz_purl_parse
compile_go_fuzzer github.com/aquasecurity/trivy FuzzPURLRoundTrip fuzz_purl_roundtrip
