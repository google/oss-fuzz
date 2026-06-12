#!/bin/bash -eu
go mod download


compile_go_fuzzer github.com/goharbor/harbor/src FuzzValidateHTTPURL fuzz_validate_url
compile_go_fuzzer github.com/goharbor/harbor/src FuzzParseRef fuzz_parse_ref
