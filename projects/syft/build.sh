#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/anchore/syft FuzzCPEParse fuzz_cpe_parse
compile_go_fuzzer github.com/anchore/syft FuzzCPEBind fuzz_cpe_bind
