#!/bin/bash -eu 
 
cd $SRC/go-github 
go mod download 
go install github.com/AdamKorcz/go-118-fuzz-build@latest 
go get github.com/AdamKorcz/go-118-fuzz-build/testing 
 
compile_native_go_fuzzer github.com/google/go-github/v84/github FuzzParseWebHook fuzz_parse_webhook 
