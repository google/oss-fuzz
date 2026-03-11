#!/bin/bash -eu

cd "${SRC}/gosaml2"

# Register the go-118-fuzz-build testing dependency
printf "package fuzz\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > internal/fuzz/registerfuzzdep.go
go get github.com/AdamKorcz/go-118-fuzz-build/testing
go mod tidy

compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzDecodeResponse FuzzDecodeResponse
compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzLogoutResponse FuzzLogoutResponse
compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzBuildRequest FuzzBuildRequest
