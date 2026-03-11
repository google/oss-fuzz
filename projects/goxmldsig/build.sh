#!/bin/bash -eu

cd "${SRC}/goxmldsig"

# Register the go-118-fuzz-build testing dependency
printf "package dsig\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
printf "package etreeutils\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > etreeutils/registerfuzzdep.go
go get github.com/AdamKorcz/go-118-fuzz-build/testing
go mod tidy

compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzValidateXML FuzzValidateXML
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzCanonicalize FuzzCanonicalize
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzSignRoundTrip FuzzSignRoundTrip
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzValidateWithCert FuzzValidateWithCert
compile_native_go_fuzzer github.com/russellhaering/goxmldsig/etreeutils FuzzNSTraverse FuzzNSTraverse
compile_native_go_fuzzer github.com/russellhaering/goxmldsig/etreeutils FuzzTransformExcC14n FuzzTransformExcC14n
