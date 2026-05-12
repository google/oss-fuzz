#!/bin/bash -eu
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# OSS-Fuzz build script. Compiles each of go-seccure's native Go fuzz
# targets (defined in fuzz_test.go) into a libFuzzer-compatible binary
# using compile_native_go_fuzzer, then OSS-Fuzz harnesses run them
# continuously on Google's infrastructure.

cd "${SRC}/go-seccure"

# `compile_native_go_fuzzer` generates a shim file that imports
# github.com/AdamKorcz/go-118-fuzz-build/testing — the standard
# adapter from Go's native fuzzing API to libFuzzer. The library's
# canonical go.mod doesn't include that dependency (we keep it
# zero-deps for the production library), so add it here inside the
# OSS-Fuzz build container. This `go get` only modifies the
# container's transient go.mod, not the upstream repo's.
go get github.com/AdamKorcz/go-118-fuzz-build/testing

# Each target gets its own libFuzzer binary. Seed corpora are pulled
# from each f.Add() entry automatically by the wrapper.
for target in \
    FuzzDecodeCompactNeverPanics \
    FuzzEncodeDecodeCompactRoundTrip \
    FuzzPassphraseToPubkeyNeverPanics \
    FuzzDecryptNeverPanics \
    FuzzVerifyBinaryNeverPanics \
    FuzzCurveByNameNeverPanics
do
    compile_native_go_fuzzer github.com/invenity-labs/go-seccure "${target}" "${target}"
done
