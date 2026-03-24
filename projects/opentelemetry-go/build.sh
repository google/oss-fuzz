#!/bin/bash -eu
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

REPO=$PWD

cd $REPO/attribute
# Mitigate the error: found packages attribute_test and attribute in /src/opentelemetry-go/attribute.
# Remove all Go files with *_test package before building the fuzzer.
# Tracking issue: https://github.com/google/oss-fuzz/issues/7923.
grep -rl --include="*.go" '^package .*_test' . | xargs rm -f 
compile_native_go_fuzzer_v2 $(go list) FuzzHashKVs sdk_attribute_FuzzHashKVs

cd $REPO/sdk/metric/internal/aggregate
compile_native_go_fuzzer_v2 $(go list) FuzzGetBin sdk_metric_internal_aggregate_FuzzGetBin

cd $REPO/trace
compile_native_go_fuzzer_v2 $(go list) FuzzTraceIDFromHex trace_FuzzTraceIDFromHex
compile_native_go_fuzzer_v2 $(go list) FuzzSpanIDFromHex trace_FuzzSpanIDFromHex
