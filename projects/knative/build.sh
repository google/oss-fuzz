#!/bin/bash -eu
# Copyright 2022 Google LLC
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

printf "package metrics\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/pkg/metrics/registerfuzzdep.go
go mod tidy && go mod vendor
cp $SRC/json_fuzzer.go $SRC/pkg/webhook/json/
mv $SRC/pkg/webhook/json/decode_test.go $SRC/pkg/webhook/json/decode_test_fuzz.go
compile_go_fuzzer knative.dev/pkg/webhook/json FuzzJsonDecode fuzz_json_decode

cp $SRC/fuzz_pkg_metrics.go $SRC/pkg/metrics/
compile_native_go_fuzzer knative.dev/pkg/metrics FuzzNewObservabilityConfigFromConfigMap FuzzNewObservabilityConfigFromConfigMap

cp $SRC/fuzz_pkg_websocket.go $SRC/pkg/websocket/
mv $SRC/pkg/websocket/connection_test.go $SRC/pkg/websocket/connection_fuzz.go
compile_native_go_fuzzer knative.dev/pkg/websocket FuzzSendRawMessage FuzzSendRawMessage

cp $SRC/fuzz_activatornet.go $SRC/serving/pkg/activator/net/
cd $SRC/serving
mv pkg/activator/net/throttler_test.go pkg/activator/net/throttler_test_fuzz.go
mv pkg/activator/net/revision_backends_test.go pkg/activator/net/revision_backends_test_fuzz.go
printf "package net\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/serving/pkg/activator/net/registerfuzzdep.go
go mod tidy && go mod vendor
compile_native_go_fuzzer knative.dev/serving/pkg/activator/net FuzzNewRevisionThrottler FuzzNewRevisionThrottler
