#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cp $SRC/json_fuzzer.go $SRC/jaeger/cmd/collector/app/zipkin/
cp $SRC/thrift_fuzzer.go $SRC/jaeger/model/converter/thrift/zipkin/

compile_go_fuzzer github.com/jaegertracing/jaeger/cmd/collector/app/zipkin Fuzz json_fuzzer
compile_go_fuzzer github.com/jaegertracing/jaeger/model/converter/thrift/zipkin Fuzz thrift_fuzzer
