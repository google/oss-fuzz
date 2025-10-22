#!/bin/bash -eu
# Copyright 2023 Google LLC
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

go get github.com/AdamKorcz/go-118-fuzz-build/testing
go run internal/cmd/build-oss-fuzz-corpus/main.go $OUT/fuzz_decode_seed_corpus.zip

mv bson/fuzz_test.go bson/fuzz.go
mv bson/bson_corpus_spec_test.go bson/bson_corpus_spec.go

sed -i '/seedBSONCorpus/d' bson/fuzz.go

compile_native_go_fuzzer go.mongodb.org/mongo-driver/v2/bson FuzzDecode fuzz_decode
