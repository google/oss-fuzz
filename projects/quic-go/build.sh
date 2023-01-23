#!/bin/bash
# Copyright 2020 Google Inc.
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

set -ex

(
cd qpack
# Fuzz qpack
compile_go_fuzzer github.com/quic-go/qpack/fuzzing Fuzz qpack_fuzzer
)

(
cd quic-go
# Fuzz quic-go
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/frames Fuzz frame_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/header Fuzz header_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/transportparameters Fuzz transportparameter_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/tokens Fuzz token_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/handshake Fuzz handshake_fuzzer

if [ $SANITIZER == "coverage" ]; then
    # no need for corpuses if coverage
    exit 0
fi
# generate seed corpora
go generate ./fuzzing/...

zip --quiet -r $OUT/header_fuzzer_seed_corpus.zip fuzzing/header/corpus
zip --quiet -r $OUT/frame_fuzzer_seed_corpus.zip fuzzing/frames/corpus
zip --quiet -r $OUT/transportparameter_fuzzer_seed_corpus.zip fuzzing/transportparameters/corpus
zip --quiet -r $OUT/handshake_fuzzer_seed_corpus.zip fuzzing/handshake/corpus
)

# for debugging
ls -al $OUT
