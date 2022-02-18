#!/bin/bash
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


set -x
set -e

rm -rf out work
mkdir  -vp out work

docker build -t gcr.io/oss-fuzz/credsweeper --file ./Dockerfile .

docker run --rm --privileged -e FUZZING_ENGINE=libfuzzer \
    -e SANITIZER=address -e ARCHITECTURE=x86_64 -e GIT_REPO= -e OSS_FUZZ_CI=1 -e FUZZING_LANGUAGE=python \
    -v "`pwd`/out":"/out" \
    -v "`pwd`/work":"/work" \
    -t gcr.io/oss-fuzz/credsweeper

ls -al out

docker run --rm --privileged -e FUZZING_ENGINE=libfuzzer \
    -e SANITIZER=undefined -e ARCHITECTURE=x86_64 -e FUZZING_LANGUAGE=python -e OSS_FUZZ_CI=1 \
    -v "`pwd`/out":"/out" \
    -t gcr.io/oss-fuzz-base/base-runner \
    test_all.py
