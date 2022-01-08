#! /bin/bash -eux
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

# Script for building the docker images for cifuzz.

CIFUZZ_DIR=$(dirname "$0")
CIFUZZ_DIR=$(realpath $CIFUZZ_DIR)
INFRA_DIR=$(realpath $CIFUZZ_DIR/..)
OSS_FUZZ_ROOT=$(realpath $INFRA_DIR/..)

# Build cifuzz-base.
docker build --tag gcr.io/oss-fuzz-base/cifuzz-base --file $CIFUZZ_DIR/cifuzz-base/Dockerfile $OSS_FUZZ_ROOT

# Build run-fuzzers and build-fuzzers images.
docker build \
  --tag gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers-test:v1 \
  --tag gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1 \
  --file $INFRA_DIR/build_fuzzers.Dockerfile $INFRA_DIR
docker build \
  --tag gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1 \
  --tag gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers-test:v1 \
  --file $INFRA_DIR/run_fuzzers.Dockerfile $INFRA_DIR
