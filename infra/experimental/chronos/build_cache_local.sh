#!/bin/bash -eux
# Copyright 2024 Google LLC
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

_PROJECT=$1
_FUZZING_LANGUAGE=$2

BASE=$PWD

cd projects/${_PROJECT}
docker build -t gcr.io/oss-fuzz/${_PROJECT} .

mkdir -p ccaches/${_PROJECT}
cd ${BASE}
B_START=$SECONDS
docker run \
  --entrypoint=/bin/bash \
  --env=SANITIZER=address \
  --env=CCACHE_DIR=/workspace/ccache \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --name=${_PROJECT}-origin-asan \
  -v=$PWD/ccaches/${_PROJECT}/ccache:/workspace/ccache \
  gcr.io/oss-fuzz/${_PROJECT} \
  -c \
  "export PATH=/ccache/bin:\$PATH && compile"
B_TIME=$(($SECONDS - $B_START))

# Prepare Dockerfile for ccache
cp -rf ccaches/${_PROJECT}/ccache ./projects/${_PROJECT}/ccache-cache

infra/experimental/chronos/prepare-ccache ${_PROJECT}

cd projects/${_PROJECT}
docker build -t us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address .      

# Run the ccache build
A_START=$SECONDS
docker run \
  --entrypoint=/bin/bash \
  --env=SANITIZER=address \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --name=${_PROJECT}-origin-asan-recached \
  us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address \
  -c \
  "export PATH=/ccache/bin:\$PATH && compile"
A_TIME=$(($SECONDS - $A_START))

echo "No cache: "
echo ${B_TIME}

echo "After cache: "
echo ${A_TIME}
