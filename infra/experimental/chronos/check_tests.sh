#!/bin/bash
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

# Module for validating "run_tests.sh" of a given project. Before the run_tests.sh
# script is run, a cached container image is first built. We assume here that the
# replay is working for the target project.
# (TODO): make sure this works for both replay_build.sh and ccached rebuilds.
#         currently the focus is on replay_build.sh.
_PROJECT=$1
_FUZZING_LANGUAGE=$2
_SANITIZER=${3:-address}

BASE=$PWD

# Final image is either ccache or replay script, depending on which worked.
FINAL_IMAGE_NAME=us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-${_SANITIZER}

# Step 1: build the base image
cd projects/${_PROJECT}
docker build -t gcr.io/oss-fuzz/${_PROJECT} .

# Step 2: create a container where `compile` has run which enables ccaching
#         and also generates a replay build script.
cd ${BASE}
mkdir -p ccaches/${_PROJECT}
mkdir -p build/out/${_PROJECT}

# Clean up existing images.
docker container rm -f ${_PROJECT}-origin-${_SANITIZER}

docker run \
  --env=SANITIZER=${_SANITIZER} \
  --env=CCACHE_DIR=/workspace/ccache \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --env=CAPTURE_REPLAY_SCRIPT=1 \
  --name=${_PROJECT}-origin-${_SANITIZER} \
  -v=$PWD/ccaches/${_PROJECT}/ccache:/workspace/ccache \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  gcr.io/oss-fuzz/${_PROJECT} \
  /bin/bash -c \
  "export PATH=/ccache/bin:\$PATH && compile && cp -n /usr/local/bin/replay_build.sh \$SRC/"


# Step 3: save (commit, locally) the cached container as an image
docker container commit -c "ENV REPLAY_ENABLED=1" -c "ENV CAPTURE_REPLAY_SCRIPT=" ${_PROJECT}-origin-${_SANITIZER} $FINAL_IMAGE_NAME

T_START=$SECONDS
# Step 4: run the actual run_tests.sh script in the container.
docker run \
  --rm \
  --network none \
  -ti \
  us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address /bin/bash -c 'chmod +x /src/run_tests.sh && /src/run_tests.sh'
T_END=$SECONDS

T_TOTAL_TIME=$(($T_END - $T_START))
echo "--------------------------------------------------------"
echo "Total time taken to replay tests: $T_TOTAL_TIME"
