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

# Step 1: build the base image
cd projects/${_PROJECT}
docker build -t gcr.io/oss-fuzz/${_PROJECT} .


# Step 2: create a container where `compile` has run which enables ccaching
#         and also generates a replay build script.
cd ${BASE}
mkdir -p ccaches/${_PROJECT}
mkdir -p build/out/${_PROJECT}
B_START=$SECONDS
docker run \
  --entrypoint=/bin/bash \
  --env=SANITIZER=address \
  --env=CCACHE_DIR=/workspace/ccache \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --env=CAPTURE_REPLAY_SCRIPT=1 \
  --name=${_PROJECT}-origin-asan \
  -v=$PWD/ccaches/${_PROJECT}/ccache:/workspace/ccache \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  gcr.io/oss-fuzz/${_PROJECT} \
  -c \
  "export PATH=/ccache/bin:\$PATH && compile"
B_TIME=$(($SECONDS - $B_START))

# Step 3: save (commit, locally) the cached container as an image
docker container commit ${_PROJECT}-origin-asan local/ossfuzz/${_PROJECT}-origin-asan


# Step 4: save the list of executables created from a vanilla build. This is
#         needed for validating if replay and ccaching works.
# notes: run a shell the container with e.g.
# `docker run --entrypoint /bin/bash  -it local/ossfuzz/htslib-origin-asan`
executables_vanilla="$(find ./build/out/${_PROJECT} -executable -type f | sort)"


# Step 5: Build with replay enabled, and validate the executables are the same
# in terms of naming.
# Note that an important step is removing everything in $OUT/ which is done
# in the docker command.
R_START=$SECONDS
docker run \
  --entrypoint=/bin/bash \
  --env=SANITIZER=address \
  --env=REPLAY_ENABLED=1 \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  --name=${_PROJECT}-origin-asan-replay-recached \
  local/ossfuzz/${_PROJECT}-origin-asan \
  -c \
  "export PATH=/ccache/bin:\$PATH && rm -rf /out/* && compile"
R_TIME=$(($SECONDS - $R_START))

# Step 6: Extract the newly build executables
executables_replay="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"

echo "Executables vanilla: "
echo ${executables_vanilla}

echo "------------------------------------------------------"
echo "Executables replay: "
echo ${executables_replay}

# Step 7: match executables from vanilla builds and replay builds.
#         If this step is successful, then the process can exit as it's ready.
if [[ "$executables_replay" == "$executables_vanilla" ]]
then
  echo "Replay worked"
  echo "Vanilla compile time:"
  echo ${B_TIME}
  echo "Replay compile time:"
  echo ${R_TIME}

  if [ -n "${RUN_ALL+1}" ]; then
    exit 0
  fi
else
  echo "Replay did not work"
fi

# Step 8: prepare Dockerfile for ccache
cp -rf ccaches/${_PROJECT}/ccache ./projects/${_PROJECT}/ccache-cache

infra/experimental/chronos/prepare-ccache ${_PROJECT}

cd projects/${_PROJECT}

# Step 9: Build an image with CCache's new items (modifications are done on the
#         dockerfile)
docker build -t us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address .      

cd ${BASE}

# Step 10: Run a `compile` with ccache's image.
# Run the ccache build
A_START=$SECONDS
docker run \
  --entrypoint=/bin/bash \
  --env=SANITIZER=address \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --name=${_PROJECT}-origin-asan-recached \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address \
  -c \
  "export PATH=/ccache/bin:\$PATH && rm -rf /out/* && compile"
A_TIME=$(($SECONDS - $A_START))

# Step 11: extract the executables from the ccache build
executables_ccache="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"


# Step 12: validate the ccache builds are successful
if [[ "$executables_ccache" == "$executables_vanilla" ]]
then
  echo "Vanilla compile time:"
  echo ${B_TIME}
  if [[ "$executables_replay" == "$executables_vanilla" ]]
  then
    echo "Replay worked"
    echo "Replay compile time:"
    echo ${R_TIME}
  fi

  echo "Ccache compile time: "
  echo ${A_TIME}

  exit 0
else
  echo "Replay and ccaching did not work."
fi


