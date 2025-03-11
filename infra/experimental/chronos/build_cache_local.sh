#!/bin/bash -eu
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
_SANITIZER=${3:-address}

BASE=$PWD

# Final image is either ccache or replay script, depending on which worked.
FINAL_IMAGE_NAME=us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-${_SANITIZER}

# Always build an image with ccache.
CCACHE_IMAGE_NAME=us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-ccache-${_SANITIZER}

# Step 1: build the base image
cd projects/${_PROJECT}
docker build -t gcr.io/oss-fuzz/${_PROJECT} .


# Step 2: create a container where `compile` has run which enables ccaching
#         and also generates a replay build script.
cd ${BASE}
mkdir -p ccaches/${_PROJECT}
mkdir -p build/out/${_PROJECT}
B_START=$SECONDS

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
  "export PATH=/ccache/bin:\$PATH && compile"
B_TIME=$(($SECONDS - $B_START))

# Step 3: save (commit, locally) the cached container as an image
docker container commit -c "ENV REPLAY_ENABLED=1" -c "ENV CAPTURE_REPLAY_SCRIPT=" ${_PROJECT}-origin-${_SANITIZER} $FINAL_IMAGE_NAME

# Step 4: save the list of executables created from a vanilla build. This is
#         needed for validating if replay and ccaching works.
# notes: run a shell the container with e.g.
# `docker run --entrypoint /bin/bash  -it local/ossfuzz/htslib-origin-address`
executables_vanilla="$(find ./build/out/${_PROJECT} -executable -type f | sort)"


# Step 5: Build with replay enabled, and validate the executables are the same
# in terms of naming.
# Note that an important step is removing everything in $OUT/ which is done
# in the docker command.
R_START=$SECONDS
docker run \
  --rm \
  --env=SANITIZER=${_SANITIZER} \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  --name=${_PROJECT}-origin-${_SANITIZER}-replay-recached \
  $FINAL_IMAGE_NAME \
  /bin/bash -c \
  "export PATH=/ccache/bin:\$PATH && rm -rf /out/* && compile"
R_TIME=$(($SECONDS - $R_START))

# Step 6: Extract the newly build executables
executables_replay="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"

echo "Executables vanilla: "
echo ${executables_vanilla}

echo "------------------------------------------------------"
echo "Executables replay: "
echo ${executables_replay}

REPLAY_WORKED=

# Step 7: match executables from vanilla builds and replay builds.
#         If this step is successful, then the process can exit as it's ready.
if [[ "$executables_replay" == "$executables_vanilla" ]]
then
  REPLAY_WORKED=1

  if [ -z "${RUN_ALL+1}" ]; then
    echo "${_PROJECT}: Replay worked."
    echo "${_PROJECT}: Compile times: Vanilla=${B_TIME}; Replay=${R_TIME};"
    exit 0
  fi
else
  echo "${_PROJECT}: Replay did not work"
  R_TIME="N/A"
fi

# Step 8: prepare Dockerfile for ccache
cp -rf ccaches/${_PROJECT}/ccache ./projects/${_PROJECT}/ccache-cache

infra/experimental/chronos/prepare-ccache ${_PROJECT}

cd projects/${_PROJECT}

# Step 9: Build an image with CCache's new items (modifications are done on the
#         dockerfile)
docker build -t $CCACHE_IMAGE_NAME .

cd ${BASE}

# Step 10: Run a `compile` with ccache's image.
# Run the ccache build
A_START=$SECONDS
docker run \
  --rm \
  --env=SANITIZER=${_SANITIZER} \
  --env=FUZZING_LANGUAGE=${_FUZZING_LANGUAGE} \
  --name=${_PROJECT}-origin-${_SANITIZER}-recached \
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  $CCACHE_IMAGE_NAME \
  /bin/bash -c \
  "export PATH=/ccache/bin:\$PATH && rm -rf /out/* && compile"
A_TIME=$(($SECONDS - $A_START))

# Step 11: extract the executables from the ccache build
executables_ccache="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"


# Step 12: validate the ccache builds are successful
if [[ "$executables_ccache" == "$executables_vanilla" ]]
then
  echo "${_PROJECT}: Compile times: Vanilla=${B_TIME}; Replay=${R_TIME}; CCache=${A_TIME};"

  if [[ -z "${REPLAY_WORKED}" || ${R_TIME} -gt ${A_TIME} ]]; then
    if [ ${R_TIME} -gt ${A_TIME} ]; then
      echo "Replay was slower than ccache."
    fi

    # Replay didn't work or was slower, so make the default "cached" image use the ccache one.
    docker image tag \
      $CCACHE_IMAGE_NAME \
      $FINAL_IMAGE_NAME
  fi

  exit 0
else
  echo "${_PROJECT}: Replay and ccaching did not work."
  exit 1
fi

