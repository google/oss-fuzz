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
mkdir -p build/out/${_PROJECT}
cd ${BASE}
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
docker container commit ${_PROJECT}-origin-asan local/ossfuzz/${_PROJECT}-origin-asan
# Run the container with e.g.
# docker run --entrypoint /bin/bash  -it local/ossfuzz/htslib-origin-asan
executables_vanilla="$(find ./build/out/${_PROJECT} -executable -type f | sort)"

# Build with replay enabled, and validate the executables are the same
# in terms of naming.
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

executables_replay="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"

echo "Executables vanilla: "
echo ${executables_vanilla}

echo "------------------------------------------------------"
echo "Executables replay: "
echo ${executables_replay}


if [[ "$executables_replay" == "$executables_vanilla" ]]
then
  echo "Replay worked"
  echo "Vanilla compile time:"
  echo ${B_TIME}
  echo "Replay compile time:"
  echo ${R_TIME}
  exit 0
else
  echo "Replay did not work"
fi

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
  -v=$PWD/build/out/${_PROJECT}/:/out/ \
  us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/${_PROJECT}-ofg-cached-address \
  -c \
  "export PATH=/ccache/bin:\$PATH && rm -rf /out/* && compile"
A_TIME=$(($SECONDS - $A_START))

executables_ccache="$(find ./build/out/${_PROJECT}/ -executable -type f | sort)"

if [[ "$executables_ccache" == "$executables_vanilla" ]]
then
  echo "Replaying failed, but ccache is working."
  echo "No cache: "
  echo ${B_TIME}

  echo "After cache: "
  echo ${A_TIME}

  exit 0
else
  echo "Replay and ccaching did not work."
fi


