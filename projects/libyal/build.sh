#!/bin/bash -eu
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

for PROJECT in ${SRC}/*;
do
  PROJECT=$(basename ${PROJECT})

  # A libyal project should have an ossfuzz directory and a synclibs.sh script.
  if ! test -d ${SRC}/${PROJECT}/ossfuzz || ! test -x ${SRC}/${PROJECT}/synclibs.sh;
  then
    continue
  fi
  cd ${SRC}/${PROJECT}

  # Prepare the project source for build.
  ./synclibs.sh
  ./autogen.sh
  ./configure --enable-shared=no

  # Build the project and fuzzer binaries.
  make -j$(nproc) LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE}

  # Download the test data if supported.
  if test -x ./synctestdata.sh;
  then
    ./synctestdata.sh
  fi

  # Copy the fuzzer binaries and test data to the output directory.
  for FUZZ_TARGET in $(cd ossfuzz && find . -executable -type f);
  do
    FUZZ_TARGET=$(basename ${FUZZ_TARGET})

    # Prefix the fuzzer binaries with the project name.
    cp ossfuzz/${FUZZ_TARGET} ${OUT}/${PROJECT}_${FUZZ_TARGET}

    # Download the test data if supported.
    if test -d tests/input/public;
    then
      (cd tests/input/public && zip ${OUT}/${PROJECT}_${FUZZ_TARGET}_seed_corpus.zip *)
    else
      (cd tests/data && zip ${OUT}/${PROJECT}_${FUZZ_TARGET}_seed_corpus.zip ${FUZZ_TARGET/_fuzzer/}.*)
    fi
  done
done
