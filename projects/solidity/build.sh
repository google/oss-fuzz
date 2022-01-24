#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

#!/usr/bin/env bash
set -ex

ROOTDIR="${SRC}/solidity"
BUILDDIR="${ROOTDIR}/build"
mkdir -p "${BUILDDIR}"

generate_protobuf_bindings()
{
  cd "${ROOTDIR}"/test/tools/ossfuzz
  # Generate protobuf C++ bindings
  for protoName in yul abiV2 sol;
  do
    protoc "${protoName}"Proto.proto --cpp_out .
  done
}

build_fuzzers()
{
  cd "${BUILDDIR}"
  CXXFLAGS="${CXXFLAGS} -I/usr/local/include/c++/v1"
  cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ossfuzz.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        "${ROOTDIR}"
  make ossfuzz ossfuzz_proto ossfuzz_abiv2 -j $(nproc)
}

copy_fuzzers_and_config()
{
  cp "${BUILDDIR}"/test/tools/ossfuzz/*_ossfuzz "${OUT}"
  cp "${ROOTDIR}"/test/tools/ossfuzz/config/*.options "${OUT}"
  cp "${ROOTDIR}"/test/tools/ossfuzz/config/*.dict "${OUT}"
}

update_corpus()
{
  rm -f "${OUT}"/*.zip
  cd "${SRC}"/solidity-fuzzing-corpus
  git pull origin master
  for dir in "${SRC}"/solidity-fuzzing-corpus/*;
  do
    name=$(basename $dir)
    zip -rq "${OUT}"/$name $dir
  done
}

generate_protobuf_bindings
build_fuzzers
copy_fuzzers_and_config
update_corpus
