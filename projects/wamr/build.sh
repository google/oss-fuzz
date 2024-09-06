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
echo "    <| ------- |>    "
pwd
echo "    <| ------- |>    "
ls
echo "    <| ------- |>    "
# by default.
#   - MVP
(
  cd tests/fuzz/wasm-mutator-fuzz/

  if [[ "${SANITIZER}" == "address" ]]; then
    cmake -S . -B build -DWAMR_BUILD_SANITIZER=asan\
      && cmake --build build
  elif [[ "${SANITIZER}" == "memory" ]]; then
    echo "will support msan soon"
    exit 0
  elif [[ "${SANITIZER}" == "undefined" ]]; then
    cmake -S . -B build -DWAMR_BUILD_SANITIZER=ubsan\
      && cmake --build build
  elif [[ "${SANITIZER}" == "coverage" ]]; then
    echo "will support code coverage soon"
    exit 0
  else
    cmake -S . -B build\
      && cmake --build build
  fi

  ./smith_wasm.sh 5
  cp ./build/wasm_mutator_fuzz $OUT/
  zip -j $OUT/wasm_mutator_fuzz.zip ./build/CORPUS_DIR/*
)
