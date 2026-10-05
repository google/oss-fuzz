#!/bin/bash -eu
#
# Copyright 2026 Google LLC
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

# Loop through directories
for PROJECT in ${SRC}/*
do
  PROJECT=$(basename ${PROJECT})

  # Skip libufzzer directory or directories that does not have unit testing
  if ! test -d ${SRC}/${PROJECT}/tests || [[ "$PROJECT" == "libfuzzer" ]]
  then
    continue
  fi

  # Run unit testing of that project
  # Exit immediately with error code if failed
  make check -C ${SRC}/${PROJECT} -j$(nproc) || exit $?
done
