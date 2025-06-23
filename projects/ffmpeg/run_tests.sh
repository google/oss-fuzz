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

# Usage: bash run_test.sh 
# Runs all tests (same as 'make fate') and compiles if not compiled.

set -e # Exit immediately if any command fails

FFMPEG_SRC_DIR="/src/ffmpeg"
OUT_DIR="${OUT:-/out}"

# Executable fuzzer implies built.
if [ ! -d "$OUT_DIR" ]; then
  # Output directory does not exist.
  # This implies no build has occurred or populated this directory.
  IS_LIKELY_BUILT=0
else
  if [ -z "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then
    # Output directory exists but is empty.
    # This implies no build has populated this directory yet.
    IS_LIKELY_BUILT=0
  else
    # Check specifically for executable files within OUT_DIR or its immediate subdirectories.
    first_executable=$(find "$OUT_DIR" -maxdepth 2 -type f -executable -print -quit 2>/dev/null)

    if [ -n "$first_executable" ]; then
      # Found executable file(s) in the output directory.
      # This suggests a build has already occurred.
      IS_LIKELY_BUILT=1

    else
      # $OUT is not empty, but no executables found. Could be intermediate files, logs, corpus, etc.
      IS_LIKELY_BUILT=0
    fi
  fi
fi


if [ "$IS_LIKELY_BUILT" -eq 0 ]; then
    echo "==> Project is not likely built. Building..."
    bash build.sh # TODO(carlolemos): Check if we get to the same state of
    # us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/ffmpeg-ofg-cached-address
    make -j$(nproc)

    echo "==> Build finished."
fi

echo "==> Changing to FFmpeg source directory: $FFMPEG_SRC_DIR"
cd "$FFMPEG_SRC_DIR"

echo "==> Running all FATE tests..."
make fate

echo "==> Test run finished successfully."
