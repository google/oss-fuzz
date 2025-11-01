#!/bin/bash -eu
# Copyright 2021 Google LLC
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


# ---- Build fuzz corpuses ---- #
function zip_files() {
   # Get the arguments
   directory=$1
   extension=$2
   zipfile=$3

   # Find all files with the given extension in the given directory and its subdirectories
   # and add them to the zip file
   find "$directory" -type f -name "*.$extension" -exec zip -r -j "$zipfile" {} +
}

FORMATS=("bmp" "exr" "gif" "hdr" "ico" "jpeg" "png" "pnm" "tga" "tiff" "webp")

for FORMAT in "${FORMATS[@]}"
do
     zip_files . $FORMAT "$OUT/fuzzer_script_${FORMAT}_seed_corpus.zip"
done

# ---- Build fuzz harnesses ----

cargo fuzz build -O
cargo fuzz list | while read i; do
    cp fuzz/target/x86_64-unknown-linux-gnu/release/$i $OUT/
done
