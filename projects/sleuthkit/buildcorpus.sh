#!/bin/bash -eu
#
# Script to downloads test data and build the corpus
#
# Copyright 2021 Google Inc.
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

# Test data provided by:
#
# The Fuzzing Project: https://fuzzing-project.org/resources.html
#   As CC0 1.0 Universal (CC0 1.0) Public Domain Dedication
#   https://creativecommons.org/publicdomain/zero/1.0/
#
# The dfVFS project: https://github.com/log2timeline/dfvfs
#   As Apache 2 https://github.com/log2timeline/dfvfs/blob/main/LICENSE

# Files to use for fls fuzz targets
declare -A FLS_TEST_FILES=(
  ["apfs"]="https://github.com/log2timeline/dfvfs/blob/main/test_data/apfs.raw?raw=true"
  ["ext"]="https://files.fuzzing-project.org/filesystems/ext2.img"
  ["fat"]="https://files.fuzzing-project.org/filesystems/exfat.img https://files.fuzzing-project.org/filesystems/fat12.img https://files.fuzzing-project.org/filesystems/fat16.img https://files.fuzzing-project.org/filesystems/fat32.img"
  ["hfs"]="https://files.fuzzing-project.org/filesystems/hfsplus.img"
  ["iso9660"]="https://files.fuzzing-project.org/discimages/iso9660.iso"
  ["ntfs"]="https://files.fuzzing-project.org/filesystems/ntfs.img"
)

# Files to use for mmls fuzz targets
declare -A MMLS_TEST_FILES=(
  ["dos"]="https://files.fuzzing-project.org/discimages/partition-dos"
  ["gpt"]="https://files.fuzzing-project.org/discimages/partition-gpt"
  ["mac"]="https://files.fuzzing-project.org/discimages/partition-mac"
)


for type in ${!FLS_TEST_FILES[@]}; do
  fuzz_target="sleuthkit_fls_${type}_fuzzer"

  mkdir -p "test_data/${fuzz_target}"

  IFS=" "; for url in ${FLS_TEST_FILES[$type]}; do
    filename=$( echo ${url} | sed 's/?[^?]*$//' )
    filename=$( basename ${filename} )

    curl -L -o "test_data/${fuzz_target}/${filename}" "${url}"
  done

  (cd "test_data/${fuzz_target}" && zip ${OUT}/${fuzz_target}_seed_corpus.zip *)
done


for type in ${!MMLS_TEST_FILES[@]}; do
  fuzz_target="sleuthkit_mmls_${type}_fuzzer"

  mkdir -p "test_data/${fuzz_target}"

  IFS=" "; for url in ${MMLS_TEST_FILES[$type]}; do
    filename=$( echo ${url} | sed 's/?[^?]*$//' )
    filename=$( basename ${filename} )

    curl -L -o "test_data/${fuzz_target}/${filename}" "${url}"
  done

  (cd "test_data/${fuzz_target}" && zip ${OUT}/${fuzz_target}_seed_corpus.zip *)
done
