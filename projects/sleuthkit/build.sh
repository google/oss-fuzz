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

export CFLAGS="$CFLAGS -Wno-error=non-c-typedef-for-linkage"
export CXXFLAGS="$CXXFLAGS -Wno-error=non-c-typedef-for-linkage"

# Disable error on all warnings
sed -i 's/-Werror//g' ./tsk/util/Makefile.am
sed -i 's/-Werror//g' ./tsk/pool/Makefile.am

# Dont fail if some of the seed downloads fail.
${SRC}/buildcorpus.sh || true

./bootstrap
./configure --enable-static --disable-shared --disable-java --without-afflib --without-libewf --without-libvhdi --without-libvmdk
make -j$(nproc)

declare -A TSK_FS_TYPES=(
  ["ext"]="TSK_FS_TYPE_EXT_DETECT"
  ["fat"]="TSK_FS_TYPE_FAT_DETECT"
  ["hfs"]="TSK_FS_TYPE_HFS"
  ["ntfs"]="TSK_FS_TYPE_NTFS"
  ["iso9660"]="TSK_FS_TYPE_ISO9660"
)

declare -A TSK_VS_TYPES=(
  ["dos"]="TSK_VS_TYPE_DOS"
  ["gpt"]="TSK_VS_TYPE_GPT"
  ["mac"]="TSK_VS_TYPE_MAC"
  ["sun"]="TSK_VS_TYPE_SUN"
)

# The fls APFS fuzz target has a seperate source file since it uses the libtsk
# pool layer.
$CXX $CXXFLAGS -std=c++14 -I.. -I. -Itsk \
    $SRC/sleuthkit_fls_apfs_fuzzer.cc -o $OUT/sleuthkit_fls_apfs_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/sleuthkit/tsk/.libs/libtsk.a -lz

for type in ${!TSK_FS_TYPES[@]}; do
  $CXX $CXXFLAGS -std=c++14 -I.. -I. -Itsk -DFSTYPE=${TSK_FS_TYPES[$type]} \
      $SRC/sleuthkit_fls_fuzzer.cc -o $OUT/sleuthkit_fls_${type}_fuzzer \
      $LIB_FUZZING_ENGINE $SRC/sleuthkit/tsk/.libs/libtsk.a -lz
done

for type in ${!TSK_VS_TYPES[@]}; do
  $CXX $CXXFLAGS -std=c++14 -I.. -I. -Itsk -DVSTYPE=${TSK_VS_TYPES[$type]} \
      $SRC/sleuthkit_mmls_fuzzer.cc -o $OUT/sleuthkit_mmls_${type}_fuzzer \
      $LIB_FUZZING_ENGINE $SRC/sleuthkit/tsk/.libs/libtsk.a -lz
done
