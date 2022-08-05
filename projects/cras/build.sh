#!/bin/bash -eux
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
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
# Builds fuzzers from within a container into /out/ directory.
# Expects /src/cras to contain a cras checkout.

cd ${SRC}/adhd/cras
./git_prepare.sh
mkdir -p ${WORK}/build && cd ${WORK}/build
export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
CFLAGS="${CFLAGS} -DHAVE_FUZZER" ${SRC}/adhd/cras/configure --disable-featured
make -j$(nproc)
cp ${WORK}/build/src/server/rust/target/${CARGO_BUILD_TARGET}/release/libcras_rust.a /usr/local/lib

CRAS_FUZZERS="rclient_message cras_hfp_slc cras_fl_media_fuzzer"

for fuzzer in ${CRAS_FUZZERS};
do
$CXX $CXXFLAGS $FUZZER_LDFLAGS \
  ${SRC}/adhd/cras/src/fuzz/${fuzzer}.cc -o ${OUT}/${fuzzer} \
  -I ${SRC}/adhd/cras/src/server \
  -I ${SRC}/adhd/cras/src/common \
  $(pkg-config --cflags dbus-1) \
  ${WORK}/build/src/.libs/libcrasserver.a \
  -lcras_rust -lpthread -lrt -ludev -ldl -lm -lsystemd \
  $LIB_FUZZING_ENGINE \
  -Wl,-Bstatic -liniparser -lasound -lspeexdsp -ldbus-1 -lsbc -Wl,-Bdynamic
done

zip -j ${OUT}/rclient_message_corpus.zip ${SRC}/adhd/cras/src/fuzz/corpus/*
cp "${SRC}/adhd/cras/src/fuzz/cras_hfp_slc.dict" "${OUT}/cras_hfp_slc.dict"
# Add *.rs soft link for coverage build
ln -s ${SRC}/adhd/cras/src/server/rust/src/* ${SRC}
