#!/bin/bash -eux
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Builds fuzzers from within a container into /out/ directory.
# Expects /src/cras to contain a cras checkout.

cd ${SRC}/adhd/cras
./git_prepare.sh
./configure
make -j$(nproc)
cp ${SRC}/adhd/cras/src/server/rust/target/release/libcras_rust.a /usr/local/lib

CRAS_FUZZERS="rclient_message cras_hfp_slc"

for fuzzer in ${CRAS_FUZZERS};
do
$CXX $CXXFLAGS $FUZZER_LDFLAGS \
  ${SRC}/adhd/cras/src/fuzz/${fuzzer}.cc -o ${OUT}/${fuzzer} \
  -I ${SRC}/adhd/cras/src/server \
  -I ${SRC}/adhd/cras/src/common \
  $(pkg-config --cflags dbus-1) \
  ${SRC}/adhd/cras/src/.libs/libcrasserver.a \
  -lcras_rust -lpthread -lrt -ludev -ldl -lm -lsystemd \
  $LIB_FUZZING_ENGINE \
  -Wl,-Bstatic -liniparser -lasound -lspeexdsp -ldbus-1 -lsbc -Wl,-Bdynamic
done

zip -j ${OUT}/rclient_message_corpus.zip ${SRC}/adhd/cras/src/fuzz/corpus/*
cp "${SRC}/adhd/cras/src/fuzz/cras_hfp_slc.dict" "${OUT}/cras_hfp_slc.dict"
