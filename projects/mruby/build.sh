#!/bin/bash -eux
# Copyright 2019 Google Inc.
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

# Instrument mruby
(
cd $SRC/mruby
export LD=$CC
export LDFLAGS="$CFLAGS"
rake all

# Build the test driver. This is allowed to fail; `run_tests.sh` is what gates
# on the test results.
rake test:build || true

# Record how the pristine tree scores, so that run_tests.sh has a reference
# point instead of hard-coded test counts that go stale whenever upstream adds
# or removes tests. Per batch: the number of passing tests, and the number of
# problems (KO + Crash + Warning) that are already present before any patch.
#
# Written only when absent. Chronos evaluates a patch by re-running build.sh
# over the patched tree, and overwriting the baseline there would compare the
# patched tree against itself and detect nothing. The Chronos cached image is
# built from a pristine checkout, so the file it captures is the pristine one.
if [ ! -f $SRC/mruby_test_baseline ]; then
  for batch in lib bin; do
    rake test:run:$batch > /tmp/baseline_${batch}.out 2>&1 || true
    awk -v batch="$batch" '
      /^ *OK: [0-9]+$/      { ok = $NF }
      /^ *KO: [0-9]+$/      { ko = $NF }
      /^ *Crash: [0-9]+$/   { crash = $NF }
      /^ *Warning: [0-9]+$/ { warning = $NF }
      END { if (ok != "") printf "%s %d %d\n", batch, ok, ko + crash + warning }
    ' /tmp/baseline_${batch}.out >> $SRC/mruby_test_baseline
  done
fi

# build fuzzers
FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_fuzzer.c
name=$(basename $FUZZ_TARGET .c)
$CC -c $CFLAGS -Iinclude -Ibuild/host/include \
     ${FUZZ_TARGET} -o $OUT/${name}.o
$CXX $CXXFLAGS $OUT/${name}.o $LIB_FUZZING_ENGINE -lm \
    $SRC/mruby/build/host/lib/libmruby.a -o $OUT/${name}
rm -f $OUT/${name}.o
)

# Construct options files
cat > $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options <<EOF
[libfuzzer]
dict = mruby.dict
only_ascii = 1
EOF
cp $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options $SRC/mruby/oss-fuzz/config/mruby_proto_fuzzer.options

# Build proto fuzzer: ASan and UBSan
if [[ $CFLAGS != *sanitize=memory* ]]; then
    PROTO_FUZZ_TARGET=$SRC/mruby/oss-fuzz/mruby_proto_fuzzer.cpp
    PROTO_CONVERTER=$SRC/mruby/oss-fuzz/proto_to_ruby.cpp
    rm -rf $SRC/mruby/genfiles
    mkdir $SRC/mruby/genfiles
    $SRC/LPM/external.protobuf/bin/protoc --proto_path=$SRC/mruby/oss-fuzz ruby.proto --cpp_out=$SRC/mruby/genfiles
    $CXX -c $CXXFLAGS $SRC/mruby/genfiles/ruby.pb.cc -DNDEBUG -o $SRC/mruby/genfiles/ruby.pb.o -I $SRC/LPM/external.protobuf/include
    $CXX -I $SRC/mruby/include -I $SRC/mruby/build/host/include -I $SRC/LPM/external.protobuf/include $CXXFLAGS $PROTO_FUZZ_TARGET $SRC/mruby/genfiles/ruby.pb.o $PROTO_CONVERTER \
      -I $SRC/mruby/genfiles \
      -I $SRC/libprotobuf-mutator \
      -lz -lm \
      $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
      $SRC/LPM/src/libprotobuf-mutator.a \
      -Wl,--start-group $SRC/LPM/external.protobuf/lib/lib*.a -Wl,--end-group \
      $SRC/mruby/build/host/lib/libmruby.a \
      $LIB_FUZZING_ENGINE \
      -o $OUT/mruby_proto_fuzzer

    # Copy config
    cp $SRC/mruby/oss-fuzz/config/mruby_proto_fuzzer.options $OUT
fi

# dict and config
cp $SRC/mruby/oss-fuzz/config/mruby.dict $OUT
cp $SRC/mruby/oss-fuzz/config/mruby_fuzzer.options $OUT

# seeds
zip -rq $OUT/mruby_fuzzer_seed_corpus $SRC/mruby_seeds
