
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

cd $SRC/kamailio

# export CFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"

mkdir -p build
cd build
cmake -DVERBOSE=ON \
      -DPKG_MALLOC=OFF \
      -DMODULE_GROUP_NAME="" \
      -G "Unix Makefiles" ..
make -j$(nproc) kamailio-oss-fuzz || true  

cd ../

for fuzzer in misc/fuzz/fuzz_*.c; do
    fuzzer_name=$(basename "$fuzzer" .c)
    $CC $CFLAGS -c "$fuzzer" -o "$fuzzer_name.o" \
        -DFAST_LOCK -D__CPU_i386 \
        -I./src/ -I./src/core/parser
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$fuzzer_name.o" -o "$OUT/$fuzzer_name" \
        ./build/src/libkamailio-oss-fuzz.a -ldl -lresolv -lm
done
# decoder corpora and dictionaries (corpus-dict pair)
for d in parse_msg parse_body parse_digest uri pv_parse srjson basex dns_rdata strutils check_boundaries msg_translator; do
  if [ -d misc/fuzz/corpus/fuzz_$d ]; then
    zip -r $OUT/fuzz_${d}_seed_corpus.zip misc/fuzz/corpus/fuzz_$d
  fi
  if [ -f misc/fuzz/fuzz_$d.dict ]; then
    cp -v misc/fuzz/fuzz_$d.dict $OUT/
  fi
done
