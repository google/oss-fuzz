#!/bin/bash -eu
# Copyright 2020 The Monero Project
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

export BOOST_ROOT=/src/monero/boost_1_70_0
export OPENSSL_ROOT_DIR=/src/monero/openssl-1.1.1g

cd monero
sed -i -e 's/include(FindCcache)/# include(FindCcache)/' CMakeLists.txt
git submodule init
git submodule update
mkdir -p build
cd build
export CXXFLAGS="${CXXFLAGS} -fPIC -DBOOST_NO_INCLASS_MEMBER_INITIALIZATION"
cmake -D OSSFUZZ=ON -D STATIC=ON -D BUILD_TESTS=ON -D USE_LTO=OFF -D ARCH="default" ..

TESTS="\
  base58_fuzz_tests \
  block_fuzz_tests \
  transaction_fuzz_tests \
  load-from-binary_fuzz_tests \
  load-from-json_fuzz_tests \
  parse-url_fuzz_tests \
  http-client_fuzz_tests \
  levin_fuzz_tests \
  bulletproof_fuzz_tests \
  tx-extra_fuzz_tests \
  fuzz_rpc \
  fuzz_rpc_full \
  fuzz_rpc_full_no_exceptions \
  fuzz_zmq \
"

# only libfuzzer can run the slow to start ones
if test "x$FUZZING_ENGINE" == 'xlibfuzzer'
then
  TESTS="$TESTS \
    signature_fuzz_tests \
    cold-outputs_fuzz_tests \
    cold-transaction_fuzz_tests \
  "
fi

make -j$(nproc) -C tests/fuzz $TESTS

cd /src/monero/monero/build/tests/fuzz
for fuzzer in *fuzz*
do
  cp "$fuzzer" "$OUT"
  base=$(echo $fuzzer | sed -e s/_fuzz_tests//)
  basedir="/src/monero/monero/tests/data/fuzz/$base"
  if [ -d "$basedir" ]; then
    pushd "/src/monero/monero/tests/data/fuzz/$base"
    rm -f "${OUT}/${fuzzer}_seed_corpus.zip"
    for f in *
    do
      h=$(sha1sum "$f" | awk '{print $1}')
      cp "$f" "$h"
      zip "${OUT}/${fuzzer}_seed_corpus.zip" "$h"
      rm -f "$h"
    done
    popd
  fi
done

cp $SRC/*.options $OUT/
