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

CFLAGS="${CFLAGS} -pthread" CXXFLAGS="${CXXFLAGS} -pthread" \
    ./configure --prefix=$(pwd)/build/install-root \
                --build-type=debug \
                --generator=Ninja \
                --enable-fuzzers \
                --disable-python \
                --disable-zeekctl \
                --disable-auxtools \
                --disable-broker-tests \
		--disable-spicy

cd build
ninja install

cp -R ./install-root/share/zeek ${OUT}/oss-fuzz-zeek-scripts

fuzzers=$(find . -name 'zeek-*-fuzzer')
fuzzer_count=1

function copy_lib
    {
    local fuzzer_path=$1
    local lib=$2
    cp $(ldd ${fuzzer_path} | grep "${lib}" | awk '{ print $3 }') ${OUT}/lib
    }

for f in ${fuzzers}; do
    fuzzer_exe=$(basename ${f})
    fuzzer_name=$(echo ${fuzzer_exe} | sed 's/zeek-\(.*\)-fuzzer/\1/g')

    cp ${f} ${OUT}/

    # Set up run-time dependency libraries
    if [[ "${fuzzer_count}" -eq "1" ]]; then
        mkdir -p ${OUT}/lib
        zeek_libs=$(ldd ${f} | grep 'zeek/build' | awk '{ print $1 }' )

        for lib in ${zeek_libs}; do
            copy_lib ${f} ${lib}
        done

        copy_lib ${f} libpcap
        copy_lib ${f} libssl
        copy_lib ${f} libcrypto
        copy_lib ${f} libz
        copy_lib ${f} libmaxminddb
    fi

    patchelf --set-rpath '$ORIGIN/lib' ${OUT}/${fuzzer_exe}

    if [[ -e ../src/fuzzers/${fuzzer_name}.dict ]]; then
        cp ../src/fuzzers/${fuzzer_name}.dict ${OUT}/${fuzzer_exe}.dict
    fi

    if [[ -e ../src/fuzzers/${fuzzer_name}-corpus.zip ]]; then
        cp ../src/fuzzers/${fuzzer_name}-corpus.zip ${OUT}/${fuzzer_exe}_seed_corpus.zip
    fi

    fuzzer_count=$((fuzzer_count + 1))
done

if [ "${SANITIZER}" = "coverage" ]; then
  # Normally, base-builder/compile copies sources for use in coverage reports,
  # but its use of `cp -rL` omits the "zeek -> ." symlink used by #includes,
  # causing the coverage build to fail.
  mkdir -p $OUT/$(basename $SRC)
  cp -r $SRC/zeek $OUT/$(basename $SRC)/zeek
fi
