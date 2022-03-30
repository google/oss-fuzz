#!/bin/bash -eu
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
# Ensure libqb can be found by pkgconfig
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig/

autoreconf -fi

libqb=`find /usr/lib64/ -name libqb.a -print -quit`
protobuf=`find /usr/lib/ -name libprotobuf.a -print -quit`

qb_LIBS="${libqb}" \
  protobuf_LIBS="-pthread ${protobuf} -pthread -lpthread" \
  ./configure --with-bundled-catch --with-bundled-pegtl \
  --with-crypto-library=gcrypt --disable-shared

fuzzers="$( cd src/Tests/Fuzzers && find -name 'fuzzer-*.cpp' |
           sed 's/^\.\/\(fuzzer-.*\)\.cpp$/\1/g' )"

make -j`nproc` src/build-config.h libusbguard.la
make -j`nproc` -C src/Tests/Fuzzers ${fuzzers}

cd src/Tests/Fuzzers
mv ${fuzzers} "$OUT"

################################################################################
# Create seed corpora.
################################################################################

# General case:
cd "$SRC/usbguard/src/Tests/Fuzzers"
# fuzzer-usb-descriptor seed corpus.
for fuzzer_name in ${fuzzers}; do
  corpus_dir="${fuzzer_name}_corpus"
  if [[ ! -d "$corpus_dir" ]] ; then
    continue
  fi
  zip_name="$OUT/${fuzzer_name}_seed_corpus.zip"
  rm -f "${zip_name}"
  zip -r "${zip_name}" "${corpus_dir}"
done

# Specific cases:
cd "$WORK"
# fuzzer-rules seed corpus.
fuzzer_name=fuzzer-rules
corpus_dir="${fuzzer_name}_corpus"
zip_name="$OUT/${fuzzer_name}_seed_corpus.zip"
if [[ ! -d "$SRC/usbguard/src/Tests/Fuzzers/$corpus_dir" ]] ; then
  rm -f "${zip_name}"
  rm -rf "${corpus_dir}"
  mkdir -p "${corpus_dir}"
  pushd "${corpus_dir}"
  i=1000000
  while read -r line; do
    echo "${line}" > "$((i++))"
  done < <( cat $SRC/usbguard/src/Tests/Rules/test-rules.good \
            $SRC/usbguard/src/Tests/Rules/test-rules.bad )
  popd
  zip -r "${zip_name}" "${corpus_dir}"
fi

# fuzzer-usb-descriptor seed corpus.
fuzzer_name=fuzzer-usb-descriptor
corpus_dir="${fuzzer_name}_corpus"
zip_name="$OUT/${fuzzer_name}_seed_corpus.zip"
if [[ ! -d "$SRC/usbguard/src/Tests/Fuzzers/$corpus_dir" ]] ; then
  rm -rf "${corpus_dir}"
  rm -f "${zip_name}"
  cp -R "$SRC/usbguard/src/Tests/USB/data" "${corpus_dir}"
  zip -r "${zip_name}" "${corpus_dir}"
fi
