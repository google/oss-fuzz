#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

CONFIGURE_FLAGS="--debug enable-fuzz-libfuzzer -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers --with-fuzzer-lib=/usr/lib/libFuzzingEngine $CFLAGS -fno-sanitize=alignment"
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CONFIGURE_FLAGS="$CONFIGURE_FLAGS no-asm"
fi
if [[ $CFLAGS != *-m32* ]]
then
  CONFIGURE_FLAGS="$CONFIGURE_FLAGS enable-ec_nistp_64_gcc_128"
fi
if [[ $CFLAGS = *-m32* ]]
then
  # Prevent error:
  #
  # error while loading shared libraries:
  # libatomic.so.1: cannot open shared object file:
  # No such file or directory
  CONFIGURE_FLAGS="$CONFIGURE_FLAGS no-threads"
fi

function build_fuzzers() {
    SUFFIX=$1
    if [[ $CFLAGS = *-m32* ]]
    then
        setarch i386 ./config $CONFIGURE_FLAGS
    else
        ./config $CONFIGURE_FLAGS
    fi

    make -j$(nproc) LDCMD="$CXX $CXXFLAGS"

    fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test '!' -name \*.pl '!' -name \*.sh)
    for f in $fuzzers; do
        fuzzer=$(basename $f)
        cp $f $OUT/${fuzzer}${SUFFIX}
        zip -j $OUT/${fuzzer}${SUFFIX}_seed_corpus.zip fuzz/corpora/${fuzzer}/*
    done

    options=$(find $SRC/ -maxdepth 1 -name '*.options')
    for o in $options; do
        o_base=$(basename $o)
        fuzzer=${o_base%".options"}
        cp $o $OUT/${fuzzer}${SUFFIX}.options
    done
    cp fuzz/oids.txt $OUT/asn1${SUFFIX}.dict
    cp fuzz/oids.txt $OUT/x509${SUFFIX}.dict
}

cd $SRC/openssl/
build_fuzzers ""
cd $SRC/openssl111/
build_fuzzers "_111"
cd $SRC/openssl30/
build_fuzzers "_30"
