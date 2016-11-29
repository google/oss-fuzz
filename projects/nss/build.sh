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

# Build the library.
make CCC="$CXX" XCFLAGS="$CXXFLAGS" SANITIZER_CFLAGS="$CXXFLAGS" \
    BUILD_OPT=1 USE_64=1 NSS_DISABLE_GTESTS=1 ZDEFS_FLAG= \
    nss_clean_all nss_build_all
cd ..

# Copy libraries and some objects to $WORK/nss/lib.
mkdir -p $WORK/nss/lib
cp dist/Linux*/lib/*.a $WORK/nss/lib
cp nspr/Linux*/pr/src/misc/prlog2.o $WORK/nss/lib

# Copy includes to $WORK/nss/include.
mkdir -p $WORK/nss/include
cp -rL dist/Linux*/include/* $WORK/nss/include
cp -rL dist/{public,private}/nss/* $WORK/nss/include


# Build the fuzzers.
FUZZERS="asn1_algorithmid_fuzzer \
  asn1_any_fuzzer \
  asn1_bitstring_fuzzer \
  asn1_bmpstring_fuzzer \
  asn1_boolean_fuzzer \
  asn1_generalizedtime_fuzzer \
  asn1_ia5string_fuzzer \
  asn1_integer_fuzzer \
  asn1_null_fuzzer \
  asn1_objectid_fuzzer \
  asn1_octetstring_fuzzer \
  asn1_utctime_fuzzer \
  asn1_utf8string_fuzzer"

# The following fuzzers are currently disabled due to linking issues:
#  cert_certificate_fuzzer, seckey_privatekeyinfo_fuzzer


for fuzzer in $FUZZERS; do
  $CXX $CXXFLAGS -std=c++11 $SRC/$fuzzer.cc \
     -I$WORK/nss/include \
     -lfuzzer \
     $WORK/nss/lib/libnss.a $WORK/nss/lib/libnssutil.a \
     $WORK/nss/lib/libnspr4.a $WORK/nss/lib/libplc4.a $WORK/nss/lib/libplds4.a \
     $WORK/nss/lib/prlog2.o -o $OUT/$fuzzer
done

# Archive and copy to $OUT seed corpus if the build succeeded.
zip $WORK/nss/all_nss_seed_corpus.zip $SRC/nss-corpus/*/*

for fuzzer in $FUZZERS; do
  cp $WORK/nss/all_nss_seed_corpus.zip $OUT/${fuzzer}_seed_corpus.zip
done
