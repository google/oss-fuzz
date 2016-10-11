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
mkdir -p /work/nss
cd /work/nss
hg clone https://hg.mozilla.org/projects/nspr
hg clone https://hg.mozilla.org/projects/nss

cd /work/nss/nss
make BUILD_OPT=1 USE_64=1 NSS_DISABLE_GTESTS=1 CC="$CC $CFLAGS" \
    CXX="$CXX $CXXFLAGS" LD="$CC $CFLAGS" ZDEFS_FLAG= clean nss_build_all
cd ..

# Copy libraries and some objects to /work/nss/lib.
mkdir -p /work/nss/lib
cp dist/Linux*/lib/*.a /work/nss/lib
cp nspr/Linux*/pr/src/misc/prlog2.o /work/nss/lib

# Copy includes to /work/nss/include.
mkdir -p /work/nss/include
cp -rL dist/Linux*/include/* /work/nss/include
cp -rL dist/{public,private}/nss/* /work/nss/include


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
  $CXX $CXXFLAGS -std=c++11 /src/oss-fuzz/nss/fuzzers/$fuzzer.cc \
     -I/work/nss/include \
     /work/libfuzzer/*.o \
     /work/nss/lib/libnss.a /work/nss/lib/libnssutil.a \
     /work/nss/lib/libnspr4.a /work/nss/lib/libplc4.a /work/nss/lib/libplds4.a \
     /work/nss/lib/prlog2.o -o /out/$fuzzer $LDFLAGS
done
