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

cd /src/nss

# Check out the code using mercurial.
rm -rf nspr
rm -rf nss
hg clone https://hg.mozilla.org/projects/nspr
hg clone https://hg.mozilla.org/projects/nss

# Build the library.
mkdir -p /work/nss
cp -u -r /src/nss/* /work/nss/
cd /work/nss/nss
make BUILD_OPT=1 USE_64=1 NSS_DISABLE_GTESTS=1 CC="$CC $CFLAGS" \
  CXX="$CXX $CXXFLAGS" LD="$CC $CFLAGS" ZDEFS_FLAG= clean nss_build_all install


# Copy libraries to /usr/lib.
cd ../dist
cp Linux*/lib/*.so /usr/lib
cp Linux*/lib/{*.chk,libcrmf.a} /usr/lib

# Copy libraries to /out since fuzzers don't work without them.
cp Linux*/lib/*.so /out
cp Linux*/lib/*.a /out

# Copy includes to /work/nss/include.
mkdir -p /work/nss/include
cp -rL Linux*/include/* /work/nss/include
cp -rL {public,private}/nss/* /work/nss/include
cd ..

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
  asn1_utf8string_fuzzer \
  cert_certificate_fuzzer \
  seckey_privatekeyinfo_fuzzer"


# Instead of:
#     -lnss3 -lnssutil3 -lnspr4 -lplc4 -lplds4 \
# I tried to use /out/*.a
# log: https://gist.github.com/Dor1s/d9873b241480ccbb530d2ee2af8d7072
#
# and another version with exact names:
#      /out/libnss.a /out/libnssutil.a /out/libnspr4.a /out/libplc4.a /out/libplds4.a
# log: https://gist.github.com/Dor1s/fdd88b7092a85bcdd1a03bcd2382fe6b

for fuzzer in $FUZZERS; do
  $CXX $CXXFLAGS -std=c++11 /src/oss-fuzz/nss/fuzzers/$fuzzer.cc \
     -I/work/nss/include \
     /work/libfuzzer/*.o \
     /out/libnss.a /out/libnssutil.a /out/libnspr4.a /out/libplc4.a /out/libplds4.a \
     -o /out/$fuzzer
done

# To avoid "unbound variable" error.
#if [[ ! -v LD_LIBRARY_PATH ]]; then
#  export LD_LIBRARY_PATH=/work/nss/lib
#else
#  export LD_LIBRARY_PATH=/work/nss/lib:$LD_LIBRARY_PATH
#fi
