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

# Workaround for fixing AFL++ build, discarded for others.
# See https://github.com/google/oss-fuzz/issues/4280#issuecomment-773977943
export AFL_LLVM_INSTRUMENT=CLASSIC,NGRAM-4

# Compile NSS
mkdir $SRC/nss-nspr
mv $SRC/nss $SRC/nss-nspr/
mv $SRC/nspr $SRC/nss-nspr/
cd $SRC/nss-nspr/
# We do not need NSS to be built with address sanitizer
CFLAGS="" CXXFLAGS="" nss/build.sh --static

# Create a package config for NSS
cp dist/Debug/lib/pkgconfig/{nspr,nss}.pc
sed -i "s/Debug//g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/\/lib/\/lib\/Debug/g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/include\/nspr/public\/nss/g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/NSPR/NSS/g" dist/Debug/lib/pkgconfig/nss.pc
LIBS="-lssl -lsmime -lnssdev -lnss_static -lpk11wrap_static -lcryptohi"
LIBS="$LIBS -lcerthi -lcertdb -lnssb -lnssutil -lnsspki -ldl -lm -lsqlite"
LIBS="$LIBS -lsoftokn_static -lsha-x86_c_lib -lfreebl_static"
LIBS="$LIBS -lgcm-aes-x86_c_lib -lhw-acc-crypto-avx -lhw-acc-crypto-avx2"
sed -i "s/Libs:.*/Libs: -L\${libdir} $LIBS/g" dist/Debug/lib/pkgconfig/nss.pc
echo "Requires: nspr" >> dist/Debug/lib/pkgconfig/nss.pc

export NSS_NSPR_PATH=$(realpath $SRC/nss-nspr/)
export PKG_CONFIG_PATH=$NSS_NSPR_PATH/dist/Debug/lib/pkgconfig
export LD_LIBRARY_PATH=$NSS_NSPR_PATH/dist/Debug/lib

# compile libcacard
BUILD=$WORK/meson
rm -rf $BUILD
mkdir $BUILD

cd $SRC/libcacard
# Drop the tests as they are not needed and require too much dependencies
meson $BUILD -Ddefault_library=static -Ddisable_tests=true
ninja -C $BUILD

# We need nss db to work
cp -r tests/db $OUT/

echo "XXXXXXXX" > $WORK/testinput

fuzzers=$(find $BUILD/fuzz/ -executable -type f)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	# Check if it runs at least in build image
	$OUT/$fuzzer $WORK/testinput
	#zip -j $OUT/${fuzzer}_seed_corpus.zip fuzz/corpora/${fuzzer}/*
done

rm $WORK/testinput
