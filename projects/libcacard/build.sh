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

# Compile NSS
mkdir $SRC/nss-nspr
mv $SRC/nss $SRC/nss-nspr/
mv $SRC/nspr $SRC/nss-nspr/
cd $SRC/nss-nspr/
# We do not need NSS to be built with address sanitizer
CFLAGS="" CXXFLAGS="" nss/build.sh --static --disable-tests

# Create a package config for NSS
cp dist/Debug/lib/pkgconfig/{nspr,nss}.pc
sed -i "s/Debug//g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/\/lib/\/lib\/Debug/g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/include\/nspr/public\/nss/g" dist/Debug/lib/pkgconfig/nss.pc
sed -i "s/NSPR/NSS/g" dist/Debug/lib/pkgconfig/nss.pc
# Derive the NSS link list from the produced archives (names vary across releases)
NSS_LIBS=""
for a in dist/Debug/lib/*.a; do
	name=$(basename "$a" .a)        # e.g. libfreebl_static
	NSS_LIBS="$NSS_LIBS -l${name#lib}"
done
LIBS="-Wl,--start-group $NSS_LIBS -Wl,--end-group -ldl -lm"
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

# NSS dlopen()s its PKCS#11 modules at runtime; ship them with RPATH $ORIGIN
cp $NSS_NSPR_PATH/dist/Debug/lib/*.so $OUT/ 2>/dev/null || true
for so in $OUT/*.so; do
	patchelf --force-rpath --set-rpath '$ORIGIN' "$so" 2>/dev/null || true
done

echo "XXXXXXXX" > $WORK/testinput

fuzzers=$(find $BUILD/fuzz/ -executable -type f)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	patchelf --force-rpath --set-rpath '$ORIGIN' $OUT/$fuzzer 2>/dev/null || true
done

rm $WORK/testinput
