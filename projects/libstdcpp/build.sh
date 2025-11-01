#!/bin/bash -eu
# Copyright 2023 Google LLC
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
SRCDIR=$SRC/libstdcpp
BUILDDIR=$OUT/build.d
INSTALLDIR=$OUT/install.d
mkdir -p $BUILDDIR $INSTALLDIR

(
    cd $BUILDDIR
    CXX= CC= CXXFLAGS= CFLAGS= $SRCDIR/configure \
       --disable-bootstrap \
       --prefix=$INSTALLDIR \
       --enable-languages=c++
    make -j$(nproc)
    make -j$(nproc) install-target-libstdc++-v3
)

for fuzzsrcfile in /src/*.cpp; do
    targetfile=$(basename $fuzzsrcfile .cpp)
    $CXX \
	$CXXFLAGS \
	-std=c++20 \
	-nostdinc++ \
	-cxx-isystem $( echo $INSTALLDIR/include/c++/*/ ) \
	-cxx-isystem $( echo $INSTALLDIR/include/c++/*/x86_64-pc-linux-gnu ) \
	$fuzzsrcfile \
	-o $OUT/$targetfile \
	$LIB_FUZZING_ENGINE \
	$INSTALLDIR/lib64/libstdc++.a
done

