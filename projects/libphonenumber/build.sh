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

export CXXFLAGS="$CXXFLAGS -std=c++14"

# For coverage build we need to remove some flags when building protobuf and icu
if [ "$SANITIZER" = "coverage" ]
then
    export OCX=$CXXFLAGS
    export OC=$CFLAGS
    CF1=${CFLAGS//-fprofile-instr-generate/}
    export CFLAGS=${CF1//-fcoverage-mapping/}
    CXF1=${CXXFLAGS//-fprofile-instr-generate/}
    export CXXFLAGS=${CXF1//-fcoverage-mapping/}
fi

cd $SRC/abseil-cpp
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ../  && make -j$(nproc) && make install
ldconfig

# Build Protobuf
mkdir $SRC/protobuf-install
cd $SRC/protobuf-install
cmake $SRC/protobuf/cmake -Dprotobuf_BUILD_TESTS=OFF -DABSL_ROOT_DIR=$SRC/abseil-cpp
make -j$(nproc)
make install
cp $SRC/protobuf/src/google/protobuf/*.inc /usr/local/include/google/protobuf/

# Build icu
export DEPS_PATH=/src/deps/
mkdir $DEPS_PATH

# build ICU for linking statically.
cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static --prefix=$DEPS_PATH
make install -j$(nproc)

# Ugly ugly hack to get static linking to work for icu.
cd $DEPS_PATH/lib
ls *.a | xargs -n1 ar x
rm *.a
ar r libicu.a *.{ao,o}
ln -s libicu.a libicudata.a
ln -s libicu.a libicuuc.a
ln -s libicu.a libicui18n.a

if [ "$SANITIZER" = "coverage" ]
then
    export CFLAGS=$OC
    export CXXFLAGS=$OCX
fi

# Build libphonenumber
cd $SRC/libphonenumber/cpp
sed -i 's/set (BUILD_SHARED_LIB true)/set (BUILD_SHARED_LIB false)/g' CMakeLists.txt
sed -i 's/set(CMAKE_CXX_STANDARD 11/set(CMAKE_CXX_STANDARD 14/g' CMakeLists.txt
sed -i 's/list (APPEND CMAKE_C_FLAGS "-pthread")/string (APPEND CMAKE_C_FLAGS " -pthread")/g' CMakeLists.txt
sed -i 's/# Safeguarding/find_package(absl REQUIRED) # Safeguarding/g' CMakeLists.txt

mkdir build
cd build
cmake -DUSE_BOOST=OFF -DBUILD_GEOCODER=OFF \
      -DBUILD_STATIC_LIB=ON -DBUILD_SHARED_LIBS=OFF \
      -DPROTOBUF_LIB="/src/protobuf-install/libprotobuf.a" \
      -DBUILD_TESTING=OFF \
      -DICU_UC_INCLUDE_DIR=$SRC/icu/source/comon \
      -DICU_UC_LIB=$DEPS_PATH/lib/libicuuc.a \
      -DICU_I18N_INCLUDE_DIR=$SRC/icu/source/i18n/ \
      -DICU_I18N_LIB=$DEPS_PATH/lib/libicui18n.a  \
      -DREGENERATE_METADATA=OFF \
      ../
make -j$(nproc)

# list of fuzz targets
FUZZ_TARGETS=(
    "fuzz_phone" 
    "fuzz_shortnumberinfo"
    "fuzz_asyoutypeformatter"
    "fuzz_matcher"
)

# libraries for building the fuzzers
LIBS=(
    "./libphonenumber.a"
    "$SRC/protobuf-install/libprotobuf.a"
    "/usr/local/lib/libabsl_cord.a"
    "/usr/local/lib/libabsl_cordz_info.a"
    "/usr/local/lib/libabsl_cord_internal.a"
    "/usr/local/lib/libabsl_cordz_functions.a"
    "/usr/local/lib/libabsl_cordz_handle.a"
    "/usr/local/lib/libabsl_hash.a"
    "/usr/local/lib/libabsl_city.a"
    "/usr/local/lib/libabsl_bad_variant_access.a"
    "/usr/local/lib/libabsl_low_level_hash.a"
    "/usr/local/lib/libabsl_raw_hash_set.a"
    "/usr/local/lib/libabsl_bad_optional_access.a"
    "/usr/local/lib/libabsl_hashtablez_sampler.a"
    "/usr/local/lib/libabsl_exponential_biased.a"
    "/usr/local/lib/libabsl_synchronization.a"
    "/usr/local/lib/libabsl_graphcycles_internal.a"
    "/usr/local/lib/libabsl_stacktrace.a"
    "/usr/local/lib/libabsl_symbolize.a"
    "/usr/local/lib/libabsl_malloc_internal.a"
    "/usr/local/lib/libabsl_debugging_internal.a"
    "/usr/local/lib/libabsl_demangle_internal.a"
    "/usr/local/lib/libabsl_time.a"
    "/usr/local/lib/libabsl_strings.a"
    "/usr/local/lib/libabsl_strings_internal.a"
    "/usr/local/lib/libabsl_throw_delegate.a"
    "/usr/local/lib/libabsl_int128.a"
    "/usr/local/lib/libabsl_civil_time.a"
    "/usr/local/lib/libabsl_time_zone.a"
    "/usr/local/lib/libabsl_base.a"
    "/usr/local/lib/libabsl_raw_logging_internal.a"
    "/usr/local/lib/libabsl_log_severity.a"
    "/usr/local/lib/libabsl_spinlock_wait.a"
    "$DEPS_PATH/lib/libicu.a"
)

# build fuzzers
for target in "${FUZZ_TARGETS[@]}"; do
    $CXX -I$SRC/libphonenumber/cpp/src $CXXFLAGS -o ${target}.o -c ../test/phonenumbers/${target}.cc
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${target}.o -o $OUT/${target} \
        ${LIBS[@]} \
        -lrt -lpthread
done
