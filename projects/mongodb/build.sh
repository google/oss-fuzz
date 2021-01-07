# Copyright 2021 Google LLC
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

cd $SRC/
mkdir mongo-c-driver-install

cd mongo-c-driver
mkdir cmake-build && cd cmake-build
#cmake -DENABLE_MONGOC=ON -DENABLE_BSON_AUTO=ON -DENABLE_STATIC=ON -DCMAKE_INSTALL_PATH="$SRC/mongo-c-driver-install" ../ 
cmake -DENABLE_MONGOC=ON  -DENABLE_STATIC=ON -DCMAKE_INSTALL_PREFIX="/src/mongo-c-driver-install/" ../
make install

$CC $CFLAGS -I./src \
    -I./src/libbson/src -I./src/libbson/src/bson -I./src/common \
    -I../src/libbson/src -I../src/libbson/src/bson -I../src/common \
    -c ../src/libbson/fuzz/fuzz_test_libbson.c -o fuzz_test_libbson.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_test_libbson.o \
    ./src/libbson/libbson-static-1.0.a -o $OUT/fuzz-libbson

# libmongocrypt
#cd $SRC/libmongocrypt
#mkdir cmake-build && cd cmake-build
#cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_PREFIX_PATH="$SRC/mongo-c-driver-install" ../
#make

#$CC $CFLAGS $LIB_FUZZING_ENGINE ./test/fuzz_kms.c -o $OUT/fuzz_kms \
#    -I../kms-message/ ./kms-message/libkms_message-static.a -lssl -lcrypto

# Mongodb
cd $SRC
git clone https://github.com/mongodb/mongo
cd mongo
pip3 install psutil pyyaml Cheetah3

SAN=""
if [ $SANITIZER == "address" ]; then
  #python3 src/third_party/scons-3.1.2/scons.py CC=clang CXX=clang++ --libc++ --disable-warnings-as-errors --sanitize=fuzzer,address LLVM_SYMBOLIZER=llvm-symbolizer --allocator=system VERBOSE=on ./src/mongo/bson/ 
  SAN=",address"
elif [ $SANITIZER == "undefined" ]; then
  #python3 src/third_party/scons-3.1.2/scons.py CC=clang CXX=clang++ --libc++ --disable-warnings-as-errors --sanitize=fuzzer,undefined LLVM_SYMBOLIZER=llvm-symbolizer  --allocator=system VERBOSE=on ./src/mongo/bson/
  SAN=",undefined"
#elif [ $SANITIZER == "coverage" ]; then
fi

python3 src/third_party/scons-3.1.2/scons.py CC=$CC CXX=$CXX --libc++ --disable-warnings-as-errors --sanitize=fuzzer${SAN} LLVM_SYMBOLIZER=llvm-symbolizer  --allocator=system VERBOSE=on ./src/mongo/bson/
mv ./build/opt/mongo/bson/bson_validate_fuzzer $OUT/bson_validate_fuzzer

#python3 src/third_party/scons-3.1.2/scons.py CC=clang CXX=clang++ --libc++ --disable-warnings-as-errors --sanitize=fuzzer${SAN} LLVM_SYMBOLIZER=llvm-symbolizer  --allocator=system VERBOSE=on ./src/mongo/db
#mv ./build/opt/mongo/db/op_msg_fuzzer
