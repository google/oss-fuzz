# Copyright 2022 Google LLC
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

set -e
SOURCES=(dgif_lib.c egif_lib.c getarg.c gifalloc.c gif_err.c gif_font.c \
        gif_hash.c openbsd-reallocarray.c qprintf.c quantize.c)
cd $SRC/giflib-code
rm -f *.o
for file in ${SOURCES[@]};
do
    name=$(basename $file .c)
    $CC -c -I . $CFLAGS $file -o $name.o
done
ar rc libgif.a *.o

cd $SRC
$CXX $CFLAGS -Wall -c -I giflib-code dgif_target.cc -o dgif_target.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11  -I giflib-code dgif_fuzz_common.cc dgif_target.o  \
        -o $OUT/dgif_target giflib-code/libgif.a

$CXX $CXXFLAGS -Wall -c -I giflib-code egif_target.cc -o egif_target.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11  -I giflib-code egif_fuzz_common.cc egif_target.o  \
        -o $OUT/egif_target giflib-code/libgif.a

rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc gif_fuzz_proto.proto --cpp_out=genfiles

$CXX $CXXFLAGS -DNDEBUG -Wall -c -I giflib-code dgif_protobuf_target.cc -I libprotobuf-mutator/ \
-I genfiles \
-I LPM/external.protobuf/include \
 -o dgif_protobuf_target.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -DNDEBUG -std=c++11 -I. -I giflib-code dgif_protobuf_target.o dgif_fuzz_common.cc genfiles/gif_fuzz_proto.pb.cc \
ProtoToGif.cpp \
-I LPM/external.protobuf/include \
-I genfiles \
LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
LPM/src/libprotobuf-mutator.a \
LPM/external.protobuf/lib/libprotobuf.a \
        -o $OUT/dgif_protobuf_target giflib-code/libgif.a


# Place dict and config in OUT
wget -O $OUT/gif.dict \
  https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/gif.dict \
  &> /dev/null
cp $SRC/*.options $OUT/
find $SRC/giflib-code -iname "*.gif" -exec \
  zip -ujq $OUT/dgif_target_seed_corpus.zip "{}" \;
