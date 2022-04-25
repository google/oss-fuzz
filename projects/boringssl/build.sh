#!/bin/bash -eux
#
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
mkdir -p $WORK/boringssl
cd $WORK/boringssl

CFLAGS="$CFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"
CXXFLAGS="$CXXFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"

CMAKE_DEFINES="-DBORINGSSL_ALLOW_CXX_RUNTIME=1"
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CMAKE_DEFINES+=" -DOPENSSL_NO_ASM=1"
fi

cmake -GNinja -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      $CMAKE_DEFINES $SRC/boringssl/
ninja

fuzzerFiles=$(find $SRC/boringssl/fuzz/ -name "*.cc")

find . -name "*.a"

for F in $fuzzerFiles; do
  fuzzerName=$(basename $F .cc)
  echo "Building fuzzer $fuzzerName"
  $CXX $CXXFLAGS \
      -o $OUT/${fuzzerName} $LIB_FUZZING_ENGINE $F \
      -I $SRC/boringssl/include ./ssl/libssl.a  ./crypto/libcrypto.a

  if [ -d "$SRC/boringssl/fuzz/${fuzzerName}_corpus" ]; then
    zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/boringssl/fuzz/${fuzzerName}_corpus/*
  fi
done

if [[ $CFLAGS != *sanitize=memory* ]]; then
  fuzzerLPMFiles=$(find $SRC/ -maxdepth 1 -name "*.cc")

  cp $SRC/fuzzing/proto/asn1-pdu/* $SRC/

  rm -rf genfiles && mkdir genfiles && $SRC/LPM/external.protobuf/bin/protoc asn1_pdu.proto --cpp_out=genfiles --proto_path=$SRC/

  for F in $fuzzerLPMFiles
  do
    fuzzerName=$(echo ${F#*_})
    fuzzerName=$(basename $fuzzerName .cc)
    echo "Building fuzzer $fuzzerName"
    $CXX $CXXFLAGS -I genfiles -I . -I $SRC/libprotobuf-mutator/ -I $SRC/LPM/external.protobuf/include -I include $LIB_FUZZING_ENGINE \
        -I $SRC/boringssl/include \
        $F genfiles/asn1_pdu.pb.cc $SRC/asn1_pdu_to_der.cc $SRC/common.cc \
        ./ssl/libssl.a ./crypto/libcrypto.a \
        $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
        $SRC/LPM/src/libprotobuf-mutator.a \
        $SRC/LPM/external.protobuf/lib/libprotobuf.a \
        -o $OUT/"${fuzzerName}_lpm"
  done
fi
