#!/bin/bash
set -e
cd $SRC/xerces-c
mkdir build
cd build
#CC=clang CFLAGS=-fsanitize=address,fuzzer-no-link CXX=clang++ CXXFLAGS=-fsanitize=address,fuzzer-no-link
#CC;CFLAGS;CXX;CXXFLAGS should already be set
cmake -DBUILD_SHARED_LIBS:BOOL=OFF ..
make -j

cd $SRC
rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc xml.proto --cpp_out=genfiles
cd libprotobuf-mutator
#../LPM/external.protobuf/bin/protoc examples/xml/xml.proto --cpp_out=../genfiles
cd $SRC

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 \
        -I../src -I../build/src \
        xerces_fuzz_common.cpp parse_target.cpp -o parse_target \
        ../build/src/libxerces.a

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 \
        -I xerces-c/src -Ixerces-c/build/src genfiles/xml.pb.cc xml_writer.cc xerces_fuzz_common.cpp parse_target_proto.cpp \
        -I libprotobuf-mutator/ \
        -I genfiles \
        -I LPM/external.protobuf/include \
        -o parse_target_proto ../build/src/libxerces.a \
        LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
        LPM/src/libprotobuf-mutator.a \
        LPM/external.protobuf/lib64/libprotobuf.a
