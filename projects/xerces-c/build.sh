#!/bin/bash
#https://github.com/linux-on-ibm-z/docs/wiki/Building-Xerces
set -e
cd $SRC/xerces-c
./reconf
./configure
make -j
#CC=clang CFLAGS=-fsanitize=address,fuzzer-no-link CXX=clang++ CXXFLAGS=-fsanitize=address,fuzzer-no-link
#CC;CFLAGS;CXX;CXXFLAGS should already be set
#cmake -DBUILD_SHARED_LIBS:BOOL=OFF ..

cd $SRC

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 \
        -I. -Ixerces-c/src \
        xerces_fuzz_common.cpp parse_target.cpp -o $OUT/parse_target \
        xerces-c/src/.libs/libxerces-c.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
	rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc xml.proto --cpp_out=genfiles

	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 \
	        -I. -I xerces-c/src -Ixerces-c/build/src genfiles/xml.pb.cc xmlProtoConverter.cpp xerces_fuzz_common.cpp parse_target_proto.cpp \
	        -I libprotobuf-mutator/ \
	        -I genfiles \
	        -I LPM/external.protobuf/include \
	        -o $OUT/parse_target_proto xerces-c/src/.libs/libxerces-c.a \
	        LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
	        LPM/src/libprotobuf-mutator.a \
	        LPM/external.protobuf/lib/libprotobuf.a
fi
