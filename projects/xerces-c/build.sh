#!/bin/bash
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
#https://github.com/linux-on-ibm-z/docs/wiki/Building-Xerces
set -e
cd $SRC/xerces-c
./reconf
./configure --disable-shared
make -j

cd $SRC
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 \
        -I. -Ixerces-c/src \
        xerces_fuzz_common.cpp parse_target.cpp -o $OUT/parse_target \
        xerces-c/src/.libs/libxerces-c.a

if [[ $CFLAGS != *sanitize=memory* ]]; then
	rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc xml.proto --cpp_out=genfiles

	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -DNDEBUG -std=c++11 \
	        -I. -I xerces-c/src -Ixerces-c/build/src genfiles/xml.pb.cc xmlProtoConverter.cpp xerces_fuzz_common.cpp parse_target_proto.cpp \
	        -I libprotobuf-mutator/ \
	        -I genfiles \
	        -I LPM/external.protobuf/include \
	        -o $OUT/parse_target_proto xerces-c/src/.libs/libxerces-c.a \
	        LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
	        LPM/src/libprotobuf-mutator.a \
	        LPM/external.protobuf/lib/libprotobuf.a
fi
