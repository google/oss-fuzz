# Copyright 2019 Google Inc.
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

cd fuzzing
# "Unit tests"
$CXX $CXXFLAGS -std=c++17 -O3 WebSocket.cpp -o $OUT/WebSocket $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++17 -O3 Http.cpp -o $OUT/Http $LIB_FUZZING_ENGINE
$CXX $CXXFLAGS -std=c++17 -O3 PerMessageDeflate.cpp -o $OUT/PerMessageDeflate $LIB_FUZZING_ENGINE -lz
# "Integration tests"
$CC $CFLAGS -DLIBUS_NO_SSL -c -O3 uSocketsMock.c
$CXX $CXXFLAGS -std=c++17 -O3 -DUWS_NO_ZLIB -DLIBUS_NO_SSL -I../src -I../uSockets/src MockedHelloWorld.cpp uSocketsMock.o -o $OUT/MockedHelloWorld $LIB_FUZZING_ENGINE

# Too small tests, failing coverage test
# $CXX $CXXFLAGS -std=c++17 -O3 Extensions.cpp -o $OUT/Extensions $LIB_FUZZING_ENGINE
# $CXX $CXXFLAGS -std=c++17 -O3 Handshake.cpp -o $OUT/Handshake $LIB_FUZZING_ENGINE
