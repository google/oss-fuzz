#!/bin/bash -eu
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

mkdir build-dir && cd build-dir
cmake -DLIBIGL_OPENGL=OFF \
      -DLIBIGL_GLFW=OFF \
      -DLIBIGL_IMGUI=OFF \
      -DLIBIGL_COMISO=OFF \
      -DLIBIGL_EMBREE=OFF \
      -DLIBIGL_PNG=OFF \
      -DLIBIGL_COPYLEFT_CORE=OFF \
      -DLIBIGL_COPYLEFT_CGAL=OFF \
      -DLIBIGL_COPYLEFT_TETGEN=OFF \
      -DLIBIGL_COPYLEFT_COMISO=OFF \
      -DLIBIGL_RESTRICTED_TRIANGLE=OFF \
      -DLIBIGL_PREDICATES=OFF \
      -DLIBIGL_XML=OFF \
      -DLIBIGL_RESTRICTED_MATLAB=OFF \
      -DLIBIGL_BUILD_TESTS=OFF \
      ..
make -j$(nproc)

$CXX $CXXFLAGS -DIGL_STATIC_LIBRARY \
     -I/src/libigl/include \
     -isystem /src/libigl/cmake/../include \
     -isystem /src/libigl/cmake/../external/eigen \
     -c $SRC/igl_fuzzer.cpp -o fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o   \
     -o $OUT/igl_fuzzer $SRC/libigl/build-dir/lib/libigl.a
