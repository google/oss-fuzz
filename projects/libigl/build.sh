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
cmake -DLIBIGL_WITH_OPENGL=OFF \
      -DLIBIGL_WITH_OPENGL_GLFW=OFF \
      -DLIBIGL_WITH_OPENGL_GLFW_IMGUI=OFF \
      -DLIBIGL_WITH_COMISO=OFF \
      -DLIBIGL_WITH_EMBREE=OFF \
      -DLIBIGL_WITH_PNG=OFF \
      -DLIBIGL_WITH_TETGEN=OFF \
      -DLIBIGL_WITH_TRIANGLE=OFF \
      -DLIBIGL_WITH_PREDICATES=OFF \
      -LIBIGL_WITH_XML=OFF \
      -DLIBIGL_BUILD_TESTS=ON \
      ..
make -j$(nproc)

$CXX $CXXFLAGS -DIGL_STATIC_LIBRARY \
     -I/src/libigl/include \
     -isystem /src/libigl/cmake/../include \
     -isystem /src/libigl/cmake/../external/eigen \
     -c $SRC/igl_fuzzer.cpp -o fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o   \
     -o $OUT/igl_fuzzer $SRC/libigl/build-dir/libigl.a
