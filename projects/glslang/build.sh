#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_CTEST=ON -DCMAKE_VERBOSE_MAKEFILE=ON -DENABLE_OPT=0 ../
make V=1 -j4 install


$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/compile_fuzzer.cc \
	-DENABLE_HLSL -DENABLE_OPT=0 -DGLSLANG_OSINCLUDE_UNIX \
	-I/src/glslang/glslang/Include/ -I/src/glslang/glslang/.. \
	-I/src/glslang/build/include -I/src/glslang/SPIRV/.. \
	./glslang/libglslang.a ./SPIRV/libSPIRV.a \
	./hlsl/libHLSL.a \
	./glslang/libglslang-default-resource-limits.a ./SPIRV/libSPVRemapper.a \
	-lpthread ./glslang/libMachineIndependent.a \
	./OGLCompilersDLL/libOGLCompiler.a ./glslang/OSDependent/Unix/libOSDependent.a \
	./glslang/libGenericCodeGen.a \
	-o $OUT/compile_fuzzer
