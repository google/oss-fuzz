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
cd /usr/local/lib
curl -O https://www.antlr.org/download/antlr-4.9-complete.jar
export CLASSPATH=".:/usr/local/lib/antlr-4.9-complete.jar"
alias antlr4='java -Xmx500M -cp "/usr/local/lib/antlr-4.9-complete.jar:$CLASSPATH" org.antlr.v4.Tool'
alias grun='java -Xmx500M -cp "/usr/local/lib/antlr-4.9-complete.jar:$CLASSPATH" org.antlr.v4.gui.TestRig'

cd /src/antlr4
cd runtime/Cpp/
mkdir build && mkdir run && cd build
cmake .. -DANTLR_JAR_LOCATION=/usr/local/lib/antlr-4.9-complete.jar  -DWITH_DEMO=True -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
make V=1
cd demo
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_cpp_runtime.cpp -I../../demo/generated/ -I../../runtime/src/ CMakeFiles/antlr4-demo.dir/generated/TLexer.cpp.o CMakeFiles/antlr4-demo.dir/generated/TParser.cpp.o CMakeFiles/antlr4-demo.dir/generated/TParserBaseListener.cpp.o CMakeFiles/antlr4-demo.dir/generated/TParserBaseVisitor.cpp.o CMakeFiles/antlr4-demo.dir/generated/TParserListener.cpp.o CMakeFiles/antlr4-demo.dir/generated/TParserVisitor.cpp.o -o $OUT/fuzz_cpp_runtime  ../../dist/libantlr4-runtime.a -luuid
