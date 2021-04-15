#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

#add next branch
for branch in v4 next
do
    cd capstone$branch
    # build project
    mkdir build
    # does not seem to work in source directory
    # + make.sh overwrites CFLAGS
    cd build
    cmake -DCAPSTONE_BUILD_SHARED=0 ..
    make

    cd $SRC/capstone$branch/bindings/python
    #better debug info
    sed -i -e 's/#print/print/' capstone/__init__.py
    (
    export CFLAGS=""
    export AFL_NOOPT=1
    python setup.py install
    )
    cd $SRC/capstone$branch/suite
    mkdir fuzz/corpus
    find MC/ -name *.cs | ./test_corpus.py
    cd fuzz
    zip -r fuzz_disasm"$branch"_seed_corpus.zip corpus/
    cp fuzz_disasm"$branch"_seed_corpus.zip $OUT/

    # export other associated stuff
    cp fuzz_disasm.options $OUT/fuzz_disasm$branch.options

    cd ../../build
    # build fuzz target
    FUZZO=CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o
    if [ -f CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o ]; then
        FUZZO="$FUZZO CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
    fi
    $CXX $CXXFLAGS $FUZZO -o $OUT/fuzz_disasm$branch libcapstone.a $LIB_FUZZING_ENGINE

    cd ../../
done
