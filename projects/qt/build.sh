#!/bin/bash -eu
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

# add the flags to Qt build, gratefully borrowed from karchive
cd $SRC/qt/qtbase/mkspecs
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" linux-clang-libc++/qmake.conf

# set optimization to O1
sed -i -e "s/QMAKE_CFLAGS_OPTIMIZE      = -O2/QMAKE_CFLAGS_OPTIMIZE      = -O1/g" common/gcc-base.conf
sed -i -e "s/QMAKE_CFLAGS_OPTIMIZE_FULL = -O3/QMAKE_CFLAGS_OPTIMIZE_FULL = -O1/g" common/gcc-base.conf

# build project
cd $WORK
MAKEFLAGS=-j$(nproc) $SRC/qt/configure -platform linux-clang-libc++ -static -opensource -confirm-license -no-opengl -nomake tests -nomake examples -prefix $PWD/qtbase
make -j$(nproc)

# prepare corpus files
zip -j $WORK/html $SRC/qtqa/fuzzing/testcases/html/*
zip -j $WORK/markdown $SRC/qtqa/fuzzing/testcases/markdown/*
zip -j $WORK/xml $SRC/qtqa/fuzzing/testcases/xml/* /usr/share/afl/testcases/others/xml/*

# build fuzzers

build_fuzzer() {
    local nameScheme=$1
    local module=$2
    local proFilePath=$3
    local format=${4-""}
    local dictionary=${5-""}
    local proFileName=${proFilePath##*/}
    local exeName=${proFileName%%.*}
    local proFileDir=${proFilePath%/*}
    local targetName="$module"_${proFileDir//\//_}
    mkdir build_fuzzer
    cd build_fuzzer
    $WORK/qtbase/bin/qmake $SRC/qt/$module/tests/libfuzzer/$proFilePath
    make -j$(nproc)

    # use old names of fuzzers, so open issues don't change state accidentally
    local lowercaseExeName=$exeName
    if [ "$exeName" == "setmarkdown" ]; then
        exeName=setMarkdown
    elif [ "$exeName" == "beginlayout" ]; then
        exeName=beginLayout
    fi
    if [ "$lowercaseExeName" != "$exeName" ]; then
        mv $lowercaseExeName $exeName
    fi
    if [ "$nameScheme" == "old" ]; then
        targetName="$exeName"
    fi

    mv $exeName $OUT/$targetName
    if [ -n "$format" ]; then
        cp $WORK/$format.zip $OUT/"$targetName"_seed_corpus.zip
    fi
    if [ -n "$dictionary" ]; then
        cp $dictionary $OUT/$targetName.dict
    fi
    cd ..
    rm -r build_fuzzer
}

build_fuzzer "old" "qtbase" "corelib/serialization/qxmlstream/qxmlstreamreader/readnext/readnext.pro" "xml" "/usr/share/afl/testcases/_extras/xml.dict"
# build_fuzzer "new" "qtbase" "gui/text/qtextdocument/sethtml/sethtml.pro" "html" "/usr/share/afl/testcases/_extras/html_tags.dict"
build_fuzzer "old" "qtbase" "gui/text/qtextdocument/setmarkdown/setmarkdown.pro" "markdown"
build_fuzzer "old" "qtbase" "gui/text/qtextlayout/beginlayout/beginlayout.pro"
