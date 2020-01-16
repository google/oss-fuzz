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
MAKEFLAGS=-j$(nproc) $SRC/qt/configure -platform linux-clang-libc++ -static -opensource -confirm-license -no-opengl -no-widgets -nomake tests -nomake examples -prefix $OUT
make -j$(nproc)
make install

# prepare corpus files
zip -j $WORK/markdown $SRC/qtqa/fuzzing/testcases/markdown/*
zip -j $WORK/xml $SRC/qtqa/fuzzing/testcases/xml/* /usr/share/afl/testcases/others/xml/*

# build fuzzers
$OUT/bin/qmake $SRC/qt/qtbase/tests/libfuzzer/corelib/serialization/qxmlstream/qxmlstreamreader/readnext/readnext.pro
make -j$(nproc)
mv readnext $OUT
cp $WORK/xml.zip $OUT/readnext_seed_corpus.zip
cp /usr/share/afl/testcases/_extras/xml.dict $OUT/readnext.dict

$OUT/bin/qmake $SRC/qt/qtbase/tests/libfuzzer/gui/text/qtextdocument/setMarkdown/setMarkdown.pro
make -j$(nproc)
mv setMarkdown $OUT
cp $WORK/markdown.zip $OUT/setMarkdown_seed_corpus.zip
