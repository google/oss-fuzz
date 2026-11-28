#!/bin/bash -eu
# Copyright 2025 Google LLC
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
###########################################################################
export CXXFLAGS="${CXXFLAGS:-}"
export FUZZER_FLAGS="${FUZZER_FLAGS:--fsanitize=fuzzer -std=c++17 -fPIC -pie}"
export OUT="${OUT:-/app/out}"
export CXX="${CXX:-/usr/bin/clang++}"
export FUZZER_NAME="kcodecs_fuzzer"

export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:/usr/share/pkgconfig"

echo "--- Creating output directory: $OUT ---"
mkdir -p "$OUT"
if [ ! -d "$OUT" ]; then
    echo "ERROR: Failed to create output directory $OUT!"
    exit 1
fi
echo "Output directory $OUT created successfully."

mkdir -p "/src"

echo "--- Configuring Qt5 ---"
if command -v pkg-config &> /dev/null; then
    QT_CFLAGS=$(pkg-config --cflags Qt5Core Qt5Gui Qt5Network Qt5Widgets Qt5Xml Qt5XmlPatterns Qt5Sql 2>/dev/null || echo "")
    QT_LIBS=$(pkg-config --libs Qt5Core Qt5Gui Qt5Network Qt5Widgets Qt5Xml Qt5XmlPatterns Qt5Sql 2>/dev/null || echo "")
else
    echo "Warning: pkg-config not found. Cannot use it for Qt flags."
    QT_CFLAGS=""
    QT_LIBS=""
fi

if [ -z "$QT_CFLAGS" ]; then
    echo "Warning: Qt5Core, Qt5Gui, etc. not found by pkg-config. Using default include paths and explicit library names."
    QT_ALL_INCLUDE_PATHS="-I/usr/include/qt5 -I/usr/include/qt5/QtCore -I/usr/include/qt5/QtGui -I/usr/include/qt5/QtWidgets -I/usr/include/qt5/QtNetwork -I/usr/include/qt5/QtXml -I/usr/include/qt5/QtXmlPatterns -I/usr/include/qt5/QtSql"
    QT_LIBS="-lQt5Core -lQt5Gui -lQt5Network -lQt5Widgets -lQt5Xml -lQt5XmlPatterns -lQt5Sql"
else
    echo "Using Qt5 flags from pkg-config: CFLAGS=$QT_CFLAGS LIBS=$QT_LIBS"
    QT_ALL_INCLUDE_PATHS="$QT_CFLAGS"
fi

echo "--- Configuring KCodecs ---"
KCODECS_CUSTOM_INCLUDE="-I/usr/include/KF5 -I/usr/include/KF5/KCodecs"

if command -v pkg-config &> /dev/null; then
    KCODECS_PC_CFLAGS=$(pkg-config --cflags KF5Codecs 2>/dev/null || echo "")
    KCODECS_PC_LIBS=$(pkg-config --libs KF5Codecs 2>/dev/null || echo "")
else
    echo "Warning: pkg-config not found. Cannot use it for KF5Codecs flags."
    KCODECS_PC_CFLAGS=""
    KCODECS_PC_LIBS=""
fi

if [ -z "$KCODECS_PC_LIBS" ]; then
    echo "Warning: KF5Codecs not found by pkg-config. Using explicit library name."
    KCODECS_LIBS="-lKF5Codecs"
else
    echo "Using KF5Codecs flags from pkg-config: CFLAGS=$KCODECS_PC_CFLAGS LIBS=$KCODECS_PC_LIBS"
    KCODECS_CUSTOM_INCLUDE="$KCODECS_CUSTOM_INCLUDE $KCODECS_PC_CFLAGS"
    KCODECS_LIBS="$KCODECS_PC_LIBS"
fi

echo "--- Compiling kcodecs_fuzzer.cc ---"
echo "QT ALL INCLUDE PATHS: $QT_ALL_INCLUDE_PATHS"
echo "QT LIBS: $QT_LIBS"
echo "KCODECS CUSTOM INCLUDE: $KCODECS_CUSTOM_INCLUDE"
echo "KCODECS LIBS: $KCODECS_LIBS"

echo "Current working directory before compilation:"
pwd
echo "Contents of /app/out/ before compilation:"
ls -la /app/out/
echo "Contents of /src/ before compilation:"
ls -la /src/

set -x

$CXX $CXXFLAGS $FUZZER_FLAGS \
    $QT_ALL_INCLUDE_PATHS $KCODECS_CUSTOM_INCLUDE \
    -c /src/kcodecs_fuzzer.cc -o "kcodecs_fuzzer.o"
COMPILE_STATUS=$?
set +x

echo "Contents of /app/out/ after compilation (before move):"
ls -la /app/out/
echo "Contents of /src/ after compilation (before move):"
ls -la /src/

if [ $COMPILE_STATUS -eq 0 ] && [ -f "kcodecs_fuzzer.o" ]; then
    echo "Fuzzer object file kcodecs_fuzzer.o found in /src/. Moving to $OUT..."
    mv "kcodecs_fuzzer.o" "$OUT/"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to move kcodecs_fuzzer.o to $OUT!"
        exit 1
    fi
    echo "Fuzzer object file moved to $OUT successfully."
else
    echo "ERROR: kcodecs_fuzzer.o was not created in /src/ after compilation, or compilation failed!"
    exit 1
fi

if [ ! -f "$OUT/kcodecs_fuzzer.o" ]; then
    echo "ERROR: Fuzzer object file $OUT/kcodecs_fuzzer.o was not created/moved to $OUT despite successful compilation command!"
    exit 1
fi

echo "Object file $OUT/kcodecs_fuzzer.o created and moved successfully."

echo "--- Linking kcodecs_fuzzer ---"
set -x

$CXX $CXXFLAGS $FUZZER_FLAGS \
    "$OUT/kcodecs_fuzzer.o" \
    -Wl,--no-as-needed $QT_LIBS $KCODECS_LIBS \
    -o "$OUT/$FUZZER_NAME"
LINK_STATUS=$?
set +x

if [ $LINK_STATUS -ne 0 ]; then
    echo "ERROR: Linking of kcodecs_fuzzer failed with exit code $LINK_STATUS!"
    exit 1
fi

if [ ! -f "$OUT/$FUZZER_NAME" ]; then
    echo "ERROR: Fuzzer executable $OUT/$FUZZER_NAME was not created! Check linking step and compiler output carefully."
    echo "Contents of $OUT/:"
    ls -la "$OUT/"
    exit 1
fi

echo "Fuzzer executable $OUT/$FUZZER_NAME created successfully."

chmod +x "$OUT/$FUZZER_NAME"

cp -r "/src/corpus.tar.gz" "$OUT/" || true
echo "Corpus copied to $OUT/"
