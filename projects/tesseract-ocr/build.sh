#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

TMP_BUILD_SCRIPT="$(mktemp /tmp/tesseract_build.XXXXXX.sh)"
trap 'rm -f "$TMP_BUILD_SCRIPT"' EXIT
cp "$SRC/tesseract/unittest/fuzzers/oss-fuzz-build.sh" "$TMP_BUILD_SCRIPT"

sed -i 's#LEPTONICA_LIBS=$(pkg-config --static --libs lept)#LEPTONICA_LIBS=$(pkg-config --static --libs lept | sed "s/ -lm\\b//g")#' "$TMP_BUILD_SCRIPT"
sed -i 's#LIBTIFF_LIBS=$(pkg-config --static --libs libtiff-4 | sed '\''s/ -lm//'\'')#LIBTIFF_LIBS=$(pkg-config --static --libs libtiff-4 | sed "s/ -lm\\b//g")#' "$TMP_BUILD_SCRIPT"
sed -i 's#-Wl,-Bdynamic#-Wl,-Bdynamic -l:libstdc++.so.6 -lm#g' "$TMP_BUILD_SCRIPT"

bash -eu "$TMP_BUILD_SCRIPT"
