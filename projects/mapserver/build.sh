#!/bin/bash -eu
# Copyright 2026 Google LLC
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

TMP_BUILD_SCRIPT="$(mktemp /tmp/mapserver_build.XXXXXX.sh)"
trap 'rm -f "$TMP_BUILD_SCRIPT"' EXIT
cp "$SRC/MapServer/fuzzers/build.sh" "$TMP_BUILD_SCRIPT"

sed -i 's|test "$0" != "$BUILD_SH_FROM_REPO"|false|' "$TMP_BUILD_SCRIPT"
sed -i 's/libproj15/libproj25/' "$TMP_BUILD_SCRIPT"
sed -i 's/-DBUILD_APPS=OFF/-DBUILD_APPS=OFF -DGDAL_USE_TIFF_INTERNAL=ON -DGDAL_USE_GEOTIFF_INTERNAL=ON -DGDAL_USE_DEFLATE=OFF -DGDAL_USE_ZSTD=OFF -DGDAL_USE_WEBP=OFF -DGDAL_USE_LERC=OFF -DGDAL_USE_CURL=OFF -DGDAL_USE_OPENSSL=OFF/' "$TMP_BUILD_SCRIPT"
sed -i 's/-lfreetype -lproj/-lfreetype -lbz2 -lbrotlidec -lbrotlicommon -lproj/' "$TMP_BUILD_SCRIPT"
sed -i 's/-Wl,-Bdynamic  -lpthread/-Wl,-Bdynamic -lm -lpthread/' "$TMP_BUILD_SCRIPT"

bash -eu "$TMP_BUILD_SCRIPT"
