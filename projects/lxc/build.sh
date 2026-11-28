#!/bin/bash -e
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

export CFLAGS="${CFLAGS} -Wno-error=backend-plugin"
# Temporary Ubuntu 24.04 MSan workaround until upstream adds a Meson guard:
# glibc 2.38+ exports uninstrumented strlcpy/strlcat, causing MSan false
# positives unless lxc uses its internal fallback implementations.
if [ "$SANITIZER" = "memory" ]; then
  MESON_BUILD="$PWD/meson.build"
  MESON_BACKUP="$(mktemp /tmp/lxc_meson.XXXXXX)"
  cp "$MESON_BUILD" "$MESON_BACKUP"
  trap 'cp -f "$MESON_BACKUP" "$MESON_BUILD" && rm -f "$MESON_BACKUP"' EXIT
  sed -i "s/have = cc.has_function(ident\[0\], prefix: ident\[1\], args: '-D_GNU_SOURCE')/have = ident[0] in ['strlcpy', 'strlcat'] ? false : cc.has_function(ident[0], prefix: ident[1], args: '-D_GNU_SOURCE')/" "$MESON_BUILD"
fi
src/tests/oss-fuzz.sh
cp $SRC/*.options $OUT/
