#!/bin/bash
# Copyright 2024 Google LLC
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

set -o errexit
set -o pipefail
set -o nounset

PREFIX="/usr"

# The OSS-Fuzz 'compile' script automatically adds instrumentation flags to the CFLAGS and CXXFLAGS
# environment variables. These flags cause build errors with some of the third-party dependencies,
# so we save them for restoration later.
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"

# Set the non-instrumentation flags manually. -O1 is particularly important for avoiding spurious
# timeouts caused by unoptimized dependencies.
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"

# Compile and install GLib
cd "$SRC/glib"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir -Dtests=false -Dsysprof=disabled
ninja -C builddir
ninja -C builddir install

# Compile and install FreeType
cd "$SRC/freetype"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir
ninja -C builddir
ninja -C builddir install

# Compile and install libxml2
cd "$SRC/libxml2"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir
ninja -C builddir
ninja -C builddir install

# Compile and install Fontconfig
cd "$SRC/fontconfig"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir -Dtests=disabled -Dtools=disabled
ninja -C builddir
ninja -C builddir install

# Compile and install Cairo
cd "$SRC/cairo"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir -Dpixman:tests=disabled -Dtests=disabled
ninja -C builddir
ninja -C builddir install

# Compile and install HarfBuzz
cd "$SRC/harfbuzz"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir -Dtests=disabled
ninja -C builddir
ninja -C builddir install

# Compile and install Pango
cd "$SRC/pango"
meson setup --prefix="$PREFIX" --buildtype=plain --default-library=static builddir
ninja -C builddir
ninja -C builddir install

# Restore the compiler flag environment variables
export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"

# Compile and copy the fuzz target(s)
cd "$SRC/librsvg/fuzz"

cargo fuzz build -O
cp target/x86_64-unknown-linux-gnu/release/render_document "$OUT/"

# Copy options files for fuzz targets
cp "$SRC"/*.options "$OUT/"

# Create dictionary files for fuzz targets
cat "$SRC/fuzzing/dictionaries/"{css,svg,xml}.dict > "$OUT/render_document.dict"

# Build a seed corpus consisting of all the SVGs from the librsvg repo
CORPUS_DIR="$WORK/corpus"
mkdir -p "$CORPUS_DIR"

FILES=$(find "$SRC/librsvg" -type f -iname "*.svg")
for file in $FILES; do
  cp "$file" "$CORPUS_DIR/$(md5sum "$file" | cut -f 1 -d ' ').svg"
done

zip -r "$OUT/render_document_seed_corpus.zip" "$CORPUS_DIR"/*
