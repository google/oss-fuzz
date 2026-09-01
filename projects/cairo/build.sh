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

# For fuzz-introspector, exclude all external code from reports
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
subprojects
EOF

PREFIX=$WORK/prefix
CAIRO_DEPS=/deps

export PKG_CONFIG="`which pkg-config` --static"
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig:$CAIRO_DEPS/lib/pkgconfig
export PATH=$PREFIX/bin:$CAIRO_DEPS/bin:$PATH

# BUILD=$WORK/build
rm -rf $WORK/*

# workaround: tell meson to use gold on fuzz-introspector builds
# https://github.com/google/oss-fuzz/pull/7583#issuecomment-1104011067
if [[ "$SANITIZER" == introspector ]]; then
    # -fuse-ld=gold can't be passed via CFLAGS/CXXFLAGS/LDFLAGS due to
    # https://github.com/mesonbuild/meson/issues/6377 and
    # https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919
    MESON_CFLAGS="${CFLAGS//-fuse-ld=gold/ }"
    MESON_CXXFLAGS="${CXXFLAGS//-fuse-ld=gold/ }"
    MESON_OPTIONS="-Db_lto=true"

    export CC_LD=gold
    export CXX_LD=gold
else
    MESON_CFLAGS=$CFLAGS
    MESON_CXXFLAGS=$CXXFLAGS
    MESON_OPTIONS=""
fi

# Build cairo
pushd $SRC/cairo
CFLAGS="-DDEBUG_SVG_RENDER $MESON_CFLAGS" \
CXXFLAGS=MESON_CXXFLAGS meson \
    setup \
    --prefix=$PREFIX \
    --libdir=lib \
    --default-library=static \
    -Db_lundef=false \
    --wrap-mode=nofallback \
    $MESON_OPTIONS \
    _builddir
ninja -C _builddir
ninja -C _builddir install
popd

mv $SRC/{*.zip,*.dict} $OUT

if [ ! -f "${OUT}/cairo_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/cairo.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 cairo cairo-gobject cairo-script-interpreter"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS` -I$SRC/fuzz"
BUILD_LDFLAGS="`pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/fuzz/ -name "*_fuzzer.c")
for f in $fuzzers ; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS \
    -c $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/${fuzzer_name} \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
  cd $OUT; ln -sf cairo_seed_corpus.zip ${fuzzer_name}_seed_corpus.zip
  cd $OUT; ln -sf cairo.dict ${fuzzer_name}.dict
done

# Fuzzers with non-PNG dict/seed corpus.
for f in $SRC/cairo/test/svg/fuzzer/svg-render-fuzzer.c ; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS \
    -c $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/${fuzzer_name} \
    $PREDEPS_LDFLAGS \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
done

# copy deps into $OUT so fuzz-introspector can see the header files
rsync -avr $CAIRO_DEPS/ $OUT/deps
