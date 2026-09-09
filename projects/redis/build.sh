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
# WITHOUT WARRANTIES OR ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd "${SRC}/redis"

# libFuzzer needs no redis main(); createClient(NULL) needs conn guard; networking.c IO-thread checks.
git apply --ignore-whitespace "${SRC}/patch.diff"

cd src

# Redis's src/Makefile only accepts SANITIZER in {address,undefined,thread,memory}
# and fatals on anything else (e.g. OSS-Fuzz's "coverage").  We handle all
# sanitizer/coverage flags through CFLAGS/LDFLAGS, so remove the error line
# to let unrecognised values pass through harmlessly.
sed -i '/unknown sanitizer/d' Makefile
export MALLOC=libc

ORIG_CFLAGS="${CFLAGS:-}"
ORIG_CXXFLAGS="${CXXFLAGS:-}"
ORIG_LDFLAGS="${LDFLAGS:-}"
SANITIZER_FLAGS="$(
  echo "${ORIG_CFLAGS} ${ORIG_LDFLAGS}" |
    grep -oE -- '(-fsanitize[^ ]+|(-fno-sanitize-recover[^ ]+))' |
    sort -u | tr '\n' ' ' || true
)"
export REDIS_CFLAGS="${REDIS_CFLAGS:-} ${SANITIZER_FLAGS} -DFUZZING_BUILD"
export REDIS_LDFLAGS="${REDIS_LDFLAGS:-} ${SANITIZER_FLAGS}"

strip_san() {
  echo "$1" |
    sed -E 's/-fsanitize[^ ]+//g' |
    sed -E 's/-fno-sanitize-recover[^ ]+//g' |
    sed -E 's/  +/ /g' |
    sed -E 's/^ //;s/ $//'
}
export CFLAGS="$(strip_san "${ORIG_CFLAGS}")"
export CXXFLAGS="$(strip_san "${ORIG_CXXFLAGS}")"
export LDFLAGS="$(strip_san "${ORIG_LDFLAGS}")"

make -C ../deps distclean || true
make -C ../deps -j"${JOBS:-$(nproc)}" \
  MALLOC=libc \
  "CFLAGS=${CFLAGS}" \
  "CXXFLAGS=${CXXFLAGS}" \
  "LDFLAGS=${LDFLAGS}" \
  hiredis linenoise lua hdr_histogram fpconv

# shellcheck disable=SC2046
OBJS="$(grep '^REDIS_SERVER_OBJ=' Makefile | head -1 | cut -d= -f2-)"
# Command-line MALLOC=libc overrides Makefile's Linux default (jemalloc).  The
# address-sanitizer branch sets MALLOC=libc, but SANITIZER=coverage does not.
# shellcheck disable=SC2086
make MALLOC=libc OPTIMIZATION=-O2 -j"${JOBS:-$(nproc)}" ${OBJS}

$CC ${ORIG_CFLAGS} -c "${SRC}/fuzz_server.c" -o fuzz_server.o \
  -I. \
  -I../deps/hiredis \
  -I../deps/linenoise \
  -I../deps/lua/src \
  -I../deps/hdr_histogram \
  -I../deps/fpconv \

DEPS_LIBS="../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a \
  ../deps/hdr_histogram/libhdrhistogram.a ../deps/fpconv/libfpconv.a"
[[ -f ../deps/fast_float/libfast_float.a ]] && DEPS_LIBS+=" ../deps/fast_float/libfast_float.a"
[[ -f ../deps/xxhash/libxxhash.a ]] && DEPS_LIBS+=" ../deps/xxhash/libxxhash.a"

# shellcheck disable=SC2086
$CXX ${ORIG_CXXFLAGS} fuzz_server.o ${OBJS} \
  ${DEPS_LIBS} \
  -lm -ldl -pthread \
  ${LIB_FUZZING_ENGINE} \
  -o "${OUT}/redis_command_fuzzer"

cp "${SRC}/redis_command_fuzzer.options" "${OUT}/"
