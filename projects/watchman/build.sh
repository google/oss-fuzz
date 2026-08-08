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

cd "$SRC/watchman"

FUZZ_BUILD_DIR="$WORK/watchman-fuzz-build"
mkdir -p \
  "$FUZZ_BUILD_DIR/folly/portability" \
  "$FUZZ_BUILD_DIR/watchman"

cat > "$FUZZ_BUILD_DIR/watchman/config.h" <<'EOF'
#pragma once

#define PACKAGE_VERSION "oss-fuzz"
EOF

cat > "$FUZZ_BUILD_DIR/watchman/Logging.h" <<'EOF'
#pragma once

#include <cstdlib>
#include <fmt/core.h>

namespace watchman {
enum LogLevel { ABORT = -2, FATAL = -1, OFF = 0, ERR = 1, DBG = 2 };

template <typename... Args>
void log(LogLevel, Args&&...) {}

template <typename... Args>
void logf(LogLevel level, fmt::string_view, Args&&...) {
  if (level <= FATAL) {
    std::abort();
  }
}

template <typename... Args>
void logf_stderr(fmt::string_view, Args&&...) {}
} // namespace watchman

#define w_check(e, ...) \
  do {                  \
    if (!(e)) {         \
      std::abort();     \
    }                   \
  } while (0)

#define w_assert(e, ...) ((void)0)
EOF

cat > "$FUZZ_BUILD_DIR/folly/FBString.h" <<'EOF'
#pragma once

#include <string>

namespace folly {
class fbstring : public std::string {
 public:
  using std::string::string;
};
} // namespace folly
EOF

cat > "$FUZZ_BUILD_DIR/folly/String.h" <<'EOF'
#pragma once
EOF

cat > "$FUZZ_BUILD_DIR/folly/portability/SysTypes.h" <<'EOF'
#pragma once

#include <sys/types.h>
EOF

cat > "$FUZZ_BUILD_DIR/folly/portability/Unistd.h" <<'EOF'
#pragma once

#include <unistd.h>
EOF

COMMON_CXXFLAGS=(
  -std=c++20
  -DNDEBUG
  -DFMT_HEADER_ONLY
  -I"$FUZZ_BUILD_DIR"
  -I"$SRC/watchman"
)

JANSSON_SOURCES=(
  watchman/string.cpp
  watchman/thirdparty/jansson/dump.cpp
  watchman/thirdparty/jansson/error.cpp
  watchman/thirdparty/jansson/load.cpp
  watchman/thirdparty/jansson/strconv.cpp
  watchman/thirdparty/jansson/utf.cpp
  watchman/thirdparty/jansson/value.cpp
)

"$CXX" $CXXFLAGS "${COMMON_CXXFLAGS[@]}" \
  watchman/fuzz/BserDecode.cpp \
  watchman/bser.cpp \
  "${JANSSON_SOURCES[@]}" \
  -o "$OUT/bser_decode" \
  $LIB_FUZZING_ENGINE

"$CXX" $CXXFLAGS "${COMMON_CXXFLAGS[@]}" \
  watchman/fuzz/JsonDecode.cpp \
  "${JANSSON_SOURCES[@]}" \
  -o "$OUT/json_decode" \
  $LIB_FUZZING_ENGINE

PYTHON_CFLAGS=$(python3-config --includes)
if python3-config --embed --ldflags >/dev/null 2>&1; then
  PYTHON_LDFLAGS=$(python3-config --embed --ldflags)
else
  PYTHON_LDFLAGS=$(python3-config --ldflags)
fi

"$CC" $CFLAGS $PYTHON_CFLAGS \
  -c watchman/python/pywatchman/bser.c \
  -o "$FUZZ_BUILD_DIR/pybser.o"

"$CXX" $CXXFLAGS "${COMMON_CXXFLAGS[@]}" $PYTHON_CFLAGS \
  watchman/fuzz/PyBserDecode.cpp \
  "$FUZZ_BUILD_DIR/pybser.o" \
  -o "$OUT/pybser_decode" \
  $LIB_FUZZING_ENGINE $PYTHON_LDFLAGS

cat > "$OUT/pybser_decode.options" <<'EOF'
[asan]
detect_leaks=0

[libfuzzer]
detect_leaks=0
EOF

PYTHON_LIBDIR=$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))')
PYTHON_LDLIB=$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LDLIBRARY"))')
cp "$PYTHON_LIBDIR/$PYTHON_LDLIB" "$OUT/"

patchelf --set-rpath '$ORIGIN' "$OUT/pybser_decode"
