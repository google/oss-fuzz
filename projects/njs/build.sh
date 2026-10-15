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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(uname -s)" = "Darwin" ]; then
  CLANG_RESOURCE_DIR="$(clang -print-resource-dir 2>/dev/null || true)"
  if [ -n "$CLANG_RESOURCE_DIR" ] && \
     [ ! -f "${CLANG_RESOURCE_DIR}/lib/darwin/libclang_rt.fuzzer_osx.a" ]; then
    FUZZ_RT="$(find /opt/homebrew/Cellar/llvm -path '*/lib/clang/*/lib/darwin/libclang_rt.fuzzer_osx.a' 2>/dev/null | sort -V | tail -n 1 || true)"
    if [ -n "${FUZZ_RT}" ] && [ -f "${FUZZ_RT}" ]; then
      export LIB_FUZZING_ENGINE="${FUZZ_RT}"
    fi
  fi
fi

if [ -d "${SRC}/njs" ]; then
  NJS_DIR="${SRC}/njs"
else
  NJS_DIR="/tmp/njs-hunt"
fi

if [ -d "${SRC}/pcre2" ]; then
  PCRE_DIR="${SRC}/pcre2"
else
  PCRE_DIR=""
fi

if [ -d "${SRC}/stubs" ]; then
  STUB_DIR="${SRC}/stubs"
elif [ -d "${SRC}/projects/njs/stubs" ]; then
  STUB_DIR="${SRC}/projects/njs/stubs"
else
  STUB_DIR="${SCRIPT_DIR}/stubs"
fi

if [ -f "${SRC}/ngx_js_form_fuzzer.cc" ]; then
  FORM_FUZZER_SRC="${SRC}/ngx_js_form_fuzzer.cc"
elif [ -f "${SRC}/projects/njs/ngx_js_form_fuzzer.cc" ]; then
  FORM_FUZZER_SRC="${SRC}/projects/njs/ngx_js_form_fuzzer.cc"
else
  FORM_FUZZER_SRC="${SCRIPT_DIR}/ngx_js_form_fuzzer.cc"
fi

if [ -f "${SRC}/ngx_js_form_fuzzer.dict" ]; then
  FORM_FUZZER_DICT="${SRC}/ngx_js_form_fuzzer.dict"
elif [ -f "${SRC}/projects/njs/ngx_js_form_fuzzer.dict" ]; then
  FORM_FUZZER_DICT="${SRC}/projects/njs/ngx_js_form_fuzzer.dict"
else
  FORM_FUZZER_DICT="${SCRIPT_DIR}/ngx_js_form_fuzzer.dict"
fi

if [ -d "${SRC}/seed_corpus" ]; then
  FORM_SEED_DIR="${SRC}/seed_corpus"
elif [ -d "${SRC}/projects/njs/seed_corpus" ]; then
  FORM_SEED_DIR="${SRC}/projects/njs/seed_corpus"
else
  FORM_SEED_DIR="${SCRIPT_DIR}/seed_corpus"
fi

# Build pcre dependency to be linked statically when available.
if [ -n "$PCRE_DIR" ] && [ -d "$PCRE_DIR" ]; then
  pushd "$PCRE_DIR"
  ./autogen.sh
  if [ "${SANITIZER:-}" = "introspector" ]; then
    # Disable sanitizers for introspector for pcre. We only care about njs and it's blocking the build.
    CFLAGS="" CXXFLAGS="" LIB_FUZZING_ENGINE="" ./configure
  else
    CFLAGS="$CFLAGS -fno-use-cxa-atexit" CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit" ./configure
  fi
  make -j"$(nproc)" clean
  make -j"$(nproc)" all
  make install
  sed -i "s/\$libS\$libR \(-lpcre2-8$\)/\$libS\$libR -Wl,-Bstatic \1 -Wl,-Bdynamic/" /usr/local/bin/pcre2-config
  popd
fi

pushd "$NJS_DIR"

./configure

# Add an additional fuzzer target through njs's Makefile build flow.
if ! grep -q "ngx_js_form_fuzzer_shim.o" Makefile; then
cat <<EOF >> Makefile

build/ngx_js_form_fuzzer_shim.o: \\
	${STUB_DIR}/ngx_fuzz_shim.c
	\$(NJS_CC) -c \$(NJS_LIB_INCS) -I${STUB_DIR} \\
		\$(CFLAGS) \$(NJS_LIB_AUX_CFLAGS) \\
		-o build/ngx_js_form_fuzzer_shim.o \\
		${STUB_DIR}/ngx_fuzz_shim.c

build/ngx_js_form_fuzzer_parser.o: \\
	nginx/ngx_js_form.c
	\$(NJS_CC) -c \$(NJS_LIB_INCS) -I${STUB_DIR} \\
		\$(CFLAGS) \$(NJS_LIB_AUX_CFLAGS) \\
		-o build/ngx_js_form_fuzzer_parser.o \\
		nginx/ngx_js_form.c

build/ngx_js_form_fuzzer.o: \\
	${FORM_FUZZER_SRC}
	\$(CXX) -c -I${STUB_DIR} -I. -Inginx \$(CXXFLAGS) \\
		-o build/ngx_js_form_fuzzer.o \\
		${FORM_FUZZER_SRC}

build/ngx_js_form_fuzzer: \\
	build/ngx_js_form_fuzzer.o \\
	build/ngx_js_form_fuzzer_shim.o \\
	build/ngx_js_form_fuzzer_parser.o
	\$(CXX) \$(CXXFLAGS) -o build/ngx_js_form_fuzzer \\
		\$(LIB_FUZZING_ENGINE) \\
		build/ngx_js_form_fuzzer.o \\
		build/ngx_js_form_fuzzer_shim.o \\
		build/ngx_js_form_fuzzer_parser.o \\
		-lm \$(NJS_LIBS) \$(NJS_LIB_AUX_LIBS)

ngx_js_form_fuzzer: build/ngx_js_form_fuzzer
EOF
fi

make -j"$(nproc)" njs_fuzzer ngx_js_form_fuzzer

cp ./build/njs_process_script_fuzzer "$OUT/"
cp ./build/ngx_js_form_fuzzer "$OUT/"

SEED_CORPUS_PATH="$OUT/njs_process_script_fuzzer_seed_corpus"
mkdir -p "$SEED_CORPUS_PATH"

set +x
cat src/test/njs_unit_test.c \
    | egrep -o '".*"' | awk '{print substr($0,2,length($0)-2)}' | sort | uniq \
    | while IFS= read -r line; do
      echo "$line" > "$SEED_CORPUS_PATH/$(echo "$line" | sha1sum | awk '{ print $1 }')";
    done

find test/ -name "*.t.js" \
    | while IFS= read -r testname; do
        cp "$testname" "$SEED_CORPUS_PATH/$(echo "$testname" | sha1sum | awk '{ print $1 }')";
      done
set -x

zip -q -r "$OUT/njs_process_script_fuzzer_seed_corpus.zip" "$SEED_CORPUS_PATH"
rm -rf "$SEED_CORPUS_PATH"

FORM_SEED_TMP="$OUT/ngx_js_form_fuzzer_seed_corpus"
mkdir -p "$FORM_SEED_TMP"
cp -f "$FORM_SEED_DIR"/* "$FORM_SEED_TMP"/
zip -q -j "$OUT/ngx_js_form_fuzzer_seed_corpus.zip" "$FORM_SEED_TMP"/*
rm -rf "$FORM_SEED_TMP"

cp "$FORM_FUZZER_DICT" "$OUT/ngx_js_form_fuzzer.dict"

popd
