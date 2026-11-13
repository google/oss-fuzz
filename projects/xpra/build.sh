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
################################################################################

# The fuzz harnesses and their seed corpus generator live in the xpra repository,
# see https://github.com/Xpra-org/xpra/tree/master/tests/fuzz

# Build only the Python modules and the native decoders targeted by the harnesses,
# with the sanitizer flags from the environment:
python3 setup.py install --minimal \
    --with-modules --with-client \
    --with-rencodeplus --with-lz4 --with-brotli --with-zstd --with-websockets

# PyInstaller cannot see the modules imported by the Cython extensions
# (including their shared runtime), or the lazily loaded codecs:
HIDDEN_IMPORTS=""
for module in xpra.cyshared xpra.buffers.membuf xpra.log xpra.net.compression \
              xpra.net.rencodeplus.rencodeplus xpra.net.lz4.lz4 xpra.net.zstd.zstd \
              xpra.net.brotli.decompressor xpra.net.brotli.compressor xpra.net.websockets.mask; do
  HIDDEN_IMPORTS="$HIDDEN_IMPORTS --hidden-import=$module"
done

# The seed corpus generator uses the instrumented decoders,
# so it needs the same runtime that the fuzzer wrappers preload:
ATHERIS_PATH=$(python3 -c "import atheris; print(atheris.path())")
case "$SANITIZER" in
  address) RUNTIME=$ATHERIS_PATH/asan_with_fuzzer.so ;;
  undefined) RUNTIME=$ATHERIS_PATH/ubsan_with_fuzzer.so ;;
  *) RUNTIME= ;;
esac
LD_PRELOAD=$RUNTIME ASAN_OPTIONS=detect_leaks=0 python3 tests/fuzz/make_corpus.py $WORK/corpus

for fuzzer in tests/fuzz/*_fuzzer.py; do
  fuzzer_basename=$(basename -s .py $fuzzer)
  compile_python_fuzzer $fuzzer $HIDDEN_IMPORTS
  zip -q -j $OUT/${fuzzer_basename}_seed_corpus.zip $WORK/corpus/$fuzzer_basename/*
done
