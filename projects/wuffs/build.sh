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

# "Build the project" is a no-op. There is no "./configure.sh && make" dance.
# Wuffs' generated C files are "drop-in libraries" a la
# http://gpfault.net/posts/drop-in-libraries.txt.html

for f in fuzz/c/std/*_fuzzer.c*; do
  # Extract the format name (such as "gzip", from the C or C++ file name,
  # "fuzz/c/std/gzip_fuzzer.c") and make the "gzip_fuzzer" binary. First
  # compile the (C or C++) Wuffs code...
  extension="${f##*.}"
  if [   "$extension" = "c" ]; then
    echo "Building (C)   $f"
    b=$(basename $f _fuzzer.c)
    $CC  $CFLAGS   -c $f -o $WORK/${b}_fuzzer.o
  elif [ "$extension" = "cc" ]; then
    if [[ $LIB_FUZZING_ENGINE == *"DataFlow"* ]]; then
      # Linking (below) with "--engine dataflow" works with the C fuzzers but
      # not the C++ ones. With C++, we get errors like `undefined reference to
      # `dfs$_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev'`
      #
      # This is possibly "DFsan instrumented dependencies"
      # https://github.com/google/oss-fuzz/issues/3388
      echo "Skipping (C++) $f"
      continue
    fi
    echo "Building (C++) $f"
    b=$(basename $f _fuzzer.cc)
    $CXX $CXXFLAGS -c $f -o $WORK/${b}_fuzzer.o
  else
    continue
  fi

  # ...then link the (C++) fuzzing library.
  $CXX $CXXFLAGS $WORK/${b}_fuzzer.o -o $OUT/${b}_fuzzer $LIB_FUZZING_ENGINE

  # Make the optional "gzip_fuzzer_seed_corpus.zip" archive. This means
  # extracting the "foo/bar/*.gz" out of the matching "gzip: foo/bar/*.gz"
  # lines in fuzz/c/std/seed_corpora.txt.
  #
  # The seed_corpora.txt lines can contain multiple entries, combining
  # independent corpora. A naive "zip --junk-paths" of all those files can fail
  # if there are duplicate file names, which can easily happen if the file name
  # is a hash of its contents and the contents are a (trivial) minimal
  # reproducer. We use a de-duplication step of copying all of those files into
  # a single directory. Doing that in a single "cp" or "mv" call can fail with
  # "will not overwrite just-created 'foo/etc' with 'bar/etc'", so we make
  # multiple calls, each copying one file at a time. Later duplicates overwrite
  # earlier duplicates. It's OK if the contents aren't identical. The result is
  # still a valid uber-corpus of seed files.
  seeds=$(sed -n -e "/^$b:/s/^$b: *//p" fuzz/c/std/seed_corpora.txt)
  if [ -n "$seeds" ]; then
    mkdir ${b}_fuzzer_seed_corpus
    for s in $seeds; do
      cp $s ${b}_fuzzer_seed_corpus
    done
    zip --junk-paths --recurse-paths $OUT/${b}_fuzzer_seed_corpus.zip ${b}_fuzzer_seed_corpus
    rm -rf ${b}_fuzzer_seed_corpus
  fi
done
