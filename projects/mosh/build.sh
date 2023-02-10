#!/bin/sh
# Copyright 2022 Google LLC
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

set -eu

./autogen.sh

# Sniff $CXXFLAGS to figure out what to pass to ./configure.
configure_flags=
case $CXXFLAGS in
  *-fsanitize=address*)
    configure_flags="$configure_flags --enable-asan"
    ;;
esac
case $CXXFLAGS in
  *-fcoverage*)
    configure_flags="$configure_flags --enable-code-coverage"
    ;;
esac

# Use libstdc++, not libc++, since the base image's prebuild libraries require
# libstdc++.
export CXXFLAGS="$CXXFLAGS -stdlib=libstdc++"

# Clear CFLAGS and CXXFLAGS during configure tests so configure won't try to
# link with -fsanitize=fuzz.
CFLAGS= CXXFLAGS= ./configure --disable-silent-rules --enable-fuzzing --enable-static-libraries $configure_flags

n=$(nproc)
make -j$n CFLAGS+="$CFLAGS" CXXFLAGS+="$CXXFLAGS"

cd src/fuzz

make -j$n CFLAGS+="$CFLAGS" CXXFLAGS+="$CXXFLAGS"

for fuzzer in *_fuzzer; do
  cp $fuzzer $OUT

  corpus=${fuzzer%_fuzzer}_corpus
  if [ -d $corpus ]; then
    zip -j $OUT/${fuzzer}_seed_corpus.zip $corpus/*
  fi
done
