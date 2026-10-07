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

# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"
export MSAN_OPTIONS="halt_on_error=0:exitcode=0:report_umrs=0"

# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}

FLAGS=()
case $SANITIZER in
  address)
    FLAGS+=("--with-address-sanitizer")
    ;;
  memory)
    FLAGS+=("--with-memory-sanitizer")
    # installing ensurepip takes a while with MSAN instrumentation, so
    # we disable it here
    FLAGS+=("--without-ensurepip")
    ;;
  undefined)
    FLAGS+=("--with-undefined-behavior-sanitizer")
    ;;
esac

pushd $SRC/Python-3.8.3/
if [ -e $OUT/sanpy/cflags -a "$(cat $OUT/sanpy/cflags)" = "${CFLAGS}" ] ; then
    echo 'Python cflags unchanged, no need to rebuild'
else
    rm -rf $OUT/sanpy
    ./configure "${FLAGS[@]:-}" \
                --prefix=$OUT/sanpy CFLAGS="${CFLAGS}" LINKCC="${CXX}" \
                LDFLAGS="${CXXFLAGS}"
    grep -v HAVE_GETC_UNLOCKED < pyconfig.h > tmp && mv tmp pyconfig.h
    make && make install
    echo "${CFLAGS}" > $OUT/sanpy/cflags
fi
popd

cd contrib/fuzz
make clean oss-fuzz PYTHON_CONFIG=$OUT/sanpy/bin/python3.8-config PYTHON_CONFIG_FLAGS="--ldflags --embed"
