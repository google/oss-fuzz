#!/bin/bash -eu

export ASAN_OPTIONS="detect_leaks=0"
FUZZ_CFLAGS=${CFLAGS//"-pthread"/}

export PYPY_INSTALL_PATH=$SRC/pypy-install
mkdir -p $PYPY_INSTALL_PATH

cd $SRC/pypy/pypy/goal
CC=clang CFLAGS="" pypy ../../rpython/bin/rpython --opt=2 --shared

cd $SRC/pypy
mkdir -p /tmp/pypy-pkg
CC=clang CFLAGS="" pypy pypy/tool/release/package.py \
    --archive-name=pypy-built \
    --targetdir=/tmp/pypy-pkg
tar xf /tmp/pypy-pkg/pypy-built.tar.bz2 -C $PYPY_INSTALL_PATH --strip-components=1
ln -sf libpypy3.11-c.so $PYPY_INSTALL_PATH/bin/libpypy3-c.so

PYPY=$PYPY_INSTALL_PATH/bin/pypy3

cd $SRC/pypy-fuzz
while read -r name; do
    CC=clang CFLAGS="" $PYPY build_cffi_fuzz.py "$name"
    $CC $FUZZ_CFLAGS fuzzer_stub.c ./_pypy_fuzz_${name}.so \
        -L$PYPY_INSTALL_PATH/bin -lpypy3-c \
        -Wl,-rpath,'$ORIGIN' \
        $LIB_FUZZING_ENGINE -rdynamic -ldl -o fuzzer-${name}

    cp fuzzer-${name} _pypy_fuzz_${name}.so fuzz_${name}.py $OUT/
    cp $PYPY_INSTALL_PATH/bin/libpypy3.11-c.so $OUT/libpypy3-c.so
    if [ -d "corp-${name}" ]; then
        zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-${name}/*
    fi
    if [ -f "fuzzer-${name}.dict" ]; then
        cp "fuzzer-${name}.dict" "$OUT/"
    fi
done < fuzz_targets.txt

cp -R $PYPY_INSTALL_PATH $OUT/
