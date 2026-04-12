#!/bin/bash -eu

export ASAN_OPTIONS="detect_leaks=0"
CFLAGS=${CFLAGS//"-pthread"/}

export PYPY_INSTALL_PATH=$SRC/pypy-install
mkdir -p $PYPY_INSTALL_PATH

cd $SRC/pypy

python3 rpython/bin/rpython --opt=2 --shared \
    pypy/goal/targetpypystandalone.py

# Install
PYPY_EXE=$(ls pypy/goal/pypy3*-c | head -1)
PYPY_LIB=$(ls pypy/goal/libpypy3*-c.so | head -1)
mkdir -p $PYPY_INSTALL_PATH/{bin,lib}
cp "$PYPY_EXE" $PYPY_INSTALL_PATH/bin/pypy3
cp "$PYPY_LIB" $PYPY_INSTALL_PATH/lib/
ln -sf "$(basename "$PYPY_LIB")" $PYPY_INSTALL_PATH/lib/libpypy3-c.so
cp -r lib-python/3 $PYPY_INSTALL_PATH/lib-python/3
cp -r lib_pypy $PYPY_INSTALL_PATH/lib_pypy
cp -r include $PYPY_INSTALL_PATH/include

PYPY=$PYPY_INSTALL_PATH/bin/pypy3
cd $SRC/pypy-fuzz

while read -r name; do
    $PYPY build_cffi_fuzz.py "$name"
    $CC $CFLAGS fuzzer_stub.c -L. -l_pypy_fuzz_${name} \
        $LIB_FUZZING_ENGINE -rdynamic -ldl -o fuzzer-${name}

    cp fuzzer-${name} _pypy_fuzz_${name}.so fuzz_${name}.py $OUT/
    if [ -d "corp-${name}" ]; then
        zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-${name}/*
    fi
    if [ -f "fuzzer-${name}.dict" ]; then
        cp "fuzzer-${name}.dict" "$OUT/"
    fi
done < fuzz_targets.txt

cp -R $PYPY_INSTALL_PATH $OUT/
